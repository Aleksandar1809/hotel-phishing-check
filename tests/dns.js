#!/usr/bin/env node
// Domain Email Check tests: parsing and scoring with recorded DoH answers. No live network.
// Usage: node tests/dns.js [-v]
'use strict';
var fs = require('fs');
var path = require('path');
var DC = require('../src/dnscheck.js');

var verbose = process.argv.indexOf('-v') >= 0;
var dir = path.join(__dirname, 'dns');
var passed = 0, failed = 0;
var pending = [];

function check(name, problems, extra) {
  if (problems.length) { failed++; console.log('FAIL ' + name + '\n  - ' + problems.join('\n  - ')); }
  else { passed++; if (verbose) console.log('ok   ' + name + (extra ? '  ' + extra : '')); }
}
function eq(name, actual, want) {
  check(name, JSON.stringify(actual) === JSON.stringify(want) ? [] : ['got ' + JSON.stringify(actual) + ', expected ' + JSON.stringify(want)]);
}

// A fake fetch that answers from a recorded fixture. Any URL outside the two resolvers fails the test.
function fakeFetch(answers, opts) {
  opts = opts || {};
  var calls = [];
  var f = function (url, init) {
    calls.push(url);
    var m = /^https:\/\/(cloudflare-dns\.com\/dns-query|dns\.google\/resolve)\?name=([^&]+)&type=(\w+)$/.exec(url);
    if (!m) return Promise.reject(new Error('unexpected URL ' + url));
    if (!init || init.credentials !== 'omit') return Promise.reject(new Error('credentials must be omitted'));
    if (opts.failCloudflare && m[1].indexOf('cloudflare') === 0) return Promise.reject(new Error('offline'));
    if (opts.failAll) return Promise.resolve({ ok: false, status: 503, json: function () { return Promise.resolve({}); } });
    var key = decodeURIComponent(m[2]) + '|' + m[3];
    var body = answers[key] || { Status: 3 };
    return Promise.resolve({ ok: true, status: 200, json: function () { return Promise.resolve(body); } });
  };
  f.calls = calls;
  return f;
}

function ids(list) { return list.map(function (x) { return x.id; }); }

// Fixture tests: the whole path check() -> lookupAll() -> parse -> evaluate.
fs.readdirSync(dir).filter(function (f) { return /\.json$/.test(f); }).sort().forEach(function (file) {
  var fx = JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8'));
  pending.push(DC.check(fx.domain, fakeFetch(fx.answers)).then(function (res) {
    var p = [], e = fx.expect;
    var f = ids(res.findings), r = ids(res.reasons), s = ids(res.nextSteps);
    if (res.verdict !== e.verdict) p.push('verdict ' + res.verdict + ', expected ' + e.verdict);
    (e.findings || []).forEach(function (id) { if (f.indexOf(id) < 0) p.push('missing finding ' + id); });
    (e.absent || []).forEach(function (id) { if (f.indexOf(id) >= 0) p.push('unexpected finding ' + id); });
    (e.reasons || []).forEach(function (id) { if (r.indexOf(id) < 0) p.push('missing reason ' + id); });
    (e.steps || []).forEach(function (id) { if (s.indexOf(id) < 0) p.push('missing step ' + id); });
    if (!res.reasons.length) p.push('no reasons given');
    res.findings.concat(res.nextSteps).forEach(function (x) {
      if (!x.text.en || !x.text.de || /\{a\}/.test(x.text.en + x.text.de)) p.push('bad text for ' + x.id);
    });
    if (p.length && verbose) p.push('findings: ' + f.join(', '));
    check(file, p, res.verdict + ' [' + r.join(', ') + ']');
  }, function (err) { check(file, ['threw ' + err.message]); }));
});

// Resolver fallback: Cloudflare down, Google answers.
(function () {
  var fx = JSON.parse(fs.readFileSync(path.join(dir, 'strong.json'), 'utf8'));
  var ff = fakeFetch(fx.answers, { failCloudflare: true });
  pending.push(DC.lookupAll(fx.domain, ff).then(function (a) {
    var used = Object.keys(a).map(function (k) { return a[k].resolver; });
    check('fallback to Google', used.every(function (x) { return x === 'Google'; }) ? [] : ['resolvers used: ' + used.join(',')]);
    // Only DNS names of the checked domain are ever sent.
    var bad = ff.calls.filter(function (u) { return !/name=([a-z0-9]+\._domainkey\.|_dmarc\.)?strong-hotel\.test&/.test(u); });
    check('only the domain name is sent', bad.length ? ['unexpected: ' + bad[0]] : []);
  }));
})();

pending.push(DC.check('example.com', fakeFetch({}, { failAll: true })).then(
  function () { check('network failure is reported', ['did not throw']); },
  function (err) { eq('network failure is reported', err.message, 'network'); }));
pending.push(DC.check('does-not-exist.test', fakeFetch({})).then(
  function () { check('nxdomain is reported', ['did not throw']); },
  function (err) { eq('nxdomain is reported', err.message, 'nxdomain'); }));
pending.push(DC.check('not a domain', fakeFetch({})).then(
  function () { check('invalid input rejected', ['did not throw']); },
  function (err) { eq('invalid input rejected', err.message, 'invalid-domain'); }));

// Unit checks
var _ = DC._;
eq('normalize url', DC.normalizeDomain('https://www.Example.com/path?x=1'), 'www.example.com');
eq('normalize email', DC.normalizeDomain('reception@grandpalm.test'), 'grandpalm.test');
eq('normalize trailing dot', DC.normalizeDomain('example.com.'), 'example.com');
eq('reject ip', DC.normalizeDomain('192.0.2.1'), null);
eq('reject no dot', DC.normalizeDomain('localhost'), null);
eq('reject bad label', DC.normalizeDomain('-bad.example.com'), null);
eq('queries', DC.buildQueries('example.com').map(function (q) { return q.name + '/' + q.type; }).slice(0, 4),
  ['example.com/MX', 'example.com/TXT', '_dmarc.example.com/TXT', 'selector1._domainkey.example.com/TXT']);
eq('selectors', DC.COMMON_SELECTORS, ['selector1', 'selector2', 'google', 'k1', 'default']);
eq('txt split strings', _.txtData('"v=spf1 include:a.example.com " "-all"'), 'v=spf1 include:a.example.com -all');
eq('txt escaped quote', _.txtData('"a\\"b"'), 'a"b');
eq('txt unquoted', _.txtData('v=spf1 -all'), 'v=spf1 -all');
eq('answer servfail', DC.parseAnswer({ Status: 2 }, 'TXT').status, 'error');
eq('answer ignores cname', DC.parseAnswer({ Status: 0, Answer: [{ type: 5, data: 'x.example.com.' }, { type: 16, data: '"v=DMARC1; p=none"' }] }, 'TXT').records, ['v=DMARC1; p=none']);
eq('mx sorted', _.parseMx(DC.parseAnswer({ Status: 0, Answer: [{ type: 15, data: '20 b.example.com.' }, { type: 15, data: '10 a.example.com.' }] }, 'MX')).hosts.map(function (h) { return h.host; }), ['a.example.com', 'b.example.com']);
eq('spf all qualifier', _.parseSpf({ status: 'ok', records: ['v=spf1 ip4:192.0.2.0/24 ?all'] }).all, '?all');
eq('spf bare all is +all', _.parseSpf({ status: 'ok', records: ['v=spf1 all'] }).all, '+all');
eq('spf lookups', _.parseSpf({ status: 'ok', records: ['v=spf1 a mx include:x.example.com ip4:192.0.2.1 exists:%{i}.example.com -all'] }).lookups, 4);
eq('spf ignores other txt', _.parseSpf({ status: 'ok', records: ['v=spf10 nope', 'hello'] }).count, 0);
eq('dmarc tags', (function () { var d = _.parseDmarc({ status: 'ok', records: ['v=DMARC1; p=Reject; sp=none; pct=50; rua=mailto:a@example.com'] }); return [d.policy, d.sp, d.pct, d.rua]; })(), ['reject', 'none', 50, 'mailto:a@example.com']);
eq('dmarc bad policy', _.parseDmarc({ status: 'ok', records: ['v=DMARC1; p=block'] }).policy, 'invalid');
eq('never says safe', Object.keys(DC.VERDICTS).every(function (k) { return !/\bsafe\b|sicher\b/i.test(DC.VERDICTS[k].en + DC.VERDICTS[k].de); }), true);

Promise.all(pending).then(function () {
  var total = passed + failed;
  console.log('\n' + passed + '/' + total + ' passed (' + Math.round(100 * passed / total) + '%)');
  process.exit(failed ? 1 : 0);
});
