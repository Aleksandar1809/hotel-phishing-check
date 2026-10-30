#!/usr/bin/env node
// Runs the synthetic test emails and a few unit checks. Usage: node tests/run.js [-v]
'use strict';
var fs = require('fs');
var path = require('path');
var PC = require('../src/analyzer.js');

var verbose = process.argv.indexOf('-v') >= 0;
var expected = JSON.parse(fs.readFileSync(path.join(__dirname, 'expected.json'), 'utf8'));
var dir = path.join(__dirname, 'emails');
var passed = 0, failed = 0;

function check(name, problems, extra) {
  if (problems.length) {
    failed++;
    console.log('FAIL ' + name + '\n  - ' + problems.join('\n  - '));
  } else {
    passed++;
    if (verbose) console.log('ok   ' + name + (extra ? '  ' + extra : ''));
  }
}

// Email tests
var files = fs.readdirSync(dir).filter(function (f) { return /\.eml$/.test(f); }).sort();
files.forEach(function (file) {
  var exp = expected.emails[file];
  if (!exp) { check(file, ['no entry in expected.json']); return; }
  var raw = fs.readFileSync(path.join(dir, file), 'utf8');
  var res = PC.analyze(raw, '', expected.settings);
  var ids = res.signals.map(function (s) { return s.id; });
  var problems = [];
  if (res.verdict !== exp.verdict) problems.push('verdict ' + res.verdict + ' (score ' + res.score + '), expected ' + exp.verdict);
  exp.signals.forEach(function (id) { if (ids.indexOf(id) < 0) problems.push('missing signal ' + id); });
  (exp.absent || []).forEach(function (id) { if (ids.indexOf(id) >= 0) problems.push('unexpected signal ' + id); });
  if (exp.firstHop && !(res.info.firstHop && res.info.firstHop.ip === exp.firstHop)) {
    problems.push('first hop ' + JSON.stringify(res.info.firstHop) + ', expected ' + exp.firstHop);
  }
  res.signals.forEach(function (s) {
    if (!s.text.en || !s.text.de || /\{[ab]\}/.test(s.text.en + s.text.de)) problems.push('bad text for ' + s.key);
  });
  if (problems.length && verbose) problems.push('signals: ' + ids.join(', '));
  check(file, problems, res.verdict + ' ' + res.score + ' [' + ids.join(', ') + ']');
});

// Splitting headers and body into two boxes must give the same result as the full source.
(function () {
  var raw = fs.readFileSync(path.join(dir, 'p02-guest-complaint.eml'), 'utf8');
  var cut = raw.indexOf('\n\n');
  var a = PC.analyze(raw, '', expected.settings);
  var b = PC.analyze(raw.slice(0, cut), raw.slice(cut + 2), expected.settings);
  check('split headers/body', a.score === b.score && a.verdict === b.verdict ? [] : ['scores differ: ' + a.score + ' vs ' + b.score]);
})();

// Unit checks
var _ = PC._;
var settings = expected.settings;
function eq(name, actual, want) {
  check(name, JSON.stringify(actual) === JSON.stringify(want) ? [] : ['got ' + JSON.stringify(actual) + ', expected ' + JSON.stringify(want)]);
}
function kind(host) { var r = _.checkLookalike(host, settings); return r ? r.kind : null; }
function signalIds(headers, body) { return PC.analyze(headers, body || '', settings).signals.map(function (s) { return s.id; }); }

eq('registrable a.b.co.uk', _.registrableDomain('mail.hotel.co.uk'), 'hotel.co.uk');
eq('registrable sub.example.com', _.registrableDomain('a.b.example.com'), 'example.com');
eq('edit distance swap', _.editDistance('bokoing', 'booking'), 1);
eq('lookalike official', kind('mail.booking.com'), null);
eq('lookalike unrelated', kind('example.com'), null);
eq('lookalike own domain', kind('intranet.grandpalm.test'), null);
eq('lookalike 0/o', kind('b00king.test'), 'swap');
eq('lookalike rn/m', kind('grandpairn.test'), 'swap');
eq('lookalike 1/l', kind('a1rbnb.test'), 'swap');
eq('lookalike typo', kind('boking.test'), 'typo');
eq('lookalike tld', kind('booking.test'), 'tld');
eq('lookalike extra words', kind('booking-com-secure.test'), 'extra');
eq('lookalike subdomain words', kind('booking.reservation-help.test'), 'extra');
eq('lookalike own hotel typo', kind('grandpalrn-hotel.test') !== null, true);
eq('punycode domain', kind('xn--bking-gra.test'), 'punycode');
eq('encoded word', _.decodeWords('=?UTF-8?B?QsO8cm8=?= =?UTF-8?Q?_M=C3=BCnchen?='), 'Büro München');
eq('auth parse', (function () { var a = _.readAuth('Authentication-Results: mx.test; spf=pass; dkim=fail; dkim=pass; dmarc=fail (p=REJECT)'); return [a.spf, a.dkim, a.dmarc, a.policy]; })(), ['pass', 'pass', 'fail', 'reject']);
eq('received-spf fallback', _.readAuth('Received-SPF: softfail (test)').spf, 'softfail');

var authOk = 'Authentication-Results: mx.grandpalm.test; spf=pass; dkim=pass; dmarc=pass\nFrom: "Guest" <guest@example.com>\nSubject: Hello';
eq('shortener link', signalIds(authOk, 'See https://bit.ly/3xYzAb for photos').indexOf('link-shortener') >= 0, true);
eq('ip link', signalIds(authOk, 'Open http://198.51.100.7/login now').indexOf('link-ip') >= 0, true);
eq('text <url> mismatch', signalIds(authOk, 'secure.booking.com <https://evil-host.test/x>').indexOf('link-text-mismatch') >= 0, true);
eq('display-name address trick', signalIds('Authentication-Results: mx.test; spf=pass; dkim=pass; dmarc=pass\nFrom: "noreply@booking.com" <x@mailer.test>').indexOf('display-address') >= 0, true);
eq('german suspension', signalIds(authOk, 'Ihr Konto wird gesperrt, wenn Sie nicht reagieren.').indexOf('content-suspension') >= 0, true);
eq('german clickfix', signalIds(authOk, 'Drücken Sie Windows-Taste + R und dann Strg + V und Enter.').indexOf('content-clickfix') >= 0, true);
eq('complaint without link', signalIds(authOk, 'There was a guest complaint about noise.').indexOf('content-complaint-link'), -1);
eq('no headers', PC.analyze('', 'hello', settings).verdict, 'none');
eq('never says safe', Object.keys(PC.VERDICTS).every(function (k) { return !/\bsafe\b/i.test(PC.VERDICTS[k].en.replace('does not mean the email is safe', '')); }), true);

var total = passed + failed;
console.log('\n' + passed + '/' + total + ' passed (' + Math.round(100 * passed / total) + '%)');
process.exit(failed ? 1 : 0);
