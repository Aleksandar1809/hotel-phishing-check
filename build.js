#!/usr/bin/env node
// Builds two self-contained pages:
//   docs/index.html  = src/ui.html     + src/analyzer.js  + synthetic example emails
//   docs/domain.html = src/domain.html + src/dnscheck.js
'use strict';
var fs = require('fs');
var path = require('path');

var root = __dirname;
function read(rel) { return fs.readFileSync(path.join(root, rel), 'utf8'); }
function jsString(value) { return JSON.stringify(value).replace(/</g, '\\u003c'); }

// Inline code must not close the script tag or open an HTML comment.
function safeScript(name, code) {
  if (/<\/script|<!--/i.test(code)) throw new Error(name + ' contains </script or <!-- and cannot be inlined');
  return code;
}

function fill(name, html, parts) {
  Object.keys(parts).forEach(function (mark) {
    if (html.split(mark).length !== 2) throw new Error('placeholder ' + mark + ' must appear exactly once in ' + name);
    html = html.replace(mark, function () { return parts[mark]; });
  });
  return html;
}

// External resources are never allowed. The only network target allowed anywhere is the
// DNS-over-HTTPS resolvers on the domain page, and only through connect-src / fetch.
function checkSelfContained(name, out, allowedConnect) {
  var css = (/<style>([\s\S]*?)<\/style>/.exec(out) || ['', ''])[1];
  var external = /<(script|link|img|iframe)\b[^>]*\b(src|href)\s*=\s*["']?(https?:)?\/\//i.exec(out) || /url\(|@import/i.exec(css);
  if (external) throw new Error(name + ': external resource found: ' + external[0]);
  var csp = (/http-equiv="Content-Security-Policy" content="([^"]*)"/.exec(out) || [])[1];
  if (!csp || !/default-src 'none'/.test(csp)) throw new Error(name + ': strict Content-Security-Policy missing');
  var connect = (/connect-src ([^;]*)/.exec(csp) || [null, ''])[1].trim().split(/\s+/).filter(Boolean);
  if (JSON.stringify(connect) !== JSON.stringify(allowedConnect)) throw new Error(name + ': unexpected connect-src ' + connect.join(' '));
}

function write(name, out, allowedConnect) {
  checkSelfContained(name, out, allowedConnect);
  fs.mkdirSync(path.join(root, 'docs'), { recursive: true });
  fs.writeFileSync(path.join(root, 'docs', name), out);
  console.log('docs/' + name + ' written (' + Math.round(out.length / 1024) + ' KB)');
}

// Phishing Check: example sets (all synthetic).
var examples = {
  ota: read('tests/emails/p01-booking-payment.eml'),
  m365: read('tests/emails/p09-m365-login.eml'),
  bank: read('tests/emails/p10-bank-change.eml')
};
write('index.html', fill('src/ui.html', read('src/ui.html'), {
  '/*__ANALYZER__*/': safeScript('analyzer.js', read('src/analyzer.js')),
  '/*__EXAMPLE__*/': 'var EXAMPLES = ' + jsString(examples) + ';'
}), []);

// Domain Email Check.
write('domain.html', fill('src/domain.html', read('src/domain.html'), {
  '/*__DNSCHECK__*/': safeScript('dnscheck.js', read('src/dnscheck.js'))
}), ['https://cloudflare-dns.com', 'https://dns.google']);
