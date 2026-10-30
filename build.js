#!/usr/bin/env node
// Builds docs/index.html: inlines src/analyzer.js and one synthetic example email into src/ui.html.
'use strict';
var fs = require('fs');
var path = require('path');

var root = __dirname;
var ui = fs.readFileSync(path.join(root, 'src', 'ui.html'), 'utf8');
var analyzer = fs.readFileSync(path.join(root, 'src', 'analyzer.js'), 'utf8');
var example = fs.readFileSync(path.join(root, 'tests', 'emails', 'p01-booking-payment.eml'), 'utf8');

// Inline code must not close the script tag or open an HTML comment.
if (/<\/script|<!--/i.test(analyzer)) throw new Error('analyzer.js contains </script or <!-- and cannot be inlined');
var exampleJs = 'var EXAMPLE_EMAIL = ' + JSON.stringify(example).replace(/</g, '\\u003c') + ';';

['/*__ANALYZER__*/', '/*__EXAMPLE__*/'].forEach(function (mark) {
  if (ui.split(mark).length !== 2) throw new Error('placeholder ' + mark + ' must appear exactly once in src/ui.html');
});
var out = ui.replace('/*__ANALYZER__*/', function () { return analyzer; })
  .replace('/*__EXAMPLE__*/', function () { return exampleJs; });

// The page must stay self-contained: no external scripts, styles, fonts or images.
var css = (/<style>([\s\S]*?)<\/style>/.exec(out) || ['', ''])[1];
var external = /<(script|link|img|iframe)\b[^>]*\b(src|href)\s*=\s*["']?(https?:)?\/\//i.exec(out) || /url\(|@import/i.exec(css);
if (external) throw new Error('external resource found: ' + external[0]);

fs.mkdirSync(path.join(root, 'docs'), { recursive: true });
fs.writeFileSync(path.join(root, 'docs', 'index.html'), out);
console.log('docs/index.html written (' + Math.round(out.length / 1024) + ' KB)');
