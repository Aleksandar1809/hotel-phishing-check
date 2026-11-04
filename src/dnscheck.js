/*
 * Domain Email Check - DNS reader and scoring.
 * Works in Node (for tests) and in the browser (inlined into docs/domain.html by build.js).
 * The only network access is lookupAll(), which sends DNS names to public DNS-over-HTTPS resolvers.
 * Parsing and scoring are pure functions so they can be tested with recorded answers.
 */
(function (root, factory) {
  var api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.DomainCheck = api;
})(this, function () {
  'use strict';

  // Public DNS-over-HTTPS JSON endpoints, tried in this order.
  var RESOLVERS = [
    { name: 'Cloudflare', url: 'https://cloudflare-dns.com/dns-query' },
    { name: 'Google', url: 'https://dns.google/resolve' }
  ];

  // Only these DKIM selectors are tried. A domain can use any other name.
  var COMMON_SELECTORS = ['selector1', 'selector2', 'google', 'k1', 'default'];

  var TYPE_NUM = { MX: 15, TXT: 16 };

  var VERDICTS = {
    strong: { en: 'Strong protection against spoofing', de: 'Starker Schutz gegen gefälschte Absender' },
    partial: { en: 'Partial protection against spoofing', de: 'Teilweiser Schutz gegen gefälschte Absender' },
    weak: { en: 'Weak protection against spoofing', de: 'Schwacher Schutz gegen gefälschte Absender' }
  };

  // ---------------------------------------------------------------------------
  // Input

  // Accepts "example.com", "https://www.example.com/x", "name@example.com". Returns null if invalid.
  function normalizeDomain(input) {
    var s = String(input || '').trim().toLowerCase();
    s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/^[^@\/]*@/, '');
    s = s.split(/[\/?#:\s]/)[0].replace(/\.+$/, '');
    if (s.length > 253 || !/^[a-z0-9.-]+$/.test(s) || s.indexOf('.') < 0) return null;
    if (/^\d+(\.\d+){3}$/.test(s)) return null; // IP address, not a domain
    var labels = s.split('.');
    for (var i = 0; i < labels.length; i++) {
      if (!labels[i] || labels[i].length > 63 || /^-|-$/.test(labels[i])) return null;
    }
    if (/^\d+$/.test(labels[labels.length - 1])) return null;
    return s;
  }

  // The DNS questions for one domain.
  function buildQueries(domain) {
    var q = [
      { key: 'mx', name: domain, type: 'MX' },
      { key: 'spf', name: domain, type: 'TXT' },
      { key: 'dmarc', name: '_dmarc.' + domain, type: 'TXT' }
    ];
    COMMON_SELECTORS.forEach(function (sel) {
      q.push({ key: 'dkim:' + sel, name: sel + '._domainkey.' + domain, type: 'TXT' });
    });
    return q;
  }

  // ---------------------------------------------------------------------------
  // Parsing DoH JSON answers

  // TXT data comes as "\"part1\" \"part2\"" (Cloudflare) or unquoted (Google).
  function txtData(data) {
    var s = String(data || '').trim();
    if (s.charAt(0) !== '"') return s;
    var out = '', re = /"((?:[^"\\]|\\.)*)"/g, m;
    while ((m = re.exec(s))) out += m[1].replace(/\\(.)/g, '$1');
    return out;
  }

  // Returns { status: 'ok' | 'nxdomain' | 'error', records: [...] }.
  function parseAnswer(json, type) {
    if (!json || typeof json.Status !== 'number') return { status: 'error', records: [] };
    if (json.Status === 3) return { status: 'nxdomain', records: [] };
    if (json.Status !== 0) return { status: 'error', records: [] };
    var records = (json.Answer || []).filter(function (a) { return a.type === TYPE_NUM[type]; }).map(function (a) {
      if (type === 'TXT') return txtData(a.data);
      var m = /^\s*(\d+)\s+(\S+)\s*$/.exec(String(a.data || ''));
      return m ? { pref: Number(m[1]), host: m[2].replace(/\.$/, '').toLowerCase() || '.' } : null;
    }).filter(function (r) { return r !== null; });
    return { status: 'ok', records: records };
  }

  function parseMx(answer) {
    var hosts = (answer.records || []).slice().sort(function (a, b) { return a.pref - b.pref; });
    var nullMx = hosts.length === 1 && hosts[0].host === '.';
    return { status: answer.status, hosts: nullMx ? [] : hosts, nullMx: nullMx };
  }

  // SPF: exactly one TXT record starting with v=spf1.
  function parseSpf(answer) {
    var recs = (answer.records || []).filter(function (r) { return /^v=spf1(\s|$)/i.test(r); });
    var res = { status: answer.status, count: recs.length, record: recs[0] || null, all: null, redirect: null, lookups: 0 };
    if (!recs.length) return res;
    recs[0].split(/\s+/).slice(1).forEach(function (term) {
      var m = /^([+?~-]?)all$/i.exec(term);
      if (m) { res.all = (m[1] || '+') + 'all'; return; }
      if (/^redirect=/i.test(term)) { res.redirect = term.slice(9); res.lookups++; return; }
      if (/^[+?~-]?(include|a|mx|ptr|exists)([:\/]|$)/i.test(term)) res.lookups++;
    });
    return res;
  }

  function tags(record) {
    var out = {};
    String(record).split(';').forEach(function (part) {
      var i = part.indexOf('=');
      if (i > 0) out[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).trim();
    });
    return out;
  }

  // DMARC: exactly one TXT record at _dmarc starting with v=DMARC1.
  function parseDmarc(answer) {
    var recs = (answer.records || []).filter(function (r) { return /^v\s*=\s*DMARC1\s*(;|$)/i.test(r); });
    var res = { status: answer.status, count: recs.length, record: recs[0] || null, policy: null, sp: null, pct: 100, rua: null };
    if (recs.length !== 1) return res;
    var t = tags(recs[0]);
    var p = String(t.p || '').toLowerCase();
    res.policy = /^(none|quarantine|reject)$/.test(p) ? p : 'invalid';
    if (t.sp) res.sp = String(t.sp).toLowerCase();
    if (t.pct != null && /^\d+$/.test(t.pct)) res.pct = Math.min(100, Number(t.pct));
    if (t.rua) res.rua = t.rua;
    return res;
  }

  // DKIM: a TXT record with a p= key. An empty p= means the key was revoked.
  function parseDkim(answers) {
    var found = [], revoked = [], errors = 0;
    COMMON_SELECTORS.forEach(function (sel) {
      var a = answers['dkim:' + sel] || { status: 'error', records: [] };
      if (a.status === 'error') errors++;
      (a.records || []).forEach(function (r) {
        if (!/(^|;)\s*p\s*=/i.test(r) && !/^v=DKIM1/i.test(r)) return;
        var key = tags(r).p;
        if (key) { if (found.indexOf(sel) < 0) found.push(sel); }
        else if (revoked.indexOf(sel) < 0) revoked.push(sel);
      });
    });
    return { found: found, revoked: revoked, errors: errors };
  }

  // ---------------------------------------------------------------------------
  // Messages

  var MSG = {
    'mx-ok': { en: 'MX: mail for this domain is received by {a}.', de: 'MX: E-Mails an diese Domain empfängt {a}.' },
    'mx-none': { en: 'MX: no mail server is listed, so this domain probably does not receive email (it can still be faked as a sender).', de: 'MX: Kein Mailserver eingetragen – die Domain empfängt wahrscheinlich keine E-Mails (als Absender kann sie trotzdem gefälscht werden).' },
    'mx-null': { en: 'MX: the domain says on purpose that it does not receive email (“null MX”).', de: 'MX: Die Domain erklärt ausdrücklich, dass sie keine E-Mails empfängt („Null-MX“).' },
    'spf-strict': { en: 'SPF: one record lists the allowed sending servers and ends with “-all”, so other servers are rejected.', de: 'SPF: Ein Eintrag nennt die erlaubten Versandserver und endet mit „-all“ – andere Server werden abgelehnt.' },
    'spf-soft': { en: 'SPF: one record lists the allowed sending servers and ends with “~all” (other servers are marked as suspicious, not rejected). Fine when DMARC is enforced.', de: 'SPF: Ein Eintrag nennt die erlaubten Versandserver und endet mit „~all“ (andere Server werden nur als verdächtig markiert). In Ordnung, wenn DMARC durchgesetzt wird.' },
    'spf-neutral': { en: 'SPF: the record ends with “?all” or has no “all” rule, so it says nothing about other servers.', de: 'SPF: Der Eintrag endet mit „?all“ oder hat keine „all“-Regel – über andere Server sagt er nichts aus.' },
    'spf-redirect': { en: 'SPF: the record hands over to the SPF record of {a}.', de: 'SPF: Der Eintrag verweist auf den SPF-Eintrag von {a}.' },
    'spf-pass-all': { en: 'SPF: the record ends with “+all”, which allows every server in the world to send as this domain.', de: 'SPF: Der Eintrag endet mit „+all“ – damit darf jeder Server der Welt im Namen dieser Domain senden.' },
    'spf-missing': { en: 'SPF: no SPF record, so receivers cannot tell which servers may send mail for this domain.', de: 'SPF: Kein SPF-Eintrag – Empfänger können nicht prüfen, welche Server für diese Domain senden dürfen.' },
    'spf-multiple': { en: 'SPF: there are {a} SPF records; that is invalid and receivers treat it as an error.', de: 'SPF: Es gibt {a} SPF-Einträge – das ist ungültig und wird von Empfängern als Fehler gewertet.' },
    'spf-lookups': { en: 'SPF: the record needs about {a} DNS lookups; more than 10 makes SPF fail.', de: 'SPF: Der Eintrag braucht etwa {a} DNS-Abfragen; mehr als 10 lassen SPF scheitern.' },
    'dmarc-reject': { en: 'DMARC: policy “reject” — receivers are told to refuse mail that fakes this domain.', de: 'DMARC: Richtlinie „reject“ – Empfänger sollen E-Mails ablehnen, die diese Domain fälschen.' },
    'dmarc-quarantine': { en: 'DMARC: policy “quarantine” — mail that fakes this domain should go to spam.', de: 'DMARC: Richtlinie „quarantine“ – E-Mails, die diese Domain fälschen, sollen im Spam landen.' },
    'dmarc-pct': { en: 'DMARC: the policy applies to only {a}% of failing mail; the rest is delivered normally.', de: 'DMARC: Die Richtlinie gilt nur für {a} % der fehlschlagenden E-Mails; der Rest wird normal zugestellt.' },
    'dmarc-none': { en: 'DMARC: policy “none” (monitoring only) — anyone can send mail that looks like it comes from this domain, and it is still delivered.', de: 'DMARC: Richtlinie „none“ (nur Beobachtung) – jeder kann E-Mails senden, die scheinbar von dieser Domain kommen, und sie werden trotzdem zugestellt.' },
    'dmarc-missing': { en: 'DMARC: no DMARC record — anyone can send mail that looks like it comes from this domain, and receivers get no instruction to block it.', de: 'DMARC: Kein DMARC-Eintrag – jeder kann E-Mails senden, die scheinbar von dieser Domain kommen, und Empfänger erhalten keine Anweisung, sie zu blockieren.' },
    'dmarc-invalid': { en: 'DMARC: the record is invalid (several records or no valid “p=” policy), so receivers ignore it.', de: 'DMARC: Der Eintrag ist ungültig (mehrere Einträge oder keine gültige „p=“-Richtlinie) und wird ignoriert.' },
    'dmarc-sp-none': { en: 'DMARC: subdomains have “sp=none”, so fake mail from invented subdomains (like billing.{a}) is not blocked.', de: 'DMARC: Subdomains haben „sp=none“ – gefälschte E-Mails von erfundenen Subdomains (z. B. billing.{a}) werden nicht blockiert.' },
    'dmarc-no-rua': { en: 'DMARC: no report address (rua), so the owner does not see who sends mail in its name.', de: 'DMARC: Keine Berichtsadresse (rua) – der Inhaber sieht nicht, wer in seinem Namen E-Mails sendet.' },
    'dkim-found': { en: 'DKIM: a signing key was found at a common selector ({a}).', de: 'DKIM: Ein Signaturschlüssel wurde bei einem üblichen Selektor gefunden ({a}).' },
    'dkim-not-found': { en: 'DKIM: not found at common selectors (may still exist under another name).', de: 'DKIM: Bei üblichen Selektoren nicht gefunden (kann unter einem anderen Namen trotzdem existieren).' },
    'dkim-revoked': { en: 'DKIM: the key at {a} is empty (revoked).', de: 'DKIM: Der Schlüssel bei {a} ist leer (widerrufen).' },
    'lookup-error': { en: 'Some DNS answers could not be read ({a}); the result may be incomplete.', de: 'Einige DNS-Antworten konnten nicht gelesen werden ({a}); das Ergebnis ist eventuell unvollständig.' }
  };

  var STEPS = {
    'dmarc-add': { en: 'Publish a DMARC record: start with p=none and a report address (rua), then move to p=quarantine and p=reject.', de: 'DMARC-Eintrag veröffentlichen: mit p=none und Berichtsadresse (rua) beginnen, dann zu p=quarantine und p=reject wechseln.' },
    'dmarc-enforce': { en: 'Read the DMARC reports, make sure every real sender passes, then change p=none to p=quarantine and later p=reject.', de: 'DMARC-Berichte auswerten, alle echten Absender korrekt einrichten, dann p=none auf p=quarantine und später p=reject ändern.' },
    'dmarc-fix': { en: 'Replace the DMARC records with one valid record, for example “v=DMARC1; p=quarantine; rua=mailto:…”.', de: 'Die DMARC-Einträge durch einen gültigen Eintrag ersetzen, z. B. „v=DMARC1; p=quarantine; rua=mailto:…“.' },
    'dmarc-pct': { en: 'Raise the DMARC pct value to 100 (or remove it).', de: 'Den DMARC-pct-Wert auf 100 erhöhen (oder entfernen).' },
    'dmarc-sp': { en: 'Set sp=quarantine or sp=reject (or remove sp) so subdomains are protected too.', de: 'sp=quarantine oder sp=reject setzen (oder sp entfernen), damit auch Subdomains geschützt sind.' },
    'dmarc-rua': { en: 'Add a rua report address to the DMARC record to see who sends mail in your name.', de: 'Eine rua-Berichtsadresse zum DMARC-Eintrag hinzufügen, um zu sehen, wer in Ihrem Namen sendet.' },
    'spf-add': { en: 'Publish one SPF record that lists every service that sends mail for you and ends with -all or ~all.', de: 'Einen SPF-Eintrag veröffentlichen, der alle Dienste nennt, die für Sie senden, und mit -all oder ~all endet.' },
    'spf-merge': { en: 'Merge the SPF records into one.', de: 'Die SPF-Einträge zu einem zusammenführen.' },
    'spf-tighten': { en: 'End the SPF record with -all or ~all instead of +all, ?all or nothing.', de: 'Den SPF-Eintrag mit -all oder ~all statt +all, ?all oder ohne Regel beenden.' },
    'spf-lookups': { en: 'Reduce the SPF includes to 10 DNS lookups or fewer.', de: 'Die SPF-Includes auf höchstens 10 DNS-Abfragen reduzieren.' },
    'parked': { en: 'If this domain never sends email, publish “v=spf1 -all” and “v=DMARC1; p=reject”.', de: 'Wenn diese Domain nie E-Mails sendet: „v=spf1 -all“ und „v=DMARC1; p=reject“ veröffentlichen.' },
    'dkim-check': { en: 'Ask your email provider to confirm DKIM signing is switched on (the selector may have a different name).', de: 'Beim E-Mail-Anbieter nachfragen, ob DKIM-Signierung aktiv ist (der Selektor kann anders heißen).' },
    'verify': { en: 'Have your IT or email provider confirm these results; this check only reads public DNS.', de: 'Die Ergebnisse von IT oder E-Mail-Anbieter bestätigen lassen; diese Prüfung liest nur öffentliches DNS.' }
  };

  function msg(id, level, a) {
    var m = MSG[id];
    function f(s) { return s.replace(/\{a\}/g, a == null ? '' : String(a)); }
    return { id: id, level: level, text: { en: f(m.en), de: f(m.de) } };
  }

  // ---------------------------------------------------------------------------
  // Scoring

  /*
   * evaluate(domain, answers) -> { domain, verdict, verdictText, reasons, findings, nextSteps, records }
   *   answers: { mx, spf, dmarc, 'dkim:<selector>' } each { status, records } from parseAnswer().
   * Verdict rules (documented in README):
   *   Strong:  DMARC p=reject or p=quarantine at pct=100, and one valid SPF record ending in -all or ~all
   *            (or a redirect), and no +all.
   *   Weak:    no DMARC, an invalid DMARC record, or p=none — the domain's name can be faked.
   *   Partial: DMARC is enforced, but something weakens it (SPF missing/broken, pct below 100, sp=none).
   * DKIM is informational only: it can only be seen at selectors we guess.
   */
  function evaluate(domain, answers) {
    var get = function (k) { return answers[k] || { status: 'error', records: [] }; };
    var mx = parseMx(get('mx'));
    var spf = parseSpf(get('spf'));
    var dmarc = parseDmarc(get('dmarc'));
    var dkim = parseDkim(answers);
    var findings = [], steps = [], weakReasons = [], partialReasons = [], spfProblems = [];
    function add(f, reasonList) { findings.push(f); if (reasonList) reasonList.push(f); }

    var errors = ['mx', 'spf', 'dmarc'].filter(function (k) { return get(k).status === 'error'; });
    if (errors.length) findings.push(msg('lookup-error', 'warn', errors.map(function (k) { return k.toUpperCase(); }).join(', ')));

    // MX (information only)
    if (mx.nullMx) add(msg('mx-null', 'info'));
    else if (mx.hosts.length) add(msg('mx-ok', 'info', mx.hosts.slice(0, 3).map(function (h) { return h.host; }).join(', ')));
    else if (mx.status !== 'error') add(msg('mx-none', 'info'));

    // DMARC
    var enforced = false;
    if (dmarc.count === 0) {
      if (dmarc.status !== 'error') { add(msg('dmarc-missing', 'bad'), weakReasons); steps.push('dmarc-add'); }
    } else if (dmarc.count > 1 || dmarc.policy === 'invalid') {
      add(msg('dmarc-invalid', 'bad'), weakReasons); steps.push('dmarc-fix');
    } else if (dmarc.policy === 'none') {
      add(msg('dmarc-none', 'bad'), weakReasons); steps.push('dmarc-enforce');
    } else {
      enforced = true;
      add(msg('dmarc-' + dmarc.policy, 'good'));
      if (dmarc.pct < 100) { add(msg('dmarc-pct', 'warn', dmarc.pct), partialReasons); steps.push('dmarc-pct'); }
      if (dmarc.sp === 'none') { add(msg('dmarc-sp-none', 'warn', domain), partialReasons); steps.push('dmarc-sp'); }
    }
    if (dmarc.count === 1 && dmarc.policy !== 'invalid' && !dmarc.rua) { add(msg('dmarc-no-rua', 'info')); steps.push('dmarc-rua'); }

    // SPF
    var spfOk = false;
    if (spf.count === 0) {
      if (spf.status !== 'error') { add(msg('spf-missing', 'bad'), spfProblems); steps.push('spf-add'); }
    } else if (spf.count > 1) {
      add(msg('spf-multiple', 'bad', spf.count), spfProblems); steps.push('spf-merge');
    } else if (spf.all === '+all') {
      add(msg('spf-pass-all', 'bad'), spfProblems); steps.push('spf-tighten');
    } else if (spf.all === '-all') { spfOk = true; add(msg('spf-strict', 'good')); }
    else if (spf.all === '~all') { spfOk = true; add(msg('spf-soft', 'good')); }
    else if (spf.redirect && !spf.all) { spfOk = true; add(msg('spf-redirect', 'info', spf.redirect)); }
    else { add(msg('spf-neutral', 'warn'), spfProblems); steps.push('spf-tighten'); }
    if (spf.count === 1 && spf.lookups > 10) { add(msg('spf-lookups', 'warn', spf.lookups), spfProblems); steps.push('spf-lookups'); }

    // DKIM (information only)
    if (dkim.found.length) add(msg('dkim-found', 'good', dkim.found.join(', ')));
    else { add(msg('dkim-not-found', 'info')); steps.push('dkim-check'); }
    if (dkim.revoked.length) add(msg('dkim-revoked', 'info', dkim.revoked.join(', ')));

    if ((mx.nullMx || (!mx.hosts.length && mx.status === 'ok')) && !(enforced && dmarc.policy === 'reject' && spf.all === '-all')) steps.push('parked');
    steps.push('verify');

    var verdict = !enforced ? 'weak' : (partialReasons.length || spfProblems.length || !spfOk) ? 'partial' : 'strong';
    var reasons = verdict === 'weak' ? weakReasons.concat(spfProblems) : verdict === 'partial' ? partialReasons.concat(spfProblems)
      : findings.filter(function (f) { return f.level === 'good'; });
    if (!reasons.length) reasons = findings.filter(function (f) { return f.id === 'lookup-error'; });

    return {
      domain: domain,
      verdict: verdict,
      verdictText: VERDICTS[verdict],
      reasons: reasons,
      findings: findings,
      nextSteps: steps.filter(function (s, i) { return steps.indexOf(s) === i; }).map(function (s) { return { id: s, text: STEPS[s] }; }),
      records: { mx: mx, spf: spf, dmarc: dmarc, dkim: dkim }
    };
  }

  // ---------------------------------------------------------------------------
  // Network (browser): only DNS names go to the resolvers. fetchImpl is injectable for tests.

  function queryOne(q, fetchImpl) {
    var i = 0;
    function attempt() {
      if (i >= RESOLVERS.length) return Promise.resolve({ status: 'error', records: [], resolver: null });
      var r = RESOLVERS[i++];
      var url = r.url + '?name=' + encodeURIComponent(q.name) + '&type=' + q.type;
      return fetchImpl(url, {
        headers: { accept: 'application/dns-json' },
        credentials: 'omit', referrerPolicy: 'no-referrer', cache: 'no-store'
      }).then(function (res) {
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return res.json();
      }).then(function (json) {
        var parsed = parseAnswer(json, q.type);
        if (parsed.status === 'error') throw new Error('bad answer');
        parsed.resolver = r.name;
        return parsed;
      }).catch(attempt);
    }
    return attempt();
  }

  function lookupAll(domain, fetchImpl) {
    var f = fetchImpl || (typeof fetch === 'function' ? fetch.bind(null) : null);
    if (!f) return Promise.reject(new Error('fetch is not available'));
    var queries = buildQueries(domain);
    return Promise.all(queries.map(function (q) { return queryOne(q, f); })).then(function (list) {
      var answers = {};
      queries.forEach(function (q, idx) { answers[q.key] = list[idx]; });
      return answers;
    });
  }

  function check(input, fetchImpl) {
    var domain = normalizeDomain(input);
    if (!domain) return Promise.reject(new Error('invalid-domain'));
    return lookupAll(domain, fetchImpl).then(function (answers) {
      var all = ['mx', 'spf', 'dmarc'].map(function (k) { return answers[k].status; });
      if (all.every(function (s) { return s === 'error'; })) throw new Error('network');
      if (answers.mx.status === 'nxdomain' && answers.spf.status === 'nxdomain') throw new Error('nxdomain');
      return evaluate(domain, answers);
    });
  }

  return {
    RESOLVERS: RESOLVERS,
    COMMON_SELECTORS: COMMON_SELECTORS,
    VERDICTS: VERDICTS,
    normalizeDomain: normalizeDomain,
    buildQueries: buildQueries,
    parseAnswer: parseAnswer,
    evaluate: evaluate,
    lookupAll: lookupAll,
    check: check,
    _: { txtData: txtData, parseMx: parseMx, parseSpf: parseSpf, parseDmarc: parseDmarc, parseDkim: parseDkim }
  };
});
