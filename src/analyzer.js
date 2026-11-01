/*
 * Hotel Phishing Check - analyzer.
 * Works in Node (require('./analyzer.js')) and in the browser (window.PhishCheck).
 * Pure functions only: no network calls, no storage, no dependencies.
 */
(function (root, factory) {
  'use strict';
  var api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.PhishCheck = api;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ---------------------------------------------------------------------------
  // Editable lists
  // ---------------------------------------------------------------------------

  // Official brands. Edit this one array to add brands or domains.
  //   match:    finds the brand in a sender display name or subject
  //   domains:  the brand's real domains (compared at the registrable level)
  //   names:    domain labels compared for lookalikes (typos, swapped characters)
  //   contains: strings that are suspicious anywhere inside a non-official label
  // Sources (checked 2026-11-01):
  //  Airbnb: airbnb.com/help/article/971 (all listed senders are airbnb.com subdomains;
  //    third-party survey senders express.medallia.com and qemailserver.com are left out on purpose,
  //    because anyone can send from those shared platforms).
  //  Expedia: partner.expediagroup.com "preventing phishing attacks" (expediagroup.com,
  //    expediapartnercentral.com, mg.vrbo.com, mg.abritel.fr, mg.fewo-direkt.de).
  //  Agoda: partnerhub.agoda.com security article (agoda.com, agoda.net for partner documents).
  //  HRS: hrs.com imprint (hrs.de, hrs.com).
  var OFFICIAL_BRANDS = [
    { name: 'Booking.com', match: /booking\s?\.\s?com|\bbooking\s+(partner|extranet|support|security|admin)/i,
      domains: ['booking.com', 'bstatic.com'], names: ['booking', 'bookingcom'], contains: ['bookingcom'] },
    { name: 'Expedia', match: /\bexpedia\b/i,
      domains: ['expedia.com', 'expediagroup.com', 'expediapartnercentral.com', 'expedia.de', 'expedia.co.uk', 'expedia.ae', 'expedia.at', 'expedia.ch',
        'vrbo.com', 'abritel.fr', 'fewo-direkt.de'],
      names: ['expedia'], contains: ['expedia'] },
    { name: 'Airbnb', match: /\bairbnb\b/i,
      domains: ['airbnb.com', 'airbnb.de', 'airbnb.co.uk', 'airbnb.ae'], names: ['airbnb'], contains: ['airbnb'] },
    { name: 'Agoda', match: /\bagoda\b/i,
      domains: ['agoda.com', 'agoda.net'], names: ['agoda'], contains: ['agoda'] },
    { name: 'Hotels.com', match: /\bhotels\s?\.\s?com\b/i,
      domains: ['hotels.com'], names: ['hotelscom'], contains: ['hotelscom'] },
    { name: 'Trip.com', match: /\btrip\s?\.\s?com\b/i,
      domains: ['trip.com', 'ctrip.com'], names: ['tripcom', 'ctrip'], contains: ['tripcom'] },
    { name: 'HRS', match: /\bHRS\b/,
      domains: ['hrs.com', 'hrs.de'], names: ['hrs'], contains: [] }
  ];

  var SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly',
    'shorturl.at', 'rb.gy', 't.ly', 'tiny.cc', 's.id', 'lnkd.in', 'shorte.st', 'bl.ink', 'v.gd', 'qrco.de', 'tinyurl.is'
  ];

  var RISKY_EXTENSIONS = ['html', 'htm', 'zip', 'iso', 'img', 'lnk', 'js', 'exe', 'scr'];

  // Suffixes where the registrable domain has three labels (example.co.uk).
  var TWO_LEVEL_SUFFIXES = [
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.ae', 'net.ae', 'org.ae', 'gov.ae',
    'ac.ae', 'com.tr', 'com.br', 'co.jp', 'co.in', 'com.cn', 'com.sg', 'co.za', 'com.mx', 'co.nz', 'com.hk',
    'com.sa', 'com.eg', 'com.qa', 'com.kw', 'com.om', 'com.bh'
  ];

  // Points per signal. The total decides the verdict (see THRESHOLDS).
  var POINTS = {
    'auth-missing': 2,
    'auth-spf:fail': 3, 'auth-spf:softfail': 2, 'auth-spf:none': 1, 'auth-spf:missing': 1,
    'auth-dkim:fail': 2, 'auth-dkim:none': 1, 'auth-dkim:missing': 1,
    'auth-dmarc:fail': 4, 'auth-dmarc:none': 1, 'auth-dmarc:missing': 1,
    'from-missing': 2,
    'mismatch-reply-to': 3,
    'mismatch-return-path': 1,
    'display-address': 3,
    'brand-display': 5,
    'brand-subject': 2,
    'lookalike-tld': 4,
    'lookalike-swap': 5,
    'lookalike-typo': 5,
    'lookalike-extra': 4,
    'punycode': 4,
    'link-ip': 4,
    'link-shortener': 2,
    'link-punycode': 4,
    'link-text-mismatch': 4,
    'link-unrelated': 1,
    'content-payment': 3,
    'content-suspension': 3,
    'content-complaint-link': 3,
    'content-cancellation': 2,
    'content-clickfix': 5,
    'attachment-risky': 4,
    'attachment-password': 3,
    'info-first-hop': 0
  };

  var THRESHOLDS = { many: 8, some: 3 };

  var VERDICTS = {
    many: { en: 'Many warning signs', de: 'Viele Warnzeichen' },
    some: { en: 'Some warning signs', de: 'Einige Warnzeichen' },
    none: {
      en: 'No warning signs found — this does not mean the email is safe',
      de: 'Keine Warnzeichen gefunden – das bedeutet nicht, dass die E-Mail sicher ist'
    }
  };

  // Content keywords, English and German.
  var CONTENT_PATTERNS = {
    'content-payment': /verify (your )?(credit )?card|card (details|verification|information)|(update|confirm|verify) (your )?(payment|billing)|payment (has )?(failed|declined|required|overdue|is due)|urgent(ly)? (payment|transfer)|pay (immediately|now|today|within)|(kredit)?karten(daten|informationen)|kreditkarte (bestätigen|verifizieren|aktualisieren)|zahlung (ist )?(fehlgeschlagen|erforderlich|ausstehend|überfällig)|zahlungs(daten|informationen) (bestätigen|aktualisieren)|dringende (zahlung|überweisung)|sofort (bezahlen|überweisen)/i,
    'content-suspension': /account (will be |has been |is )?(temporarily )?(suspended|locked|blocked|deactivated|restricted|closed)|(suspend|deactivate|block)(ed)? your (account|listing|property)|suspension of your (account|listing|property)|(listing|property) (will be )?(suspended|deactivated|removed|delisted)|konto (wird |wurde )?(vorübergehend )?(gesperrt|deaktiviert|eingeschränkt)|sperrung (ihres|deines|des) (kontos|accounts|zugangs)|unterkunft (wird |wurde )?(deaktiviert|gesperrt|entfernt)/i,
    'content-complaint': /guest complaint|complaint (from|by) (a|your|the) guest|guest (has )?(reported|complained|claims)|negative review|gästebeschwerde|beschwerde (eines|von einem|des) gast|gast hat sich beschwert/i,
    'content-cancellation': /(reservation|booking)s? (will|would) be (automatically )?cancel+ed|(automatically )?cancel+ed (unless|if you do not|if not|within)|(reservierung|buchung) wird (automatisch )?(storniert|annulliert)|(automatisch|sonst) storniert/i,
    'content-clickfix': /win(dows)?(\s*-?\s*(key|taste))?\s*\+\s*r\b|press (the )?windows key|ctrl\s*\+\s*v[\s\S]{0,40}enter|paste (the|this) (command|code)|run dialog|powershell|mshta|cmd\.exe|ausführen-dialog|befehl einfügen|strg\s*\+\s*v[\s\S]{0,40}(enter|eingabe)/i,
    'attachment-password': /(password|passwort|kennwort)[^.\n]{0,60}(zip|rar|7z|archive|archiv|attachment|anhang|file|datei)|(zip|rar|7z|archive|archiv|attachment|anhang|file|datei)[^.\n]{0,60}(password|passwort|kennwort)/i
  };

  // ---------------------------------------------------------------------------
  // Messages (one sentence each, English and German)
  // ---------------------------------------------------------------------------

  var MESSAGES = {
    'auth-missing': {
      title: { en: 'No authentication results', de: 'Keine Authentifizierungsergebnisse' },
      en: 'No SPF, DKIM or DMARC results were found, so the sender could not be verified — check that you pasted the full headers.',
      de: 'Es wurden keine SPF-, DKIM- oder DMARC-Ergebnisse gefunden, daher ließ sich der Absender nicht prüfen – bitte prüfen Sie, ob Sie die vollständigen Header eingefügt haben.'
    },
    'auth-spf:fail': {
      title: { en: 'SPF failed', de: 'SPF fehlgeschlagen' },
      en: 'SPF failed: the server that sent this email is not allowed to send for {a}.',
      de: 'SPF fehlgeschlagen: Der sendende Server darf nicht im Namen von {a} senden.'
    },
    'auth-spf:softfail': {
      title: { en: 'SPF soft fail', de: 'SPF-Softfail' },
      en: 'SPF soft-failed: the sending server is probably not allowed to send for {a}.',
      de: 'SPF-Softfail: Der sendende Server ist wahrscheinlich nicht berechtigt, für {a} zu senden.'
    },
    'auth-spf:none': {
      title: { en: 'SPF: no result', de: 'SPF: kein Ergebnis' },
      en: 'SPF gave no result, so the sending server could not be checked against the sender\'s domain.',
      de: 'SPF lieferte kein Ergebnis, daher konnte der sendende Server nicht mit der Absenderdomain abgeglichen werden.'
    },
    'auth-spf:missing': {
      title: { en: 'SPF result missing', de: 'SPF-Ergebnis fehlt' },
      en: 'No SPF result was found in the headers.',
      de: 'In den Headern wurde kein SPF-Ergebnis gefunden.'
    },
    'auth-dkim:fail': {
      title: { en: 'DKIM failed', de: 'DKIM fehlgeschlagen' },
      en: 'DKIM failed: the digital signature does not match, so the email may have been forged or changed.',
      de: 'DKIM fehlgeschlagen: Die digitale Signatur stimmt nicht, die E-Mail könnte gefälscht oder verändert sein.'
    },
    'auth-dkim:none': {
      title: { en: 'No DKIM signature', de: 'Keine DKIM-Signatur' },
      en: 'The email has no valid DKIM signature, so its origin cannot be confirmed.',
      de: 'Die E-Mail hat keine gültige DKIM-Signatur, ihre Herkunft lässt sich daher nicht bestätigen.'
    },
    'auth-dkim:missing': {
      title: { en: 'DKIM result missing', de: 'DKIM-Ergebnis fehlt' },
      en: 'No DKIM result was found in the headers.',
      de: 'In den Headern wurde kein DKIM-Ergebnis gefunden.'
    },
    'auth-dmarc:fail': {
      title: { en: 'DMARC failed', de: 'DMARC fehlgeschlagen' },
      en: 'DMARC failed: the email does not prove that it really comes from {a}, the domain shown as sender.',
      de: 'DMARC fehlgeschlagen: Die E-Mail weist nicht nach, dass sie wirklich von {a} stammt, der angezeigten Absenderdomain.'
    },
    'auth-dmarc:none': {
      title: { en: 'No DMARC policy', de: 'Keine DMARC-Richtlinie' },
      en: 'The sender\'s domain has no DMARC policy, which makes it easier to fake.',
      de: 'Die Absenderdomain hat keine DMARC-Richtlinie, dadurch ist sie leichter zu fälschen.'
    },
    'auth-dmarc:missing': {
      title: { en: 'DMARC result missing', de: 'DMARC-Ergebnis fehlt' },
      en: 'No DMARC result was found in the headers.',
      de: 'In den Headern wurde kein DMARC-Ergebnis gefunden.'
    },
    'from-missing': {
      title: { en: 'No sender address', de: 'Keine Absenderadresse' },
      en: 'No sender address (From) was found in the headers.',
      de: 'In den Headern wurde keine Absenderadresse (From) gefunden.'
    },
    'mismatch-reply-to': {
      title: { en: 'Replies go elsewhere', de: 'Antworten gehen woanders hin' },
      en: 'Replies would go to {b}, not to the sender\'s domain {a}.',
      de: 'Antworten gingen an {b} und nicht an die Absenderdomain {a}.'
    },
    'mismatch-return-path': {
      title: { en: 'Different return address', de: 'Abweichende Rücklaufadresse' },
      en: 'The technical return address ({b}) differs from the sender\'s domain ({a}); this is common for mailing services but also used by fakers.',
      de: 'Die technische Rücklaufadresse ({b}) weicht von der Absenderdomain ({a}) ab; das ist bei Versanddiensten üblich, wird aber auch von Fälschern genutzt.'
    },
    'display-address': {
      title: { en: 'Fake address in sender name', de: 'Falsche Adresse im Absendernamen' },
      en: 'The sender name shows the address {b}, but the email really comes from {a}.',
      de: 'Der Absendername zeigt die Adresse {b}, die E-Mail kommt aber tatsächlich von {a}.'
    },
    'brand-display': {
      title: { en: 'Brand in sender name', de: 'Marke im Absendernamen' },
      en: 'The sender name mentions {b}, but the email comes from {a}, which is not an official {b} domain.',
      de: 'Der Absendername nennt {b}, die E-Mail kommt aber von {a}, keiner offiziellen Domain von {b}.'
    },
    'brand-subject': {
      title: { en: 'Brand in subject', de: 'Marke im Betreff' },
      en: 'The subject mentions {b} but the email comes from {a}, not an official {b} domain — normal if a guest wrote it, suspicious if it claims to be {b}.',
      de: 'Der Betreff nennt {b}, die E-Mail kommt aber von {a}, keiner offiziellen Domain von {b} – normal, wenn ein Gast schreibt, verdächtig, wenn sie vorgibt, von {b} zu sein.'
    },
    'lookalike-tld': {
      title: { en: 'Brand name, wrong ending', de: 'Markenname, falsche Endung' },
      en: '{a} uses the name of {b} with a different domain ending, a common fake.',
      de: '{a} verwendet den Namen von {b} mit einer anderen Domainendung – eine häufige Fälschung.'
    },
    'lookalike-swap': {
      title: { en: 'Swapped characters', de: 'Vertauschte Zeichen' },
      en: '{a} imitates {b} by swapping look-alike characters (such as 0 for o or rn for m).',
      de: '{a} ahmt {b} nach, indem ähnlich aussehende Zeichen vertauscht werden (z. B. 0 statt o oder rn statt m).'
    },
    'lookalike-typo': {
      title: { en: 'Lookalike domain', de: 'Doppelgänger-Domain' },
      en: '{a} is only one or two letters away from {b}, a typical lookalike domain.',
      de: '{a} unterscheidet sich nur um ein bis zwei Buchstaben von {b} – eine typische Doppelgänger-Domain.'
    },
    'lookalike-extra': {
      title: { en: 'Brand name with extra words', de: 'Markenname mit Zusatzwörtern' },
      en: '{a} adds extra words around the name of {b} but is not an official {b} domain.',
      de: '{a} ergänzt den Namen von {b} um zusätzliche Wörter, ist aber keine offizielle Domain von {b}.'
    },
    'punycode': {
      title: { en: 'Punycode sender domain', de: 'Punycode-Absenderdomain' },
      en: 'The sender domain {a} uses punycode (xn--), which can hide look-alike letters from other alphabets.',
      de: 'Die Absenderdomain {a} nutzt Punycode (xn--), womit sich ähnlich aussehende Buchstaben aus anderen Alphabeten verstecken lassen.'
    },
    'link-ip': {
      title: { en: 'Link to an IP address', de: 'Link zu einer IP-Adresse' },
      en: 'A link points to a raw IP address ({a}) instead of a normal domain name.',
      de: 'Ein Link führt zu einer reinen IP-Adresse ({a}) statt zu einem normalen Domainnamen.'
    },
    'link-shortener': {
      title: { en: 'Shortened link', de: 'Gekürzter Link' },
      en: 'A link uses a URL shortener ({a}), which hides the real destination.',
      de: 'Ein Link nutzt einen URL-Kürzer ({a}), der das wahre Ziel verbirgt.'
    },
    'link-punycode': {
      title: { en: 'Punycode link', de: 'Punycode-Link' },
      en: 'A link goes to a punycode domain ({a}), which can hide look-alike letters.',
      de: 'Ein Link führt zu einer Punycode-Domain ({a}), die ähnlich aussehende Buchstaben verbergen kann.'
    },
    'link-text-mismatch': {
      title: { en: 'Link text hides the real address', de: 'Linktext verbirgt die echte Adresse' },
      en: 'A link shows {b} but really opens {a}.',
      de: 'Ein Link zeigt {b} an, öffnet aber tatsächlich {a}.'
    },
    'link-unrelated': {
      title: { en: 'Links to unrelated domains', de: 'Links zu fremden Domains' },
      en: 'Links go to {a}, which matches neither the sender nor a known official domain.',
      de: 'Links führen zu {a} – das passt weder zum Absender noch zu einer bekannten offiziellen Domain.'
    },
    'content-payment': {
      title: { en: 'Payment or card request', de: 'Zahlungs- oder Kartenaufforderung' },
      en: 'The text asks for an urgent payment or for card details to be verified, a classic fake-OTA trick.',
      de: 'Der Text fordert eine dringende Zahlung oder die Bestätigung von Kartendaten – ein klassischer Trick gefälschter OTA-E-Mails.'
    },
    'content-suspension': {
      title: { en: 'Account suspension threat', de: 'Drohung mit Kontosperrung' },
      en: 'The text threatens that your account or listing will be suspended.',
      de: 'Der Text droht mit der Sperrung Ihres Kontos oder Ihrer Unterkunft.'
    },
    'content-complaint-link': {
      title: { en: 'Guest complaint with a link', de: 'Gästebeschwerde mit Link' },
      en: 'The email mentions a guest complaint and includes a link, a common way to deliver malware.',
      de: 'Die E-Mail erwähnt eine Gästebeschwerde und enthält einen Link – ein häufiger Weg, Schadsoftware zu verbreiten.'
    },
    'content-cancellation': {
      title: { en: 'Cancellation threat', de: 'Drohung mit Stornierung' },
      en: 'The text threatens that a reservation will be cancelled, to make you act fast.',
      de: 'Der Text droht mit der Stornierung einer Reservierung, damit Sie schnell handeln.'
    },
    'content-clickfix': {
      title: { en: '“ClickFix” instructions', de: '„ClickFix“-Anleitung' },
      en: 'The email asks you to press Win+R or paste a command — never do this, it installs malware (the “ClickFix” trick).',
      de: 'Die E-Mail fordert Sie auf, Win+R zu drücken oder einen Befehl einzufügen – tun Sie das nie, so wird Schadsoftware installiert (der „ClickFix“-Trick).'
    },
    'attachment-risky': {
      title: { en: 'Risky attachment', de: 'Riskanter Anhang' },
      en: 'The email has a risky attachment type ({a}) that can run code or open a fake login page.',
      de: 'Die E-Mail hat einen riskanten Anhangstyp ({a}), der Code ausführen oder eine gefälschte Anmeldeseite öffnen kann.'
    },
    'attachment-password': {
      title: { en: 'Password-protected archive', de: 'Passwortgeschütztes Archiv' },
      en: 'The email mentions a password-protected archive, which hides its contents from virus scanners.',
      de: 'Die E-Mail erwähnt ein passwortgeschütztes Archiv, dessen Inhalt Virenscanner nicht prüfen können.'
    },
    'info-first-hop': {
      title: { en: 'First external server', de: 'Erster externer Server' },
      en: 'The email entered the internet at {a} ({b}) — shown for information only.',
      de: 'Die E-Mail wurde über {a} ({b}) eingeliefert – nur zur Information.'
    }
  };

  var CATEGORY = {
    auth: 'auth', from: 'sender', mismatch: 'sender', display: 'sender', brand: 'brand',
    lookalike: 'lookalike', punycode: 'lookalike', link: 'links', content: 'content',
    attachment: 'content', info: 'received'
  };

  // ---------------------------------------------------------------------------
  // Small helpers
  // ---------------------------------------------------------------------------

  function fill(template, a, b) {
    return String(template).replace(/\{a\}/g, a == null ? '' : a).replace(/\{b\}/g, b == null ? '' : b);
  }

  function makeSignal(key, a, b, evidence) {
    var msg = MESSAGES[key];
    var id = key.split(':')[0];
    var points = POINTS[key] || 0;
    return {
      id: id,
      key: key,
      result: key.indexOf(':') > 0 ? key.split(':')[1] : undefined,
      category: CATEGORY[id.split('-')[0]] || 'other',
      points: points,
      severity: points >= 4 ? 'high' : points >= 2 ? 'medium' : points > 0 ? 'low' : 'info',
      title: { en: msg.title.en, de: msg.title.de },
      text: { en: fill(msg.en, a, b), de: fill(msg.de, a, b) },
      evidence: evidence || ''
    };
  }

  function bytesToString(bytes, charset) {
    var cs = String(charset || 'utf-8').toLowerCase();
    if (typeof TextDecoder === 'function') {
      try { return new TextDecoder(cs).decode(new Uint8Array(bytes)); } catch (e) { /* fall through */ }
      try { return new TextDecoder('utf-8').decode(new Uint8Array(bytes)); } catch (e2) { /* fall through */ }
    }
    var out = '';
    for (var i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
    return out;
  }

  function b64ToBytes(s) {
    var clean = String(s).replace(/[^A-Za-z0-9+/=_-]/g, '').replace(/-/g, '+').replace(/_/g, '/');
    while (clean.length % 4) clean += '=';
    var bin = atob(clean);
    var bytes = [];
    for (var i = 0; i < bin.length; i++) bytes.push(bin.charCodeAt(i));
    return bytes;
  }

  function strToBytes(s) {
    if (typeof TextEncoder === 'function') return Array.prototype.slice.call(new TextEncoder().encode(s));
    var out = [];
    for (var i = 0; i < s.length; i++) out.push(s.charCodeAt(i) & 255);
    return out;
  }

  // Quoted-printable (body) or Q-encoding (headers, underscores are spaces).
  function qpToBytes(s, isHeader) {
    var src = isHeader ? s.replace(/_/g, ' ') : s.replace(/=\r?\n/g, '');
    var bytes = [];
    var i = 0;
    while (i < src.length) {
      var c = src.charAt(i);
      if (c === '=' && /^[0-9A-Fa-f]{2}$/.test(src.substr(i + 1, 2))) {
        bytes.push(parseInt(src.substr(i + 1, 2), 16));
        i += 3;
      } else {
        var code = src.charCodeAt(i);
        if (code < 128) bytes.push(code);
        else bytes = bytes.concat(strToBytes(c));
        i += 1;
      }
    }
    return bytes;
  }

  // RFC 2047 encoded words: =?UTF-8?B?...?= and =?UTF-8?Q?...?=
  function decodeWords(s) {
    return String(s || '').replace(/=\?([^?\s]+)\?([bBqQ])\?([^?]*)\?=(\s+(?==\?))?/g, function (all, cs, enc, txt) {
      try {
        var bytes = enc.toUpperCase() === 'B' ? b64ToBytes(txt) : qpToBytes(txt, true);
        return bytesToString(bytes, cs.split('*')[0]);
      } catch (e) {
        return all;
      }
    });
  }

  var ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: '\'', nbsp: ' ' };
  function decodeEntities(s) {
    return String(s || '').replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, function (all, e) {
      if (e.charAt(0) === '#') {
        var n = e.charAt(1).toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
        try { return String.fromCodePoint(n); } catch (err) { return all; }
      }
      var v = ENTITIES[e.toLowerCase()];
      return v == null ? all : v;
    });
  }

  function stripHtml(html) {
    return decodeEntities(String(html || '')
      .replace(/<!-{2}[\s\S]*?-{2}>/g, ' ')
      .replace(/<(style|script|head)\b[\s\S]*?<\/\1\s*>/gi, ' ')
      .replace(/<br\s*\/?>|<\/(p|div|tr|li|h[1-6])\s*>/gi, '\n')
      .replace(/<[^>]+>/g, ' '))
      .replace(/[ \t ]+/g, ' ');
  }

  function looksLikeHtml(s) {
    return /<(html|body|div|p|a|table|br|span)\b[^>]*>/i.test(s);
  }

  // ---------------------------------------------------------------------------
  // Domains
  // ---------------------------------------------------------------------------

  function toAsciiHost(host) {
    var h = String(host || '').trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
    if (!h) return '';
    if (/[^\x00-\x7f]/.test(h) && typeof URL === 'function') {
      try { return new URL('http://' + h).hostname; } catch (e) { /* keep as is */ }
    }
    return h;
  }

  function isIp(host) {
    var h = String(host || '').replace(/^\[|\]$/g, '');
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || (h.indexOf(':') >= 0 && /^[0-9a-f:.]+$/i.test(h));
  }

  function isPrivateIp(ip) {
    var h = String(ip || '').toLowerCase();
    if (h.indexOf(':') >= 0) return h === '::1' || /^f[cd]/.test(h) || /^fe80/.test(h);
    var p = h.split('.').map(Number);
    return p[0] === 10 || p[0] === 127 || p[0] === 0 ||
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) ||
      (p[0] === 169 && p[1] === 254) ||
      (p[0] === 100 && p[1] >= 64 && p[1] <= 127);
  }

  function registrableDomain(host) {
    var h = toAsciiHost(host);
    if (!h || isIp(h)) return h;
    var labels = h.split('.');
    if (labels.length <= 2) return h;
    var last2 = labels.slice(-2).join('.');
    if (TWO_LEVEL_SUFFIXES.indexOf(last2) >= 0) return labels.slice(-3).join('.');
    return last2;
  }

  // Optimal string alignment distance (Levenshtein plus adjacent swaps).
  function editDistance(a, b) {
    var m = a.length, n = b.length, d = [], i, j;
    for (i = 0; i <= m; i++) { d[i] = [i]; }
    for (j = 0; j <= n; j++) { d[0][j] = j; }
    for (i = 1; i <= m; i++) {
      for (j = 1; j <= n; j++) {
        var cost = a.charAt(i - 1) === b.charAt(j - 1) ? 0 : 1;
        d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
        if (i > 1 && j > 1 && a.charAt(i - 1) === b.charAt(j - 2) && a.charAt(i - 2) === b.charAt(j - 1)) {
          d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
        }
      }
    }
    return d[m][n];
  }

  // Maps look-alike characters to one shape, so b00king and booking compare equal.
  function skeleton(s) {
    return String(s).toLowerCase()
      .replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/cl/g, 'd')
      .replace(/0/g, 'o').replace(/[1i|!]/g, 'l').replace(/3/g, 'e').replace(/5/g, 's').replace(/q/g, 'g');
  }

  // Brand list plus the hotel's own name and domain from settings.
  function buildCandidates(settings) {
    var list = OFFICIAL_BRANDS.slice();
    var s = settings || {};
    var ownDomain = registrableDomain(s.hotelDomain || '');
    var ownName = String(s.hotelName || '').trim();
    if (ownDomain || ownName.length >= 3) {
      var label = ownDomain ? ownDomain.split('.')[0] : '';
      var escaped = ownName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+');
      list.push({
        name: ownName || ownDomain,
        own: true,
        match: ownName.length >= 3 ? new RegExp('(^|[^a-z0-9])' + escaped + '($|[^a-z0-9])', 'i') : null,
        domains: ownDomain ? [ownDomain] : [],
        names: label.length >= 4 ? [label] : [],
        contains: label.length >= 6 ? [label] : []
      });
    }
    return list;
  }

  function isOfficial(reg, candidates) {
    for (var i = 0; i < candidates.length; i++) {
      if (candidates[i].domains.indexOf(reg) >= 0) return true;
    }
    return false;
  }

  // Returns { kind, brand, official } for a suspicious host, or null.
  // kind: punycode | tld | swap | typo | extra
  function checkLookalike(host, settings, candidatesIn) {
    var h = toAsciiHost(host);
    if (!h || isIp(h)) return null;
    var candidates = candidatesIn || buildCandidates(settings);
    var reg = registrableDomain(h);
    if (isOfficial(reg, candidates)) return null;
    if (/(^|\.)xn--/.test(h)) return { kind: 'punycode', host: h, brand: '', official: '' };

    var sld = reg.split('.')[0];
    var flat = sld.replace(/-/g, '');
    var i, j, c, name;
    function similar(label, nm) {
      if (skeleton(label) === skeleton(nm)) return 'swap';
      if (nm.length >= 5 && editDistance(label, nm) <= (nm.length >= 7 ? 2 : 1)) return 'typo';
      return null;
    }
    for (i = 0; i < candidates.length; i++) {
      c = candidates[i];
      for (j = 0; j < c.names.length; j++) {
        name = c.names[j];
        var hit = flat === name ? 'tld' : similar(flat, name);
        if (hit) return { kind: hit, host: h, brand: c.name, official: c.domains[0] || c.name };
      }
    }
    // Parts of a hyphenated label: grandpalrn-hotel, b00king-support
    var parts = sld.split('-').filter(function (p) { return p.length >= 4; });
    if (parts.length > 1) {
      for (i = 0; i < candidates.length; i++) {
        c = candidates[i];
        for (j = 0; j < c.names.length; j++) {
          for (var p = 0; p < parts.length; p++) {
            if (parts[p] === c.names[j]) continue; // exact name plus words is reported as 'extra'
            var near = similar(parts[p], c.names[j]);
            if (near) return { kind: near, host: h, brand: c.name, official: c.domains[0] || c.name };
          }
        }
      }
    }

    var labels = h.split('.').slice(0, -1);
    var tokens = [];
    labels.forEach(function (l) { tokens = tokens.concat(l.split('-')); });
    for (i = 0; i < candidates.length; i++) {
      c = candidates[i];
      for (j = 0; j < c.names.length; j++) {
        if (tokens.indexOf(c.names[j]) >= 0) return { kind: 'extra', host: h, brand: c.name, official: c.domains[0] || c.name };
      }
      for (j = 0; j < c.contains.length; j++) {
        for (var k = 0; k < labels.length; k++) {
          if (labels[k].replace(/-/g, '').indexOf(c.contains[j]) >= 0) {
            return { kind: 'extra', host: h, brand: c.name, official: c.domains[0] || c.name };
          }
        }
      }
    }
    return null;
  }

  // ---------------------------------------------------------------------------
  // Headers
  // ---------------------------------------------------------------------------

  var HEADER_LINE = /^([!-9;-~]+):[ \t]?(.*)$/;

  function parseHeaders(text) {
    var lines = String(text || '').replace(/\r\n?/g, '\n').split('\n');
    var list = [];
    var cur = null;
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (/^[ \t]/.test(line) && cur) { cur.value += ' ' + line.trim(); continue; }
      var m = HEADER_LINE.exec(line);
      if (m) { cur = { name: m[1].toLowerCase(), value: m[2].trim() }; list.push(cur); }
      else cur = null;
    }
    return list;
  }

  // Splits pasted text into its header block and anything after it. Picks the block
  // with the most header lines, so a summary table above the raw source is skipped.
  function splitMessage(text) {
    var src = String(text || '').replace(/\r\n?/g, '\n');
    var blocks = src.split(/\n[ \t]*\n/);
    var best = -1, bestCount = 0;
    for (var i = 0; i < blocks.length; i++) {
      var count = 0;
      blocks[i].split('\n').forEach(function (l) { if (HEADER_LINE.test(l)) count++; });
      if (count > bestCount) { bestCount = count; best = i; }
    }
    if (best < 0) return { headers: src, rest: '' };
    return { headers: blocks[best], rest: blocks.slice(best + 1).join('\n\n') };
  }

  function headerGetter(list) {
    return {
      all: function (name) { return list.filter(function (h) { return h.name === name; }).map(function (h) { return h.value; }); },
      first: function (name) {
        for (var i = 0; i < list.length; i++) if (list[i].name === name) return list[i].value;
        return '';
      }
    };
  }

  function parseAddress(value) {
    var v = decodeWords(value || '').trim();
    var display = '', address = '';
    var m = /^([\s\S]*?)<\s*([^<>]*?)\s*>\s*$/.exec(v) || /^([\s\S]*?)<\s*([^<>]*?)\s*>/.exec(v);
    if (m) {
      display = m[1];
      address = m[2];
    } else {
      var a = /[^\s<>"(),;:]+@[^\s<>"(),;]+/.exec(v);
      address = a ? a[0] : '';
      display = a ? v.replace(a[0], '').replace(/^\s*\(|\)\s*$/g, '') : v;
    }
    display = display.trim().replace(/^"|"$/g, '').replace(/\\"/g, '"').trim();
    address = address.replace(/^mailto:/i, '').trim();
    var at = address.lastIndexOf('@');
    var domain = at >= 0 ? toAsciiHost(address.slice(at + 1)) : '';
    return { display: display, address: address, domain: domain, registrable: domain ? registrableDomain(domain) : '' };
  }

  function normResult(v) {
    var r = String(v || '').toLowerCase();
    if (r === 'pass') return 'pass';
    if (r === 'softfail') return 'softfail';
    if (r === 'fail' || r === 'hardfail' || r === 'permerror' || r === 'policy') return 'fail';
    return 'none';
  }

  function parseAuthValue(value) {
    var out = {};
    var re = /(?:^|[;\s])(spf|dkim|dmarc)\s*=\s*([a-z]+)/gi, m;
    while ((m = re.exec(value))) {
      var method = m[1].toLowerCase();
      (out[method] = out[method] || []).push(m[2].toLowerCase());
    }
    var p = /\bdmarc\s*=\s*[a-z]+[^;]*?\bp=([a-z]+)/i.exec(value);
    if (p) out.policy = p[1].toLowerCase();
    return out;
  }

  function combine(method, values) {
    if (!values || !values.length) return null;
    var r;
    if (method === 'dkim') r = values.indexOf('pass') >= 0 ? 'pass' : normResult(values[0]);
    else r = normResult(values[0]);
    if (method !== 'spf' && r === 'softfail') r = 'fail';
    return r;
  }

  // Uses the topmost Authentication-Results header (added by your own mail server),
  // then Received-SPF, then ARC-Authentication-Results.
  function readAuth(h) {
    var auth = { spf: 'missing', dkim: 'missing', dmarc: 'missing', source: {}, policy: '' };
    var sources = [['authentication-results', h.all('authentication-results')],
      ['arc-authentication-results', h.all('arc-authentication-results')]];
    ['spf', 'dkim', 'dmarc'].forEach(function (method) {
      for (var s = 0; s < sources.length; s++) {
        if (s === 1 && method === 'spf' && auth.spf !== 'missing') break;
        var values = sources[s][1];
        for (var i = 0; i < values.length; i++) {
          var parsed = parseAuthValue(values[i]);
          var r = combine(method, parsed[method]);
          if (r) {
            auth[method] = r;
            auth.source[method] = sources[s][0];
            if (method === 'dmarc' && parsed.policy) auth.policy = parsed.policy;
            return;
          }
        }
        if (s === 0 && method === 'spf') {
          var rs = h.first('received-spf');
          var m = /^\s*([a-z]+)/i.exec(rs);
          if (m) { auth.spf = normResult(m[1]); auth.source.spf = 'received-spf'; return; }
        }
      }
    });
    return auth;
  }

  function firstExternalHop(h) {
    var received = h.all('received');
    for (var i = received.length - 1; i >= 0; i--) {
      var r = received[i];
      var fromPart = (/\bfrom\s+([\s\S]*?)(?:\sby\s|;|$)/i.exec(r) || [])[1];
      if (!fromPart) continue;
      var ipm = /\[(?:ipv6:)?([0-9a-f:.]+)\]/i.exec(fromPart) || /\((\d{1,3}(?:\.\d{1,3}){3})\)/.exec(fromPart);
      if (!ipm || !isIp(ipm[1])) continue;
      var rdns = /\(\s*([a-z0-9.-]+\.[a-z]{2,})\s*\[/i.exec(fromPart);
      var token = fromPart.trim().split(/\s+/)[0].replace(/^\[|\]$/g, '');
      var host = rdns ? rdns[1] : (isIp(token) ? '' : token);
      var hop = { host: host || ipm[1], ip: ipm[1] };
      if (!isPrivateIp(ipm[1])) return hop;
    }
    return null;
  }

  // ---------------------------------------------------------------------------
  // Body: MIME parts, links, attachments
  // ---------------------------------------------------------------------------

  function paramOf(headerValue, name) {
    var re = new RegExp('(?:^|;)\\s*' + name + '\\*?\\s*=\\s*("([^"]*)"|[^;\\s]+)', 'i');
    var m = re.exec(headerValue || '');
    if (!m) return '';
    var v = m[2] != null ? m[2] : m[1];
    v = v.replace(/^utf-8''/i, '');
    try { if (/%[0-9a-f]{2}/i.test(v)) v = decodeURIComponent(v); } catch (e) { /* keep */ }
    return decodeWords(v);
  }

  function decodeTransfer(content, cte, charset) {
    var enc = String(cte || '').toLowerCase();
    try {
      if (enc.indexOf('base64') >= 0 && /^[A-Za-z0-9+\/=\s]+$/.test(content)) return bytesToString(b64ToBytes(content), charset);
      if (enc.indexOf('quoted-printable') >= 0) return bytesToString(qpToBytes(content, false), charset);
    } catch (e) { /* keep raw */ }
    return content;
  }

  // Walks multipart bodies. Collects decoded text/html parts and attachment names.
  function readMime(headerList, raw, out, depth) {
    var h = headerGetter(headerList);
    var ctype = h.first('content-type');
    var cte = h.first('content-transfer-encoding');
    var charset = paramOf(ctype, 'charset') || 'utf-8';
    var disp = h.first('content-disposition');
    var fname = paramOf(disp, 'filename') || paramOf(ctype, 'name');
    if (fname) out.attachments.push(fname);
    var boundary = paramOf(ctype, 'boundary');
    if (!boundary && depth === 0) {
      var bm = /^--([^\s-][^\s]{5,})\s*$/m.exec(raw);
      if (bm && raw.indexOf('--' + bm[1] + '--') >= 0) boundary = bm[1];
    }
    if (boundary && depth < 6 && raw.indexOf('--' + boundary) >= 0) {
      var pieces = raw.split('--' + boundary);
      for (var i = 1; i < pieces.length; i++) {
        var piece = pieces[i];
        if (/^--/.test(piece)) break;
        piece = piece.replace(/^\r?\n/, '');
        var cut = piece.search(/\r?\n\r?\n/);
        var ph = cut >= 0 ? piece.slice(0, cut) : '';
        var pb = cut >= 0 ? piece.slice(cut).replace(/^\r?\n\r?\n/, '') : piece;
        readMime(parseHeaders(ph), pb, out, depth + 1);
      }
      return;
    }
    if (fname || /^(image|audio|video|application)\//i.test(ctype)) return;
    var looksQp = !cte && depth === 0 && (/=3D/i.test(raw) || (/=\r?\n/.test(raw) && /=[0-9A-F]{2}/.test(raw)));
    var text = decodeTransfer(raw, looksQp ? 'quoted-printable' : cte, charset);
    if (/html/i.test(ctype) || looksLikeHtml(text)) out.html.push(text);
    else out.text.push(text);
  }

  function hostOfUrl(u) {
    var url = /^www\./i.test(u) ? 'http://' + u : u;
    if (typeof URL === 'function') {
      try { return toAsciiHost(new URL(url).hostname); } catch (e) { /* fall back */ }
    }
    var m = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@\/?#]*@)?(\[[^\]]+\]|[^\/:?#]+)/i.exec(url);
    return m ? toAsciiHost(m[1]) : '';
  }

  function cleanUrl(u) {
    return decodeEntities(String(u || '').trim()).replace(/[.,;:!?)\]}'"]+$/, '');
  }

  var DOMAIN_IN_TEXT = /(?:^|[^@\w.-])(?:https?:\/\/)?((?:[a-z0-9¡-￿](?:[a-z0-9¡-￿-]*[a-z0-9¡-￿])?\.)+[a-z¡-￿]{2,})(?=$|[\/\s:?#),.])/i;

  function extractLinks(html, text) {
    var links = [];
    var seen = {};
    function add(url, shown) {
      var u = cleanUrl(url);
      if (!/^(https?:\/\/|www\.)/i.test(u)) return;
      var key = u + '|' + (shown || '');
      if (seen[key]) return;
      seen[key] = true;
      links.push({ url: u, host: hostOfUrl(u), text: shown || '' });
    }
    var all = html.join('\n');
    var a = /<a\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a\s*>/gi, m;
    while ((m = a.exec(all))) add(m[1] || m[2] || m[3], stripHtml(m[4]).trim());
    var plain = text.join('\n') + '\n' + stripHtml(all.replace(/<a\b[^>]*>[\s\S]*?<\/a\s*>/gi, ' '));
    var shownRe = /(\S+)\s*<\s*((?:https?:\/\/|www\.)[^>\s]+)\s*>/gi;
    while ((m = shownRe.exec(plain))) add(m[2], m[1]);
    var bare = /\b(?:https?:\/\/|www\.)[^\s<>"'`{}|\\^]+/gi;
    while ((m = bare.exec(plain))) {
      var u = cleanUrl(m[0]);
      var dup = links.some(function (l) { return l.url === u; });
      if (!dup) add(u, '');
    }
    return links;
  }

  function findAttachments(names, text) {
    var found = [];
    var extRe = new RegExp('\\.(' + RISKY_EXTENSIONS.join('|') + ')$', 'i');
    names.forEach(function (n) { if (extRe.test(n.trim())) found.push(n.trim()); });
    var scrubbed = text.replace(/\b(?:https?:\/\/|www\.)\S+/gi, ' ');
    var re = new RegExp('(^|[\\s"\'(\\[:])([^\\s"\'<>/\\\\:*?|()\\[\\]]{1,80}\\.(' + RISKY_EXTENSIONS.join('|') + '))(?=$|[\\s"\').,;\\]])', 'gim');
    var m;
    while ((m = re.exec(scrubbed))) {
      if (found.indexOf(m[2]) < 0) found.push(m[2]);
    }
    return found;
  }

  // ---------------------------------------------------------------------------
  // Main
  // ---------------------------------------------------------------------------

  function verdictFor(score) {
    if (score >= THRESHOLDS.many) return 'many';
    if (score >= THRESHOLDS.some) return 'some';
    return 'none';
  }

  function listShort(items) {
    var u = [];
    items.forEach(function (x) { if (x && u.indexOf(x) < 0) u.push(x); });
    return u.slice(0, 3).join(', ') + (u.length > 3 ? ' (+' + (u.length - 3) + ')' : '');
  }

  /**
   * analyze(headersText, bodyText, settings)
   *   headersText: pasted headers (or the whole raw email source)
   *   bodyText:    optional pasted text or HTML of the email
   *   settings:    { hotelName, hotelDomain }
   * Returns { score, verdict, verdictText, signals, info }.
   */
  function analyze(headersText, bodyText, settings) {
    var split = splitMessage(headersText);
    var headerList = parseHeaders(split.headers);
    var h = headerGetter(headerList);
    var rawBody = String(bodyText || '').trim() ? String(bodyText) : split.rest;
    var candidates = buildCandidates(settings);
    var signals = [];

    var from = parseAddress(h.first('from'));
    var replyTo = h.first('reply-to');
    var returnPath = parseAddress(h.first('return-path'));
    var subject = decodeWords(h.first('subject'));
    var auth = readAuth(h);
    var hasHeaders = headerList.length > 0;

    // 1. Authentication
    if (hasHeaders) {
      if (auth.spf === 'missing' && auth.dkim === 'missing' && auth.dmarc === 'missing') {
        signals.push(makeSignal('auth-missing'));
      } else {
        ['spf', 'dkim', 'dmarc'].forEach(function (method) {
          var r = auth[method];
          if (r === 'pass') return;
          // SPF checks the envelope sender (Return-Path); DMARC checks the visible From.
          var domain = method === 'spf' ? (returnPath.domain || from.domain) : from.domain;
          signals.push(makeSignal('auth-' + method + ':' + r, domain || '?', '', method + '=' + r));
        });
      }
    }

    // 2. Sender mismatch
    if (hasHeaders && !from.domain) signals.push(makeSignal('from-missing'));
    if (from.domain) {
      var replyDomains = [];
      replyTo.split(',').forEach(function (part) {
        var r = parseAddress(part);
        if (r.registrable && r.registrable !== from.registrable && replyDomains.indexOf(r.domain) < 0) replyDomains.push(r.domain);
      });
      if (replyDomains.length) {
        signals.push(makeSignal('mismatch-reply-to', from.domain, replyDomains.join(', '), 'Reply-To: ' + replyTo));
      }
      if (returnPath.registrable && returnPath.registrable !== from.registrable) {
        signals.push(makeSignal('mismatch-return-path', from.domain, returnPath.domain, 'Return-Path: ' + returnPath.address));
      }
      var shownAddr = /[^\s<>"'(),;:]+@([a-z0-9.-]+\.[a-z]{2,})/i.exec(from.display);
      if (shownAddr && registrableDomain(shownAddr[1]) !== from.registrable) {
        signals.push(makeSignal('display-address', from.address, shownAddr[0], 'From: ' + from.display));
      }
    }

    // 3. Brand impersonation
    if (from.registrable) {
      var ownReg = registrableDomain((settings || {}).hotelDomain || '');
      var brandHit = null;
      if (from.registrable !== ownReg) {
        for (var bi = 0; bi < candidates.length; bi++) {
          var c = candidates[bi];
          if (!c.match || c.domains.indexOf(from.registrable) >= 0) continue;
          if (c.match.test(from.display)) { brandHit = { key: 'brand-display', brand: c.name, where: from.display }; break; }
          if (!brandHit && c.match.test(subject)) brandHit = { key: 'brand-subject', brand: c.name, where: subject };
        }
      }
      if (brandHit) signals.push(makeSignal(brandHit.key, from.domain, brandHit.brand, brandHit.where));
    }

    // 4. Lookalike domains (sender side; link hosts are added below)
    var lookalikeSeen = {};
    function lookalikeSignal(host, isLink) {
      var res = checkLookalike(host, settings, candidates);
      if (!res) return false;
      if (res.kind === 'punycode' && isLink) return false; // reported as link-punycode
      var reg = registrableDomain(host);
      if (lookalikeSeen[reg]) return true;
      lookalikeSeen[reg] = true;
      var key = res.kind === 'punycode' ? 'punycode' : 'lookalike-' + res.kind;
      var named = res.kind === 'extra' || res.kind === 'tld' ? res.brand : res.official;
      signals.push(makeSignal(key, res.host, named, res.host));
      return true;
    }
    var senderHosts = [from.domain, returnPath.domain];
    replyTo.split(',').forEach(function (part) { senderHosts.push(parseAddress(part).domain); });
    senderHosts.forEach(function (d) { if (d) lookalikeSignal(d, false); });

    // 5. Links
    var mime = { text: [], html: [], attachments: [] };
    if (String(rawBody).trim()) {
      var bodySplit = /^(?:[!-9;-~]+:[^\n]*\n(?:[ \t][^\n]*\n)*)+\n/.exec(String(rawBody).replace(/\r\n?/g, '\n'));
      if (bodySplit && /content-type:/i.test(bodySplit[0])) {
        readMime(parseHeaders(bodySplit[0]), String(rawBody).replace(/\r\n?/g, '\n').slice(bodySplit[0].length), mime, 0);
      } else {
        readMime(headerList.filter(function (x) { return /^content-/.test(x.name); }), String(rawBody), mime, 0);
      }
    }
    // Attachment names may also appear in pasted headers of the full source.
    split.headers.replace(/(?:file)?name\*?\s*=\s*"?([^";\n]+)"?/gi, function (all, n) { mime.attachments.push(decodeWords(n)); return all; });

    var links = extractLinks(mime.html, mime.text);
    var ips = [], shorteners = [], puny = [], mismatches = [], unrelated = [];
    links.forEach(function (link) {
      var host = link.host;
      if (!host) return;
      var reg = registrableDomain(host);
      var flagged = false;
      if (isIp(host)) { ips.push(host); flagged = true; }
      else if (SHORTENERS.indexOf(host.replace(/^www\./, '')) >= 0) { shorteners.push(host); flagged = true; }
      if (/(^|\.)xn--/.test(host)) { puny.push(host); flagged = true; }
      if (link.text) {
        var shown = DOMAIN_IN_TEXT.exec(link.text);
        if (shown) {
          var shownHost = toAsciiHost(shown[1]);
          if (registrableDomain(shownHost) !== reg) { mismatches.push({ shown: shownHost, real: host }); flagged = true; }
        }
      }
      if (!isIp(host) && lookalikeSignal(host, true)) flagged = true;
      if (!flagged && reg !== from.registrable && !isOfficial(reg, candidates)) unrelated.push(host);
    });
    if (ips.length) signals.push(makeSignal('link-ip', listShort(ips), '', listShort(ips)));
    if (shorteners.length) signals.push(makeSignal('link-shortener', listShort(shorteners), '', listShort(shorteners)));
    if (puny.length) signals.push(makeSignal('link-punycode', listShort(puny), '', listShort(puny)));
    if (mismatches.length) {
      signals.push(makeSignal('link-text-mismatch', mismatches[0].real, mismatches[0].shown,
        mismatches.map(function (x) { return x.shown + ' → ' + x.real; }).slice(0, 3).join('; ')));
    }
    if (unrelated.length) signals.push(makeSignal('link-unrelated', listShort(unrelated), '', listShort(unrelated)));

    // 6. Content signals
    var bodyPlain = mime.text.join('\n') + '\n' + mime.html.map(stripHtml).join('\n');
    var content = (subject + '\n' + bodyPlain).replace(/[ \t]+/g, ' ');
    ['content-payment', 'content-suspension', 'content-cancellation', 'content-clickfix'].forEach(function (id) {
      var m = CONTENT_PATTERNS[id].exec(content);
      if (m) signals.push(makeSignal(id, '', '', '“' + m[0].trim() + '”'));
    });
    var complaint = CONTENT_PATTERNS['content-complaint'].exec(content);
    if (complaint && links.length) signals.push(makeSignal('content-complaint-link', '', '', '“' + complaint[0].trim() + '”'));
    var risky = findAttachments(mime.attachments, bodyPlain);
    if (risky.length) signals.push(makeSignal('attachment-risky', listShort(risky), '', listShort(risky)));
    var pw = CONTENT_PATTERNS['attachment-password'].exec(content);
    if (pw) signals.push(makeSignal('attachment-password', '', '', '“' + pw[0].trim() + '”'));

    // 7. Received chain (information only)
    var hop = firstExternalHop(h);
    if (hop) signals.push(makeSignal('info-first-hop', hop.host, hop.ip, hop.host + ' [' + hop.ip + ']'));

    var score = signals.reduce(function (sum, s) { return sum + s.points; }, 0);
    var verdict = verdictFor(score);
    signals.sort(function (x, y) { return y.points - x.points; });
    return {
      score: score,
      verdict: verdict,
      verdictText: VERDICTS[verdict],
      signals: signals,
      info: {
        from: from,
        subject: subject,
        replyTo: replyTo,
        returnPath: returnPath.address,
        auth: auth,
        firstHop: hop,
        links: links.length,
        headerCount: headerList.length
      }
    };
  }

  return {
    analyze: analyze,
    OFFICIAL_BRANDS: OFFICIAL_BRANDS,
    SHORTENERS: SHORTENERS,
    RISKY_EXTENSIONS: RISKY_EXTENSIONS,
    POINTS: POINTS,
    THRESHOLDS: THRESHOLDS,
    VERDICTS: VERDICTS,
    MESSAGES: MESSAGES,
    // exposed for tests
    _: {
      parseHeaders: parseHeaders,
      parseAddress: parseAddress,
      registrableDomain: registrableDomain,
      editDistance: editDistance,
      checkLookalike: checkLookalike,
      extractLinks: extractLinks,
      decodeWords: decodeWords,
      readAuth: function (text) { return readAuth(headerGetter(parseHeaders(text))); },
      isIp: isIp
    }
  };
});
