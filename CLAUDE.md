# Phishing Check — spot fake emails before you click

## Goal
Two linked, self-contained web pages (portfolio piece for an email-security and tech-sales job search):
1. **Phishing Check** (src/ui.html → docs/index.html): anyone who handles email at work pastes a suspicious email's headers, and optionally its text, and sees the warning signs in plain language.
   Example sets: hotels / OTAs (fake Booking.com etc., the original focus), fake Microsoft 365 login, supplier bank-detail change.
2. **Domain Email Check** (src/domain.html + src/dnscheck.js → docs/domain.html): type a domain, see how well it is protected against spoofing (SPF, DKIM, DMARC, MX).

## Owner
Aleksandar (short form "Aco") is not a developer but is very tech-literate. He is a former hotel Front Office Manager.
Talk to him in Bosnian/Serbian, in at most 2 short sentences per explanation.

## Non-negotiable rules
These apply to Phishing Check; the Domain Email Check exceptions are listed in its own section below.
- **Runs 100% in the browser.** No network calls, no external fonts, CDNs or analytics. Pasted content never leaves the device, and the UI says so.
- **Never label an email "safe".** The only verdicts are:
  - "Many warning signs"
  - "Some warning signs"
  - "No warning signs found — this does not mean the email is safe"
- **Defensive only.** No real guest emails or real personal data anywhere in the repo. All test emails are synthetic, using example.com or .test domains and invented names.
- **Plain technology.** Plain HTML, CSS and vanilla JavaScript, with Node built-ins only: no frameworks, no npm packages.
  - Source lives in src/: analyzer.js and dnscheck.js work in both Node and the browser, plus ui.html and domain.html.
  - build.js inlines them into two self-contained files, docs/index.html and docs/domain.html, and fails on any external resource or unexpected connect-src.
- The two pages link to each other.

## Working rules (save tokens)
- Never print whole files into the conversation. Report counts and short samples only.
- Commit after each step. If something fails the same way twice, stop and explain.

## Checks
Each check produces a signal with a one-sentence explanation in English and German.

1. **Authentication.** Parse the Authentication-Results, Received-SPF and ARC headers to get the SPF, DKIM and DMARC results: pass, fail, softfail, none or missing.
2. **Sender mismatch.** Compare the domains of From, Reply-To and Return-Path.
3. **Brand impersonation.** Flag when the display name or subject names one of the brands below, but the From domain is not on the official domain list.
   - Brands (8): Booking.com, Expedia, Airbnb, Agoda, Hotels.com, Trip.com, HRS, Microsoft 365, plus the hotel's own name (from settings).
   - Keep the official list in one editable array.
4. **Lookalike domains.** Compare sender and link domains against the official list. Flag:
   - edit distance of 2 or less
   - swapped characters (0/o, 1/l, rn/m)
   - extra words (booking-com-secure, booking.reservation-help)
   - punycode (xn--)
5. **Links** (when the body is pasted). Extract the URLs and flag:
   - raw IP addresses
   - URL shorteners
   - punycode
   - link text that shows a different domain than the real link
   - links to domains that match neither the sender nor the official list
6. **Content signals** (English and German keywords):
   - urgent payment or card verification
   - account suspension
   - a "guest complaint" with a link
   - "reservation will be cancelled"
   - instructions to press Win+R or paste a command (the "ClickFix" pattern)
   - risky attachments: .html, .htm, .zip, .iso, .img, .lnk, .js, .exe, .scr, password-protected archives
7. **Received chain.** Show the first external hop (host and IP) for information only, with no verdict.

**Scoring:** transparent points per signal, with the thresholds documented in the README.

## Plan

1. **Core and tests.**
   - Write src/analyzer.js.
   - Add 14 synthetic emails in tests/emails/:
     - 10 phishing emails in different styles: fake Booking.com payment request, fake guest complaint with a link, ClickFix, lookalike domain, fake Microsoft 365 login, supplier bank-detail change, and others
     - 4 legitimate-looking emails with valid authentication
   - Write tests/run.js, which checks the expected verdict and the key signals for each email.
   - Report the pass rate. Fix the analyzer until all tests pass.
2. **UI.** Build src/ui.html and build.js, then generate docs/index.html.
   - English by default, with a German toggle.
   - Two text boxes (headers; optional body), a "Check" button, a traffic-light verdict, and the list of signals with explanations.
   - A "How do I get the headers?" panel for Outlook desktop, Outlook web, Gmail and Apple Mail.
   - A "Load example" button with one synthetic phishing email.
   - A setting for the hotel's own name and domain. Store it only in localStorage, wrapped in try/catch.
   - Must work at mobile width.
3. **Docs.**
   - README.md: what the tool does and doesn't do, privacy, scoring, and limits ("signals only, not a security product").
   - LEARN.md for Aco, in simple English, one paragraph each on:
     - SPF, DKIM and DMARC
     - lookalike domains
     - why hotels are targeted
   - Also in LEARN.md: 8 questions an email-security SDR gets in interviews, with short answers.

## Domain Email Check (docs/domain.html)
- **Only network calls allowed:** public DNS-over-HTTPS JSON, https://cloudflare-dns.com/dns-query first, fallback https://dns.google/resolve. CSP connect-src lists exactly these two. Only the domain name is sent (no cookies, no referrer).
- **Nothing is stored** (no localStorage, no cookies), no analytics. The UI says so.
- Queries: MX, SPF (TXT), DMARC (_dmarc TXT), DKIM only at selectors selector1, selector2, google, k1, default, labelled "found at a common selector" / "not found at common selectors (may still exist)".
- **Never "safe".** Verdicts: "Strong / Partial / Weak protection against spoofing", each with reasons. Rules in evaluate() in src/dnscheck.js and in the README. DKIM never changes the verdict.
- Plain English with a German toggle: what each record means, what it means for spoofing risk (DMARC missing or p=none = anyone can send mail that looks like yours), and a "what to do next" list.
- Tests: tests/dns.js with recorded-format DNS answers in tests/dns/*.json and a fake fetch. No live network in tests. Synthetic .test / example.com domains only.

## Tests
- node tests/run.js (Phishing Check: 14 emails + unit checks), node tests/dns.js (Domain Email Check), node build.js. All must pass before committing.
