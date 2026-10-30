# Hotel Phishing Check

## Goal
Build one web page that a hotel receptionist uses to check a suspicious email. The receptionist pastes the email's headers, and optionally its text, and sees the warning signs in plain language.
Hotels are heavily targeted by fake Booking.com and OTA emails.
Purpose: a portfolio piece for an email-security and tech-sales job search.

## Owner
Aca is not a developer but is very tech-literate. He is a former hotel Front Office Manager.
Talk to him in Bosnian/Serbian, in at most 2 short sentences per explanation.

## Non-negotiable rules
- **Runs 100% in the browser.** No network calls, no external fonts, CDNs or analytics. Pasted content never leaves the device, and the UI says so.
- **Never label an email "safe".** The only verdicts are:
  - "Many warning signs"
  - "Some warning signs"
  - "No warning signs found — this does not mean the email is safe"
- **Defensive only.** No real guest emails or real personal data anywhere in the repo. All test emails are synthetic, using example.com or .test domains and invented names.
- **Plain technology.** Plain HTML, CSS and vanilla JavaScript, with Node built-ins only: no frameworks, no npm packages.
  - Source lives in src/: analyzer.js works in both Node and the browser, plus ui.html.
  - build.js inlines both into one self-contained file, docs/index.html.

## Working rules (save tokens)
- Never print whole files into the conversation. Report counts and short samples only.
- Commit after each step. If something fails the same way twice, stop and explain.

## Checks
Each check produces a signal with a one-sentence explanation in English and German.

1. **Authentication.** Parse the Authentication-Results, Received-SPF and ARC headers to get the SPF, DKIM and DMARC results: pass, fail, softfail, none or missing.
2. **Sender mismatch.** Compare the domains of From, Reply-To and Return-Path.
3. **Brand impersonation.** Flag when the display name or subject names one of the brands below, but the From domain is not on the official domain list.
   - Brands: Booking.com, Expedia, Airbnb, Agoda, Hotels.com, Trip.com, HRS, or the hotel's own name (from settings).
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
   - Add 12 synthetic emails in tests/emails/:
     - 8 phishing emails in different styles: fake Booking.com payment request, fake guest complaint with a link, ClickFix, lookalike domain, and others
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
   - LEARN.md for Aca, in simple English, one paragraph each on:
     - SPF, DKIM and DMARC
     - lookalike domains
     - why hotels are targeted
   - Also in LEARN.md: 8 questions an email-security SDR gets in interviews, with short answers.
