# Phishing Check — spot fake emails before you click

Two small, self-contained web pages for people who handle email at work (front office, reservations, accounts, admin):

| Page | File | What it answers |
|---|---|---|
| **Phishing Check** | `docs/index.html` | "Is this email I received suspicious?" Paste the headers (and optionally the text) and see the warning signs in plain English or German. |
| **Domain Email Check** | `docs/domain.html` | "How easy is it to send fake emails in this company's name?" Type a domain and see its SPF, DKIM, DMARC and MX records explained. |

The two pages link to each other. Both work when hosted on GitHub Pages or opened from disk.

Example sets: hotels get a lot of fake Booking.com and OTA emails ("verify the guest's card", "your listing will be suspended", "a guest complaint with photos", "press Win+R"). Offices everywhere get fake Microsoft 365 login pages and fake supplier invoices with "new bank details". The page has a "Load example" choice for each of these three, all synthetic.

# Phishing Check

## What it checks

It runs seven groups of checks on what you paste:

| # | Check | What it looks at |
|---|-------|------------------|
| 1 | Authentication | SPF, DKIM and DMARC results from `Authentication-Results`, `Received-SPF` and `ARC-Authentication-Results` |
| 2 | Sender mismatch | From vs Reply-To vs Return-Path domains, plus a fake address hidden in the display name |
| 3 | Brand impersonation | The sender name or subject names Booking.com, Expedia, Airbnb, Agoda, Hotels.com, Trip.com, HRS, Microsoft 365 or your own organisation, but the From domain is not an official one |
| 4 | Lookalike domains | Typos (edit distance), swapped characters (0/o, 1/l, rn/m), extra words (`booking-com-secure`), a different ending (`booking.test`), punycode (`xn--`) |
| 5 | Links | Raw IP addresses, URL shorteners, punycode, link text showing a different domain, links to unrelated domains |
| 6 | Content | English and German keywords for card or payment requests, account suspension, a guest complaint with a link, cancellation threats, "ClickFix" instructions, login/password-expiry bait, changed bank details, risky attachments (.html, .htm, .zip, .iso, .img, .lnk, .js, .exe, .scr) and password-protected archives |
| 7 | Received chain | Shows the first external server (host and IP), for information only |

Each signal gives a one-sentence explanation in English and German, the points it adds, and the evidence it found.

## What it does not do

- It never says an email is "safe". The only verdicts are **Many warning signs**, **Some warning signs** and **No warning signs found — this does not mean the email is safe**.
- It does not open links, download attachments, look up DNS or check reputation lists. It only reads the text you paste.
- It does not replace your mail filter, your IT team or common sense.

## Privacy

- Everything runs in your browser. The page makes no network calls and loads no external fonts, CDNs or analytics. A Content-Security-Policy (`default-src 'none'`) blocks any request, even by accident.
- Pasted content is not stored. The only thing saved is your organisation name and domain from Settings, kept in this browser's `localStorage`. If storage is blocked (for example in private mode), the setting works until you close the page.
- The repository contains no real guest emails or personal data. All test emails are synthetic and use `example.com` or `.test` domains, documentation IP ranges and invented names.

## Scoring

Every signal adds a fixed number of points. The total decides the verdict:

| Total points | Verdict |
|---|---|
| 8 or more | Many warning signs |
| 3 to 7 | Some warning signs |
| 0 to 2 | No warning signs found — this does not mean the email is safe |

| Signal | Points |
|---|---|
| ClickFix instructions (Win+R, paste a command) | 5 |
| Brand named in the sender name, from a non-official domain | 5 |
| Lookalike domain: typo or swapped characters | 5 |
| DMARC fail | 4 |
| Lookalike domain: extra words or a different ending; punycode sender | 4 |
| Link to a raw IP, a punycode domain, or link text showing another domain | 4 |
| Risky attachment type; changed bank details | 4 |
| SPF fail | 3 |
| Reply-To on another domain; fake address in the display name | 3 |
| Card or payment request; account suspension threat; guest complaint with a link; login or password request | 3 |
| Password-protected archive | 3 |
| SPF softfail; DKIM fail; no authentication results at all; no From address | 2 |
| Brand named only in the subject; URL shortener; cancellation threat | 2 |
| SPF, DKIM or DMARC with no result, or missing | 1 |
| Return-Path on another domain; links to unrelated domains | 1 |
| First external server | 0 (information only) |

The exact values live in `POINTS` and `THRESHOLDS` in `src/analyzer.js`.

Some choices are deliberate:

- **Passing SPF/DKIM/DMARC adds nothing.** It only proves the email came from the domain it shows. Attackers send from free-mail accounts and from their own lookalike domains that pass all three checks. Test emails `p02`, `p04`, `p05` and `p08` show this.
- **A brand in the subject scores low.** Guests often write "About my Booking.com reservation" from their own address.
- **Edit distance scales with length.** A distance of 2 or less counts for names of 7 or more letters, 1 for names of 5–6 letters, and short names like "hrs" only match exactly or by swapped characters. This avoids flagging words like "pagoda" or "motels".
- **Only the topmost Authentication-Results header is used**, because it is added by your own mail server. Lower ones can be forged by the sender.

### Editing the brand list

All official brands and domains are in the single `OFFICIAL_BRANDS` array at the top of `src/analyzer.js`. Add or change entries there, then rebuild. OTAs sometimes send from extra domains. If a real OTA email gets flagged, check the domain with the OTA and add it to the list.

## Limits

**Signals only, not a security product.**

- It only sees what you paste. If you paste only part of the headers, it can miss things or report "result missing".
- If you paste the rendered email text instead of the source, the real link addresses are lost, so link checks see only visible URLs. For the best result, paste the full source (Gmail "Show original", Apple Mail "Raw Source").
- The keyword lists cover English and German only and match whole phrases. Rewording can get past them.
- The brand list is short and has to be maintained by hand. Legitimate senders that use third-party mailing services can show low-point signals such as a different Return-Path or links to tracking domains.
- Lookalike detection compares against the listed brands and your own domain only.
- The registrable-domain logic uses a small built-in list of two-part endings (such as `co.uk` and `co.ae`), not the full Public Suffix List.
- A clean result is not proof that an email is safe. When in doubt, contact the OTA or sender through a channel you already trust.

# Domain Email Check

Type a domain (or an email address or URL; the page keeps only the domain). The page asks public DNS for:

| Record | DNS name | Shown as |
|---|---|---|
| MX | `domain` | Who receives mail for the domain (information only) |
| SPF | `domain` TXT starting `v=spf1` | Which servers may send; how it ends (`-all`, `~all`, `?all`, `+all`), several records, more than 10 lookups |
| DMARC | `_dmarc.domain` TXT | Policy `none` / `quarantine` / `reject`, `pct`, `sp`, report address `rua` |
| DKIM | `selector1`, `selector2`, `google`, `k1`, `default` `._domainkey.domain` | "found at a common selector" or "not found at common selectors (may still exist)" |

Each finding has a one-sentence explanation (EN/DE), plus a short "what to do next" list.

## Verdict

It never says "safe". The verdict is about spoofing only (someone sending mail with this exact domain in the From address):

| Verdict | Rule |
|---|---|
| **Strong protection against spoofing** | DMARC `p=reject` or `p=quarantine` at `pct=100`, and one valid SPF record ending in `-all` or `~all` (or a `redirect`) |
| **Partial protection against spoofing** | DMARC is enforced, but something weakens it: SPF missing, several SPF records, `+all`/`?all`, more than 10 SPF lookups, `pct` below 100, or `sp=none` |
| **Weak protection against spoofing** | No DMARC, an invalid DMARC record, or `p=none`: anyone can send mail that looks like it comes from this domain |

DKIM never changes the verdict, because the page can only guess selector names. The rules live in `evaluate()` in `src/dnscheck.js`.

## Privacy

- Only the domain name is sent, as DNS questions, to `https://cloudflare-dns.com/dns-query` (JSON); if that fails, to `https://dns.google/resolve`. Requests omit cookies and the referrer.
- The Content-Security-Policy allows network requests to those two resolvers only (`connect-src`). `build.js` fails if any other `connect-src` or external resource appears.
- Nothing is stored (no `localStorage`, no cookies) and there are no analytics. The resolver operators can see which domain was asked about and your IP address, as with any DNS lookup.

## Limits

- Strong records do not stop **lookalike** domains (`examp1e.com`); staff still need to check senders.
- DKIM is checked only at five common selectors. Many providers use other names.
- The verdict reflects public DNS at the moment of the check, as seen by the resolver. It does not check mail servers, TLS, MTA-STS, BIMI or blocklists, and does not follow SPF `include`s to count nested lookups exactly.
- **Signals only, not a security product.**

# Project layout

```
src/analyzer.js        Phishing Check: all checks; works in Node and the browser
src/ui.html            Phishing Check page: layout, texts (EN/DE), UI logic
src/dnscheck.js        Domain Email Check: DNS parsing, scoring, DoH lookups; Node and browser
src/domain.html        Domain Email Check page
build.js               builds docs/index.html and docs/domain.html (self-contained)
tests/emails/*.eml     14 synthetic emails: 10 phishing (p01–p10), 4 legitimate (l01–l04)
tests/expected.json    expected verdict and key signals per email
tests/run.js           runs the emails plus unit checks
tests/dns/*.json       recorded-format DNS answers for synthetic .test/example.com domains
tests/dns.js           parsing and scoring tests with a fake fetch (no live network)
```

Commands (Node.js only, no npm packages):

```bash
node tests/run.js -v
```

```bash
node tests/dns.js -v
```

```bash
node build.js
```

