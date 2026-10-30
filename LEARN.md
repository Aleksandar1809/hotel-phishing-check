# Learn: email security basics for hotel people

Short notes in plain English. They explain the ideas behind Hotel Phishing Check and help you prepare for email-security sales interviews.

## SPF, DKIM and DMARC

Think of an email like a parcel arriving at the hotel's loading dock. **SPF** is the sender's published list of couriers allowed to deliver for them. The receiving server checks whether the server that delivered the email is on the list for the domain in the hidden envelope address (the Return-Path). **DKIM** is a tamper-proof seal: the sending domain signs the email with a private key, and the receiver checks the signature with a public key published in DNS. If the content was changed or the seal is fake, DKIM fails. **DMARC** ties both to the address the reader actually sees in the From line. It passes only if SPF or DKIM passes *for that same domain*, and it lets the domain owner say what to do with failures: `p=none` (just report), `p=quarantine` (send to spam) or `p=reject` (block). The key point for sales: SPF, DKIM and DMARC prove *who sent* an email, not whether the sender is honest. A criminal who registers `booking-partnerhub.example` can pass all three.

## Lookalike domains

A lookalike domain is built to fool a busy person at a glance. Common tricks:
- **Typos:** `bookng`, `expeida`
- **Swapped characters:** `b00king` with zeros, `rn` that looks like `m`, `1` that looks like `l`
- **Extra words around the real name:** `booking-com-secure`, `booking.reservation-help`
- **The real name with a different ending:** `booking.support`
- **Punycode:** letters from other alphabets, such as a Cyrillic "о" that looks exactly like a Latin "o". Browsers and tools show these domains as `xn--…`.

Because the attacker owns the lookalike domain, they can set up perfect SPF, DKIM and DMARC for it. That is why lookalike detection matters even when authentication passes. Companies defend against this by registering common variants themselves, watching new domain registrations, and teaching staff to check the domain and not the display name.

## Why hotels are targeted

Hotels are an ideal target. Reservations and front-office teams *must* open emails from strangers all day: guests, OTAs, travel agents, suppliers. They often work under time pressure and in several languages, on shared PCs that are logged into the PMS, the OTA extranets and payment terminals. OTA extranet logins are especially valuable. With one stolen Booking.com login, criminals can message real guests through the official platform and ask them to "re-confirm" their card. To the guest, the scam looks completely legitimate. Hotels also hold card data and passport details, staff turnover is high, so training gets lost, and many independent hotels have no dedicated IT security person. Typical lures include fake guest complaints with "photos", urgent card-verification requests, threats to cancel a reservation, and the newer "ClickFix" trick that asks staff to press Win+R and paste a command.

## 8 interview questions for an email-security SDR (with short answers)

**1. In one sentence, what is the difference between SPF, DKIM and DMARC?**
SPF lists which servers may send for a domain. DKIM signs the message so changes and forgeries show up. DMARC requires one of them to match the visible From domain and tells receivers what to do with failures.

**2. A prospect says "we have SPF and DKIM, so we are protected." What do you say?**
Without DMARC at `quarantine` or `reject`, anyone can still put your exact domain in the From line, and many receivers will deliver it. And even full DMARC does not stop lookalike domains or attacks from compromised partner accounts, so you also need inbound protection and user awareness.

**3. What is BEC (business email compromise), and why is it hard to catch?**
BEC is fraud where an attacker pretends to be a manager, supplier or partner to get money or data, often with no link or attachment at all, just a convincing request. Filters that look for malware miss it, so detecting it relies on behaviour, relationships and language analysis.

**4. Why would a hotel group buy email security if it already has Microsoft 365?**
Built-in filtering catches a lot of bulk spam and known malware, but targeted lures, lookalike domains and compromised-vendor emails often get through. Extra layers add impersonation detection, link rewriting and post-delivery removal, and they cut the time staff spend on suspicious emails.

**5. How would you open a cold call with a hotel IT manager?**
Start from a specific, relevant pain: "Many hotels in your region are seeing fake Booking.com emails that lead to extranet takeovers. How is your front office handling those today?" Then listen, and qualify impact, current tools and who owns the problem.

**6. What metrics matter to an email-security buyer?**
Malicious emails reaching inboxes, time to detect and remove them, staff time spent on reported emails, the share of their own domains at DMARC enforcement, and avoided incidents such as fraud losses or account takeovers.

**7. What is DMARC "p=none" and why do so many domains stay there?**
`p=none` only collects reports and does not block anything. Organisations stay there because they fear blocking legitimate mail from forgotten services such as their PMS, booking engine or newsletter tool. Helping them find and fix those senders so they can move to enforcement is a common sales and services opportunity.

**8. A prospect says "our staff are trained, we don't need a tool." How do you respond?**
Training is essential, and tools work best alongside it. But even trained people misread one email out of hundreds on a busy shift, and attackers only need one success. A tool reduces how many dangerous emails ever reach staff, and gives them a quick second opinion when one does.
