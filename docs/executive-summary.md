# Executive Summary - VulnTracker Security Review

**For:** CISO  **Read time:** 5 minutes

## The short version

VulnTracker holds the most sensitive thing a security team owns: a list of the weaknesses in its own systems that have not yet been fixed. Before this review, **anyone on the internet could have walked in as any user and read everyone's list**, and the secrets that protect the system were published in the code. Those doors are now closed. The application is in a much safer state, but it is **not yet ready for production**: one urgent clean-up task is still open, and a companion service has serious gaps that must be fixed before it is ever switched on alongside the main application.

## Where we started

The application is an internal prototype that nobody had reviewed. We found:

- **Anyone could pretend to be anyone.** The login check could be tricked with a forged pass, no password needed. *(Critical)*
- **The keys to the building were left in the source code** (and the code is public). Even with the first problem fixed, they would let an outsider make valid passes. *(Critical)*
- **Any customer could read any other customer's findings**, either by counting up record numbers or through a search box that could be tricked into handing over the user database. *(High)*
- **Passwords were written in plain text to the system's activity log** every time someone logged in. *(High)*
- Out-of-date software parts with **67 publicly known weaknesses**, plus several smaller leaks of internal detail. *(High to Medium)*

Only a handful of these were caught by automated scanning tools. Most were found by reading the code and asking "what would an attacker do here?" That is the reason the review matters: running a scanner alone would have left the most serious problems in place.

## Where we are now

| | Before | After |
|---|---|---|
| Forged logins possible | Yes | **No** |
| One customer can read another's data | Yes | **No** |
| Passwords in logs | Yes | **No** |
| Secrets in the code | Yes | **Removed** (the application will not start without them) |
| Known weaknesses in the main application's software | 67 | **0** |
| Automated tests protecting these fixes | 10 | **45** (16 written to prove each fix, 14 of which failed on the old code) |

We also built the new **"share a report with an outsider"** feature to a security standard from the start: links are random and unguessable, expire after 24 hours, can be password-protected, lock after repeated wrong guesses, and are removed if the report is deleted. Reviewing our own work found two weaker spots (a guess-limit that could be rushed, and passwords visible in web addresses); both were improved.

We also packaged the application so it can be deployed safely: it runs without administrator rights, keeps its secret in a secure vault instead of in a settings file, accepts traffic only from the front door and talks to almost nothing else, and has fixed limits on the resources it can use. Every code change now triggers automatic security checks.

## The three risks that remain, and why

1. **The old secrets must be replaced - this is urgent and not done.** The previous keys and passwords are still visible in the project's history, so they must be treated as stolen. Replacing them has to happen in the live systems that hold them, which is outside what could be done in the code. *Effort: about half a day. Until this is done, the improvements above can be undone by anyone who copied the old keys.*
2. **The companion notification service is wide open.** It has no login, it will contact any web address it is told to (including internal systems), and it hands its own secret to whoever asks. It was explicitly out of scope for changes, and it is not part of the new deployment. It is acceptable only as long as it stays unreachable from outside. *Effort: two to three days to make it safe.* **It must not be exposed or deployed until then.**
3. **Account protection is basic.** Nothing slows someone guessing passwords, weak passwords are allowed, and an account marked "disabled" still works. *Effort: one to two days. Interim step: switch on rate limiting at the front door, which needs no code.*

A fourth item is worth knowing about: the data is kept in a single file on one machine, with no automatic backups. Fine for a prototype, not for production.

## What we recommend next

1. **This week:** replace every secret that was ever in the code (risk 1); turn on request-rate limits at the front door.
2. **Before any production use:** fix the notification service (risk 2) and the account protections (risk 3); move the data to a managed, encrypted, backed-up database.
3. **Before the first customer:** independent penetration test of the main application and the share-link feature; add a record of who created and who opened each shared link.
4. **Ongoing:** keep the automatic checks on, review the weekly dependency-update proposals, and re-run this review whenever a major feature is added.
