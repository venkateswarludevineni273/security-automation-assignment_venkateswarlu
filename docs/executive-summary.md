# Executive Summary - VulnTracker Security Review

**For:** CISO  **Read time:** 5 minutes

## The short version

VulnTracker holds the most sensitive thing a security team owns: a list of the weaknesses in its own systems that have not yet been fixed. Before this review, **anyone who could reach the service could have walked in as any user and read everyone's list**, and the secrets that protect the system were published in the code. Those doors are now closed, and the companion service that sends alerts has been locked down as well. The application is in a much safer state, but it is **not yet ready for production**: one urgent clean-up task is still open, and the data is kept in a way that is only suitable for a prototype.

## Where we started

The application is an internal prototype that nobody had reviewed. We found:

- **Anyone could pretend to be anyone.** The login check could be tricked with a forged pass, no password needed. *(Critical)*
- **The keys to the building were left in the source code** (and the code is public). Even with the first problem fixed, they would let an outsider make valid passes. *(Critical)*
- **Any customer could read any other customer's findings**, either by counting up record numbers or through a search box that could be tricked into handing over the user database. *(High)*
- **Passwords were written in plain text to the system's activity log** every time someone logged in. *(High)*
- **The alert-sending service had no lock on its door.** Anyone who could reach it could make it call any address it was told to, including internal systems, and it handed its own secret to whoever asked. *(High)*
- Out-of-date software parts with **78 publicly known weaknesses** across the two services, plus several smaller leaks of internal detail. *(High to Medium)*

Only a handful of these were caught by automated scanning tools: 4 of the 16 problems we recorded in the original code. Most were found by reading the code and asking "what would an attacker do here?" That is the reason the review matters: running a scanner alone would have left the most serious problems in place.

## Where we are now

| | Before | After |
|---|---|---|
| Forged logins possible | Yes | **No** |
| One customer can read another's data | Yes | **No** |
| Passwords in logs | Yes | **No** |
| Secrets in the code | Yes | **Removed** (the services will not start without them) |
| Alert service open to anyone who can reach it | Yes | **No** (every request needs a key; internal addresses are refused) |
| Known weaknesses in the software the services use | 78 | **0** |
| Switched-off accounts still work | Yes | **No** (blocked at once) |
| Automated tests protecting these fixes | 18 | **86** |

We also built the new **"share a report with an outsider"** feature to a security standard from the start: links are random and unguessable, expire after 24 hours, can be password-protected, lock after repeated wrong guesses, show only a frozen copy of the report taken when the link was made, can be listed and cancelled by the owner, and are removed if the report is deleted. Every creation, use and failure is recorded without ever writing the secret link or password into the log. Reviewing our own work found flaws in it, which we fixed rather than hid.

We also packaged the application so it can be deployed safely: it runs without administrator rights, keeps its secret in a secure vault instead of in a settings file, accepts traffic only from the front door and talks to almost nothing else, has fixed limits on the resources it can use, and its front-door settings include a limit on how fast anyone can send requests. Every code change is checked automatically for known weaknesses before it is accepted, and the checks currently all pass.

## The three risks that remain, and why

1. **The old secrets must be replaced - this is urgent and not done.** The previous keys and passwords, including the alert service's old key, are still visible in the project's history, so they must be treated as stolen. Replacing them has to happen in the live systems that hold them, which is outside what could be done in the code. *Effort: a few hours. Until it is done, the old signing key is the single largest remaining risk.*
2. **The data lives in one file on one machine.** There are no automatic backups, the application does not encrypt it, and it cannot run as more than one copy. A machine failure would lose the data. *Why not fixed: this is a redesign (moving to a managed database), not a patch. Effort: three to five days. Interim step: keep the storage volume encrypted and back it up.*
3. **Nobody has run this in a live environment yet.** The code, the container and the deployment files all pass their automatic checks, but the deployment files have not been installed on a real cluster, so the protections they describe (the vault, the network limits, the request-rate limit) are untested in practice. Password-guessing protection also depends on that front-door limit, because per-account lockout was deliberately not built: done carelessly, it lets an attacker lock real users out. *Effort: half a day to test; one to two days for account lockout.*

Two smaller items are worth knowing about. Two serious-rated weaknesses in the base operating system of the container have no fix available yet from its maintainers; they sit in parts the application does not use, and the build will start failing the day a fix is published. The alert service still keeps its list of destinations in memory only and shares a single key between callers; that is acceptable while it is not deployed alongside the main application.

## What we recommend next

1. **This week:** replace every secret that was ever in the code (risk 1); install the deployment in a test environment and confirm each protection works (risk 3).
2. **Before any production use:** move the data to a managed, encrypted, backed-up database (risk 2); add account lockout with a cooldown; give the alert service its own network limits and per-caller keys before it is deployed.
3. **Before the first customer:** an independent penetration test of the main application and the share-link feature; send the activity records to a tamper-resistant store.
4. **Ongoing:** keep the automatic checks on, review the weekly update proposals, and re-run this review whenever a major feature is added.
