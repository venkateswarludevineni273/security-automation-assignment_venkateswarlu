# Secret Rotation Runbook

**Why this exists.** The original starter code committed four secrets to a public repository. Removing them from the latest commit does not help, because they remain in git history. They must be treated as stolen and replaced. This is risk **R1** in `remediation-plan.md` and the single largest open risk. Rotation happens in the systems that hold the secrets, so it cannot be done by a code change; this runbook is what the person who controls those systems follows.

**Time:** 2-4 hours. **Who:** whoever administers the secrets manager and the cluster.

## What to replace

| Burned value | Where it was | Replace with | Used by the current code? |
|---|---|---|---|
| JWT signing key | `app/config.py` (old versions) | New random value in the secrets manager at `vulntracker/prod/jwt-signing-key` | Yes: the API refuses to start without one |
| Notify service key | `notify/src/config.js` (old versions) | New bearer token at `vulntracker/prod/notify-api-token`, plus a separate `NOTIFY_SIGNING_SECRET` | Yes, when the notify service is deployed |
| Database password | `app/config.py` (old versions) | New password, if any real database ever used the old one | No (SQLite file, no password) |
| Admin API key | `app/config.py` (old versions) | Revoke and re-issue in any system that accepted it | No |

To see exactly which values were exposed: `git log -p -S"<first characters>" -- app/config.py notify/src/config.js`.

## Steps

1. **Generate new values.** Never reuse an old value or derive one from it.
   ```bash
   openssl rand -hex 32   # signing key
   openssl rand -hex 32   # notify bearer token
   openssl rand -hex 32   # notify signing secret
   ```
2. **Store them in the secrets manager** at the paths in `helm/vulntracker/values.yaml` (`secrets.signingKey.remoteKey`, `notify.tokenRemoteKey`). Do not paste them into chat, tickets, shell history or a file in the repository.
3. **Sync and restart.** The chart mounts the values as files, and the app reads them at startup, so pods must restart:
   ```bash
   kubectl -n <namespace> annotate externalsecret <release>-signing-key force-sync=$(date +%s) --overwrite
   kubectl -n <namespace> rollout restart deployment/<release>
   kubectl -n <namespace> rollout status deployment/<release>
   ```
4. **Invalidate old sessions.** Changing the signing key does this automatically: every token signed with the old key stops verifying. Users sign in again (tokens last 30 minutes anyway).
5. **Replace the other values** (database password, admin API key) wherever the old ones were accepted, then revoke the old ones.
6. **Rotate the notify values** in the notify service's own configuration (`NOTIFY_API_TOKEN`, `NOTIFY_SIGNING_SECRET`) and in the API's `notify-token` secret together, so the two stay in step. Webhook receivers must be given the new signing secret to keep verifying payloads.

## Confirm it worked

- A token signed with the **old** signing key is rejected:
  ```bash
  OLD_KEY='<the exposed key from git history>'
  TOKEN=$(python3 -c "import jwt,time; print(jwt.encode({'sub':'alice','exp':int(time.time())+300}, '$OLD_KEY', algorithm='HS256'))")
  curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOKEN" https://<host>/scans   # expect 401
  ```
- A freshly issued login token works (expect 200 on `/scans`).
- The notify service refuses a call that carries the old bearer token (expect 401), and accepts one that carries the new token.
- The pods start healthy (`kubectl get pods`), and the application logs show no `SECRET_KEY` errors.

## After rotation

- Record the date and who did it.
- Turn on GitHub **secret scanning** and **push protection** for the repository (Settings, Code security), so a secret in a future commit is blocked before it lands.
- Rewriting git history (for example with `git filter-repo`) is optional hygiene. It does **not** make the old values safe, because anyone who cloned or forked the repository already has them. Rotation is the fix; history rewriting is not a substitute.
