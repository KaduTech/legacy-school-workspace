# Legacy School Workspace security operations

## Scope and responsibility

The School Owner/Super Admin owns security risk acceptance, privileged access, recipient selection, incident coordination and release approval. Academic, LSS and Finance leads own access reviews for their roles. The technical owner remediates code and deployment findings. No automated report, CI result or assistant output is a penetration test or compliance certification.

## Severity and remediation targets

| Severity | Meaning | Target |
| --- | --- | --- |
| Critical | Active exposure of credentials, unauthorized privileged access, or broad student/payment-data disclosure | Contain immediately; remediate within 24 hours |
| High | Material abuse, authentication, authorization, encryption, or external-integration weakness | Remediate before release or within 7 days with written Owner acceptance |
| Medium | Defense-in-depth or configuration weakness | Remediate within 30 days |
| Low | Hardening improvement | Plan within 90 days |

## Automated scanner

`scripts/security-scan.mjs` creates redacted reports at `.security-reports/latest.md` and `.security-reports/latest.json`. It checks production dependency advisories, Git-tracked credential patterns, Worker authentication/authorization, privileged data encryption, payment/webhook and upload surface, public write abuse controls, Google integration idempotency, and browser headers. `--live` performs only unauthenticated non-destructive HEAD checks for configured URLs.

Commands:

```powershell
npm run security:scan
npm run security:scan:live
npm run security:scan:ci
npm run security:scan:weekly
node scripts/security-scan.mjs --email-dry-run
```

The CI gate fails when an unaccepted High or Critical finding exists. Reports omit secret values and are ignored by Git. The weekly workflow runs Monday 09:00 Africa/Lagos, supports manual execution and keeps artifacts for 30 days.

## Security-report recipients

Only an Owner/Super Admin may select the report owner and active security personnel in the authenticated administration portal. The scanner retrieves those recipients from the configured HTTPS endpoint using `SECURITY_REPORT_TOKEN`; it sends one Resend message per recipient with a recipient-specific idempotency key. Do not commit recipient addresses.

Before enabling weekly email, configure these values:

| Value | Store | Purpose |
| --- | --- | --- |
| `RESEND_API_KEY` | GitHub Actions secret | Report delivery credential |
| `SECURITY_REPORT_TOKEN` | GitHub Actions secret and Cloudflare Worker secret | Scanner-to-portal recipient authorization |
| `SECURITY_REPORT_SETTINGS_URL` | GitHub Actions variable | HTTPS recipient endpoint, normally `https://legacy.kadutech.com/api/security/report-recipients` |
| `SECURITY_EMAIL_FROM` | GitHub Actions variable | Verified Resend sender |
| `SECURITY_SCAN_LIVE_URLS` | GitHub Actions variable | Optional comma-separated public URLs for HEAD checks |

Use the dry-run command before enabling real weekly email. It validates recipients without sending any message.

## Risk register and release gate

The risk register is the current scanner report plus accepted exceptions recorded by the Owner with expiry and remediation owner. Do not deploy when a High/Critical finding is open without explicit documented acceptance.

Before a production release: review the exact commit, pass tests and `npm run security:scan:ci`, verify no secrets are in source, confirm D1 backup/migration plan, check Worker and Google integration settings, and obtain explicit Owner approval. Payment account collection, Google OAuth, calendar/forms sync and custom-domain routing require production smoke tests after deployment.

## Incident response and reviews

1. Preserve evidence and record affected users, data, route and time window.
2. Contain: suspend accounts, revoke sessions/tokens, disable affected routes or tighten Cloudflare rules.
3. Rotate exposed secrets at the provider; never copy replacements into reports or tickets.
4. Determine affected student, teacher, payment or calendar data from audit logs.
5. Recover from a reviewed release and validated backup where necessary.
6. Notify the Owner and obtain privacy/legal guidance for any required communication.
7. Record root cause, remediation and verification; add a test or scanner rule.

Review roles, audit activity, report recipients and dependency findings monthly. Review Cloudflare access/WAF, Google OAuth scopes, Resend senders, secrets rotation, D1 restore and authorization boundaries quarterly. Commission an independent authenticated penetration test annually and after major architecture changes.

## Limitations

The scanner cannot verify Cloudflare dashboard settings, historical Git rewriting, actual Resend/Google permissions, D1 production contents, browser exploit chains, staff behavior, external provider webhooks, legal compliance, or penetration-test coverage. These require human and production-environment review.
