# Legacy School Workspace

Cloudflare-native school-operations application with a static workspace interface and a protected Worker API. It covers the foundation for teacher onboarding, people and group management, half-month payroll cycles, capped administrative time, school calendar operations and service integrations.

## What is implemented

- D1 data model with referential integrity for people, teachers, students, group enrolments, attendance, onboarding, time, payment periods, calendar events, integration state and immutable audit logs. Payment account numbers and guardian contact objects are encrypted with AES-GCM before storage.
- Passwordless, one-time magic-link authentication via Resend. Links are hashed in D1, expire after 15 minutes and create an HTTP-only, SameSite session cookie.
- Role checks for `admin`, `academics`, `finance`, `lss`, and `teacher`; public and protected API boundaries are tested.
- Teacher creation, admin-time submission with an enforced eight-hour monthly cap, calendar event creation, dashboard statistics, Google OAuth, school-calendar configuration, and Google Calendar event/Meet synchronization.
- Onboarding-pathway seeding and progress updates, logged Resend reminders (limited to one reminder per item per 24 hours), many-to-many teacher/group assignments, finance-controlled payment-cycle transitions, time-entry approval actions, and encrypted Google Form response import queues.
- The supplied 2026–27 academic calendar is seeded as queryable, inclusive date ranges. School closures are kept distinct from live-class events, so calendar synchronization can make an explicit decision about cancellations.
- A structured incident trail replaces informal no-show, urgent absence, class-link and placement escalation messages. It routes staff reports to LSS/operations without automatically messaging families or incorrectly marking unenrolled learners absent.
- Cloudflare Pages/Workers asset deployment configuration with no credentials or payment details in source control.

The supplied legacy materials informed the default workflow: interview, theory and practice tasks, document verification, agreements, technical setup, induction and probation. Technical readiness includes a corporate Google account, separate Chrome profile, vault-managed access, Buzz, the Meet extension, recording, a personal feedback link, attendance and class readiness. Google Meet is launched from an authorized event URL instead of an iframe, which Google commonly blocks for security and account-isolation reasons.

## Local development

1. Install dependencies: `npm install`
2. Copy `.dev.vars.example` to `.dev.vars` and replace its placeholder values.
3. Create a local D1 database and apply every migration in order: `npm run db:migrate:local`
4. Start the Worker: `npm run dev`
5. Run the automated route checks: `npm test`

## Cloudflare deployment

1. Create a D1 database named `legacy-school`; replace the placeholder `database_id` in `wrangler.toml` with its ID.
2. Authenticate Wrangler to the intended Cloudflare account, then run `npm run db:migrate:remote`.
3. Set these Worker secrets in Cloudflare: `AUTH_SECRET`, `DATA_ENCRYPTION_KEY`, `RESEND_API_KEY`, `GOOGLE_CLIENT_SECRET`. `DATA_ENCRYPTION_KEY` must be a base64url-encoded, random 32-byte AES-GCM key.
4. Set these Worker variables: `APP_ORIGIN`, `BOOTSTRAP_ADMIN_EMAIL`, `RESEND_FROM`, `GOOGLE_CLIENT_ID`, `GOOGLE_REDIRECT_URI`, and `GOOGLE_OAUTH_ALLOWED_EMAIL`.
5. Deploy with `npm run deploy`, then attach the intended Cloudflare domain or subdomain.

## GitHub delivery pipeline

The repository includes two intentionally separate GitHub Actions workflows:

- `Validate workspace` runs tests and validates a Worker bundle on every pull request and push to `main`. It has no production credentials.
- `Deploy workspace` is manual-only and requires typing `DEPLOY`. It applies D1 migrations before deploying the Worker, using a protected GitHub `production` environment.

Before enabling the deployment workflow, set these GitHub values:

| GitHub value | Type | Purpose |
| --- | --- | --- |
| `CLOUDFLARE_API_TOKEN` | Actions secret | Scoped Cloudflare token that can deploy this Worker and migrate its D1 database. |
| `CLOUDFLARE_ACCOUNT_ID` | Actions variable | The intended Cloudflare account ID. |
| `CLOUDFLARE_D1_DATABASE_ID` | Actions variable | The D1 database ID created for this workspace. |

Configure application secrets (`AUTH_SECRET`, `DATA_ENCRYPTION_KEY`, `RESEND_API_KEY`, and `GOOGLE_CLIENT_SECRET`) directly in Cloudflare before the first deploy. Do not place them in GitHub Actions secrets simply to echo them into a deployment; Cloudflare Workers secrets should remain in Cloudflare.

## Security scanner

The production-aware scanner is documented in [SECURITY-OPERATIONS.md](SECURITY-OPERATIONS.md). It writes redacted reports under `.security-reports/` and fails the CI gate for High/Critical findings. It is automated evidence, not a penetration test or compliance certification.

## API workflow map

All routes except `GET /api/health`, `POST /api/auth/request-link`, and the magic-link callback require a signed-in user.

| Workflow | Route | Allowed roles |
| --- | --- | --- |
| Create a teacher | `POST /api/teachers` | admin, academics, lss |
| Start onboarding | `POST /api/teachers/:teacherId/onboarding` | admin, academics, lss |
| Update onboarding item | `PATCH /api/onboarding/:itemId` | owner teacher or operational roles |
| Send an onboarding reminder | `POST /api/onboarding/:itemId/remind` | admin, academics, lss; logged and rate-limited |
| Create/assign class group | `POST /api/groups`, `PUT /api/teachers/:teacherId/groups/:groupId` | admin, academics, lss |
| Manage a learner | `GET/POST /api/students`, `GET /api/students/:studentId`, `PUT /api/students/:studentId/enrollments/:groupId` | admin, academics, lss; teachers see only learners in their assigned groups |
| Read a roster / mark attendance | `GET /api/groups/:groupId/roster`, `POST /api/attendance` | assigned teacher or operations; only enrolled/trial learners can be marked |
| Submit / approve admin time | `POST /api/time-entries`, `PATCH /api/time-entries/:entryId` | teacher for own record; operational roles; finance can approve |
| Create / advance a payment cycle | `POST /api/pay-cycles`, `PATCH /api/pay-cycles/:cycleId` | admin, finance, academics |
| View the seeded academic calendar | `GET /api/academic-dates?from=YYYY-MM-DD&to=YYYY-MM-DD` | signed-in school users |
| Report / resolve an operational incident | `POST /api/incidents`, `GET /api/incidents`, `PATCH /api/incidents/:incidentId` | all school roles can report; admin, academics, LSS resolve |
| Set / view payment details | `PUT /api/teachers/:teacherId/payment-details`, `GET /api/teachers/:teacherId/payment-details` | own teacher record to set or view masked details; admin/finance can reveal with `?reveal=1` |
| Create calendar event | `POST /api/calendar/events` | admin, academics, lss |
| Set Google Calendar / sync one event | `PUT /api/integrations/google/calendar`, `POST /api/calendar/events/:eventId/sync` | admin for configuration; admin, academics, lss for sync |
| Map / import legacy Google Forms | `POST /api/forms`, `POST /api/forms/:mappingId/sync` | admin, academics, finance, lss |

## Operational policy choices confirmed from the added sources

- Admin time accepts only non-live work: grading, due dates, student/family communication, approved administration and approved classwork. The eight-hour monthly cap remains enforced.
- Group no-show reports require 20 minutes waited; one-to-one reports require 15. A report is not an automatic absence or parent-contact action. LSS can document escalation and resolution in the same record.
- The source calendar is the 2026–27 planning baseline; it supersedes older chat announcements when the dates differ.
- The supplied teacher announcement says the second half payment report is due on the 3rd of the following month, while the project brief says two days after the period. The application defaults to the brief (`two_calendar_days`). Set Worker variable `PAYMENT_DEADLINE_POLICY=legacy_announcement` only if the school confirms the legacy 17th/3rd rule.

## Required production follow-up

Payment account numbers and guardian contacts are already encrypted with `DATA_ENCRYPTION_KEY`; keep the key only in Cloudflare and complete a security review before collecting real records. The Google OAuth callback encrypts its refresh token in D1. For a personal-account pilot, create a dedicated school-owned Google account and set `GOOGLE_OAUTH_ALLOWED_EMAIL` to that address, so an administrator cannot accidentally connect an individual account. Calendar, Forms and Drive API access must still be enabled in the Google Cloud project after the school selects its exact source calendars and forms. Never add a Resend key, password-vault password, school password, raw payment account number or student data to GitHub.
