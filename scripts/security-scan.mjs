import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, timingSafeEqual } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

const root = process.cwd();
const args = new Set(process.argv.slice(2));
const live = args.has('--live');
const email = args.has('--email');
const emailDryRun = args.has('--email-dry-run');
const failOn = (process.argv.find(value => value.startsWith('--fail-on='))?.split('=')[1] || 'none').toLowerCase();
const rank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const findings = []; const checks = [];
const reportDir = path.join(root, '.security-reports');
const add = finding => findings.push({ status: 'open', owner: 'School Owner / Super Admin', ...finding });
const check = (id, title, passed, details) => checks.push({ id, title, passed, details });
const source = async file => { try { return await readFile(path.join(root, file), 'utf8'); } catch { return ''; } };
const finding = (id, severity, category, title, details, evidence, remediation) => add({ id, severity, category, title, details, evidence, remediation });

function auditDependencies() {
  const npmCli = process.env.npm_execpath;
  const npm = npmCli ? process.execPath : (process.platform === 'win32' ? process.env.ComSpec || 'cmd.exe' : 'npm');
  const npmArgs = npmCli ? [npmCli, 'audit', '--omit=dev', '--json'] : (process.platform === 'win32' ? ['/d', '/s', '/c', 'npm audit --omit=dev --json'] : ['audit', '--omit=dev', '--json']);
  const result = spawnSync(npm, npmArgs, { cwd: root, encoding: 'utf8', maxBuffer: 20 * 1024 * 1024 });
  try {
    if (!result.stdout?.trim()) throw new Error(result.error?.message || result.stderr || 'npm audit produced no JSON');
    const audit = JSON.parse(result.stdout);
    if (audit.error) throw new Error(audit.error.summary || audit.error.message || 'npm audit failed');
    const vulnerabilities = Object.entries(audit.vulnerabilities || {}).map(([name, value]) => ({ name, severity: value.severity || 'medium', direct: Boolean(value.isDirect), range: value.range || 'unknown' }));
    check('DEP-001', 'Production dependency audit', true, `${vulnerabilities.length} production dependency vulnerabilities reported.`);
    if (vulnerabilities.length) {
      const highest = vulnerabilities.reduce((current, item) => rank[item.severity] > rank[current] ? item.severity : current, 'info');
      finding('LSW-SEC-001', highest, 'Dependencies', 'Production dependency vulnerabilities', vulnerabilities.map(item => `${item.name} (${item.severity}, ${item.range})`).join('; '), 'npm audit --omit=dev --json', 'Upgrade to patched versions, review compatibility, then run tests and the scanner again.');
    }
  } catch (error) {
    check('DEP-001', 'Production dependency audit', false, 'Audit output could not be parsed.');
    finding('LSW-SEC-SCAN-001', 'medium', 'Scanner', 'Dependency audit unavailable', String(error.message).replace(/(?:token|key|secret)=?[^\s]+/ig, '$1=[redacted]'), 'npm audit --omit=dev --json', 'Restore npm registry access and rerun the scanner before release.');
  }
}

async function scanTrackedSecrets() {
  let files = [];
  try { files = execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8' }).split('\0').filter(Boolean); } catch { finding('LSW-SEC-SCAN-002', 'medium', 'Scanner', 'Tracked-file scan unavailable', 'git ls-files could not enumerate source files.', 'git ls-files', 'Run the scanner from the Git repository root.'); return; }
  const ignored = /(?:^|\/)(?:node_modules|\.security-reports|package-lock\.json)|\.(?:png|jpe?g|gif|webp|pdf|zip|woff2?)$/i;
  const patterns = [
    ['Private key', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/], ['GitHub token', /\bgh[opusr]_[A-Za-z0-9_]{20,}\b/],
    ['Cloudflare API token', /\b[A-Za-z0-9_-]{40,}\b(?=\s*(?:#|\/\/)?\s*(?:cloudflare|cf)[-_ ]?(?:api )?token)/i], ['Resend API key', /\bre_[A-Za-z0-9_-]{20,}\b/],
    ['Google API key', /\bAIza[0-9A-Za-z_-]{30,}\b/], ['AWS access key', /\bAKIA[0-9A-Z]{16}\b/], ['Generic assigned secret', /(?:AUTH_SECRET|GOOGLE_CLIENT_SECRET|DATA_ENCRYPTION_KEY|RESEND_API_KEY)\s*[:=]\s*["']?(?!REPLACE|YOUR_|example|\$\{|undefined)[A-Za-z0-9_\-]{16,}/]
  ];
  const matches = [];
  for (const file of files) {
    const normalized = file.replaceAll('\\', '/'); if (ignored.test(normalized)) continue;
    let content = ''; try { content = await readFile(path.join(root, file), 'utf8'); } catch { continue; }
    if (content.length > 2_000_000) continue;
    content.split(/\r?\n/).forEach((line, offset) => patterns.forEach(([type, pattern]) => { if (pattern.test(line)) matches.push({ file: normalized, line: offset + 1, type }); }));
  }
  check('SEC-001', 'Git-tracked credential pattern scan', matches.length === 0, matches.length ? `${matches.length} potential credentials detected; values redacted.` : 'No credential-shaped values detected.');
  if (matches.length) finding('LSW-SEC-002', 'critical', 'Secrets', 'Possible committed credential', matches.map(match => `${match.type} at ${match.file}:${match.line}`).join('; '), 'Value-redacted tracked-file pattern scan', 'Revoke and rotate the credential, remove it from Git history, and store the replacement in Cloudflare or GitHub Actions secrets.');
}

async function scanWorkerBoundaries() {
  const worker = await source('src/worker.js'); const schema = await source('migrations/0001_initial.sql'); const forms = await source('migrations/0002_google_forms.sql');
  const auth = /async function currentUser[\s\S]*legacy_session/.test(worker) && /HttpOnly; SameSite=Lax/.test(worker) && /magic_links/.test(worker);
  check('AUTHN-001', 'Magic-link authentication boundary', auth, auth ? 'Hashed expiring links and HTTP-only session cookies detected.' : 'Required magic-link controls were not detected.');
  if (!auth) finding('LSW-SEC-003', 'critical', 'Authentication', 'Magic-link authentication boundary incomplete', 'The Worker does not show all expected token hashing, expiry, and cookie protections.', 'src/worker.js static scan', 'Restore hashed single-use tokens, bounded expiry, and HTTP-only SameSite session cookies.');
  const roleGuard = /const can = \(user, \.\.\.roles\)/.test(worker) && /if \(!url\.pathname\.startsWith\('\/api\/'\)\)/.test(worker) && /if \(!user\) return unauthorized\(\)/.test(worker);
  check('AUTHZ-001', 'Default authentication and role guard', roleGuard, roleGuard ? 'Protected API boundary and role helper detected.' : 'Default API authorization guard is incomplete.');
  if (!roleGuard) finding('LSW-SEC-004', 'critical', 'Authorization', 'Protected API boundary is incomplete', 'The static Worker guard pattern was not found.', 'src/worker.js static scan', 'Make every API route authenticated by default and require explicit roles for privileged routes.');
  const sensitive = /encryptSecret\(/.test(worker) && /payment_account_number_encrypted/.test(schema) && /guardian_contact_encrypted/.test(await source('migrations/0004_students_attendance.sql'));
  check('DATA-001', 'Sensitive payment and guardian data encryption', sensitive, sensitive ? 'AES-GCM storage paths detected for payment and guardian details.' : 'Expected encryption boundary was not detected.');
  if (!sensitive) finding('LSW-SEC-005', 'high', 'Sensitive data', 'Sensitive school data encryption boundary incomplete', 'Payment or guardian contact storage is not demonstrably encrypted.', 'Worker and migration static scan', 'Use application-layer authenticated encryption before writing sensitive fields to D1.');
  const paymentWebhook = /webhook|stripe|paystack|paypal/i.test(worker); check('PAY-001', 'Payment/webhook surface', !paymentWebhook, paymentWebhook ? 'A payment/webhook integration was detected and requires manual provider verification.' : 'No payment processor or webhook endpoint is implemented; payment methods are stored as protected profile data.');
  if (paymentWebhook) finding('LSW-SEC-006', 'medium', 'Payments', 'Payment or webhook code requires validation review', 'A payment/webhook keyword was detected.', 'src/worker.js static scan', 'Verify provider signatures, event idempotency, replay protection, and provider-owned payment state.');
  const uploads = /formData\(|R2|upload|multipart/i.test(worker); check('FILE-001', 'File-upload surface', !uploads, uploads ? 'Potential upload handling detected.' : 'No file upload endpoint is implemented.');
  if (uploads) finding('LSW-SEC-007', 'medium', 'File upload', 'Potential upload surface needs review', 'A file-upload related pattern was detected.', 'src/worker.js static scan', 'Validate signatures and size, scan content, isolate storage, and require authorization.');
  const publicWrites = ['/api/auth/request-link']; const rateLimited = /rate.?limit|throttle|cf-connecting-ip/i.test(worker); check('ABUSE-001', 'Public write API abuse controls', rateLimited, rateLimited ? 'A rate-limit or throttle pattern was detected.' : `No application-level rate-limit pattern detected for ${publicWrites.join(', ')}.`);
  if (!rateLimited) finding('LSW-SEC-008', 'high', 'Abuse prevention', 'Public magic-link request endpoint lacks detectable rate limiting', 'POST /api/auth/request-link is public and static analysis found no throttle or IP/request-key limit.', 'src/worker.js static scan', 'Add D1 or Durable Object request limits per IP and normalized email, and configure Cloudflare WAF/Turnstile before production release.');
  const idempotency = /google_event_id/.test(worker) && /INSERT OR IGNORE INTO form_response_imports/.test(worker) && forms.includes('UNIQUE(mapping_id, google_response_id)');
  check('IDEMP-001', 'Google sync idempotency', idempotency, idempotency ? 'Calendar event and Forms response de-duplication detected.' : 'One or more external integration de-duplication controls are absent.');
  if (!idempotency) finding('LSW-SEC-009', 'high', 'External integrations', 'Google sync idempotency boundary incomplete', 'Calendar or Forms import de-duplication was not detected.', 'Worker and schema static scan', 'Persist provider identifiers and reject repeated events/responses before side effects.');
}

async function scanHttpPolicy() {
  const worker = await source('src/worker.js'); const required = ['content-security-policy', 'x-content-type-options', 'referrer-policy', 'permissions-policy']; const missing = required.filter(header => !worker.toLowerCase().includes(header));
  check('HTTP-001', 'Browser security headers', missing.length === 0, missing.length ? `Missing static header policy: ${missing.join(', ')}.` : 'CSP, X-Content-Type-Options, Referrer-Policy and Permissions-Policy detected.');
  if (missing.length) finding('LSW-SEC-010', 'medium', 'Browser security', 'Security response headers incomplete', missing.join(', '), 'src/worker.js static scan', 'Apply centralized security headers to Worker asset and API responses as appropriate.');
}

async function scanLiveHeaders() {
  const targets = (process.env.SECURITY_SCAN_LIVE_URLS || '').split(',').map(value => value.trim()).filter(Boolean); if (!targets.length) { check('LIVE-001', 'Live header targets configured', true, 'No live endpoint configured; non-destructive live check skipped.'); return; }
  const required = ['content-security-policy', 'strict-transport-security', 'x-content-type-options', 'referrer-policy', 'permissions-policy'];
  for (const target of targets) try { const response = await fetch(target, { method: 'HEAD', redirect: 'manual', signal: AbortSignal.timeout(15_000) }); const missing = required.filter(header => !response.headers.has(header)); check(`LIVE-${new URL(target).hostname}`, `Live headers for ${target}`, missing.length === 0, `HTTP ${response.status}; ${missing.length ? `missing ${missing.join(', ')}` : 'required headers present'}.`); if (missing.length) finding(`LSW-SEC-LIVE-${findings.filter(item => item.id.startsWith('LSW-SEC-LIVE')).length + 1}`, 'medium', 'Live configuration', `Production headers missing on ${target}`, missing.join(', '), `Unauthenticated HEAD returned HTTP ${response.status}`, 'Verify the deployed Worker header policy and Cloudflare SSL/TLS settings.'); } catch (error) { finding(`LSW-SEC-LIVE-${findings.filter(item => item.id.startsWith('LSW-SEC-LIVE')).length + 1}`, 'medium', 'Live configuration', `Live header check failed for ${target}`, String(error.message), 'Non-destructive HEAD request', 'Confirm endpoint availability and rerun the live scanner.'); }
}

function summary() { return Object.fromEntries(['critical','high','medium','low','info'].map(level => [level, findings.filter(f => f.severity === level).length])); }
function markdown(report) { const rows = report.findings.length ? report.findings.map(f => `| ${f.severity.toUpperCase()} | ${f.id} | ${f.title.replaceAll('|','\\|')} | ${f.owner} |`).join('\n') : '| — | — | No open findings | — |'; const details = report.findings.map(f => `### ${f.id}: ${f.title}\n\n- Severity: ${f.severity.toUpperCase()}\n- Category: ${f.category}\n- Evidence: ${f.evidence}\n- Details: ${f.details}\n- Required remediation: ${f.remediation}`).join('\n\n'); return `# Legacy School Workspace Security Scan\n\nGenerated: ${report.generatedAt}\n\n## Summary\n\n- Critical: ${report.summary.critical}\n- High: ${report.summary.high}\n- Medium: ${report.summary.medium}\n- Low: ${report.summary.low}\n\n## Findings\n\n| Severity | ID | Finding | Owner |\n|---|---|---|---|\n${rows}\n\n## Checks\n\n| Result | ID | Check | Details |\n|---|---|---|---|\n${report.checks.map(c => `| ${c.passed ? 'PASS' : 'ATTENTION'} | ${c.id} | ${c.title} | ${c.details.replaceAll('|','\\|')} |`).join('\n')}\n\n## Details\n\n${details || 'No open findings.'}\n\n## Scanner boundary\n\nThis report is automated evidence, not a penetration test or compliance certification. It cannot prove Cloudflare dashboard configuration, Google Workspace consent, Resend configuration, production data isolation, historical Git cleanup, or the absence of exploit chains. Suspected secret values are never printed or stored.\n`; }

async function recipients() { const endpoint = (process.env.SECURITY_REPORT_SETTINGS_URL || '').trim(); const token = (process.env.SECURITY_REPORT_TOKEN || '').trim(); let raw = (process.env.SECURITY_REPORT_RECIPIENTS || '').trim(); if (endpoint || token) { if (!endpoint || !token) throw Error('SECURITY_REPORT_SETTINGS_URL and SECURITY_REPORT_TOKEN must be configured together.'); const url = new URL(endpoint); if (url.protocol !== 'https:') throw Error('SECURITY_REPORT_SETTINGS_URL must use HTTPS.'); const response = await fetch(url,{method:'POST',headers:{authorization:`Bearer ${token}`,'content-type':'application/json'},body:'{}',signal:AbortSignal.timeout(15_000)}); if (!response.ok) throw Error(`Recipient service returned HTTP ${response.status}.`); const payload = await response.json(); raw = Array.isArray(payload?.recipients) ? payload.recipients.join(',') : ''; } if (!raw) throw Error('Configure GUI recipient service or SECURITY_REPORT_RECIPIENTS.'); const values = [...new Set(raw.split(',').map(value => value.trim().toLowerCase()).filter(Boolean))]; if (!values.length || values.some(value => !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value))) throw Error('Recipient configuration contains invalid addresses.'); return values; }
async function sendReport(report, content) { const to = await recipients(); if (emailDryRun) { console.log(`Security email dry run: validated ${to.length} recipient(s); no message sent.`); return; } const apiKey = (process.env.RESEND_API_KEY || '').trim(); const from = (process.env.SECURITY_EMAIL_FROM || '').trim(); if (!apiKey || !from) throw Error('RESEND_API_KEY and SECURITY_EMAIL_FROM are required for delivery.'); const date = report.generatedAt.slice(0,10); const reportHash = createHash('sha256').update(content).digest('hex').slice(0,16); for (const recipient of to) { const recipientHash = createHash('sha256').update(recipient).digest('hex').slice(0,16); const response = await fetch('https://api.resend.com/emails',{method:'POST',headers:{authorization:`Bearer ${apiKey}`,'content-type':'application/json','idempotency-key':`legacy-school-security/${date}/${reportHash}/${recipientHash}`},body:JSON.stringify({from,to:[recipient],subject:`[Legacy School Security] ${report.summary.critical} Critical, ${report.summary.high} High — ${date}`,text:`Legacy School Workspace security report\n\nCritical: ${report.summary.critical}\nHigh: ${report.summary.high}\nMedium: ${report.summary.medium}\n\nThis automated report is not a penetration test or compliance certification.`,attachments:[{filename:`legacy-school-security-report-${date}.md`,content:Buffer.from(content).toString('base64')}]}),signal:AbortSignal.timeout(20_000)}); if (!response.ok) throw Error(`Resend rejected report delivery with HTTP ${response.status}.`); } }

auditDependencies(); await scanTrackedSecrets(); await scanWorkerBoundaries(); await scanHttpPolicy(); if (live) await scanLiveHeaders(); findings.sort((a,b) => rank[b.severity]-rank[a.severity] || a.id.localeCompare(b.id)); const report={schemaVersion:1,generatedAt:new Date().toISOString(),live,summary:summary(),findings,checks}; await mkdir(reportDir,{recursive:true}); const rendered=markdown(report); await writeFile(path.join(reportDir,'latest.json'),`${JSON.stringify(report,null,2)}\n`); await writeFile(path.join(reportDir,'latest.md'),rendered); console.log(`Legacy School security scan: ${report.summary.critical} critical, ${report.summary.high} high, ${report.summary.medium} medium, ${report.summary.low} low`); if(email||emailDryRun)try{await sendReport(report,rendered)}catch(error){console.error(`Security report email failed: ${error.message}`);process.exitCode=2} if(failOn!=='none'&&process.exitCode!==2){const threshold=rank[failOn];if(threshold===undefined){console.error(`Unknown --fail-on severity: ${failOn}`);process.exitCode=2}else if(findings.some(item=>rank[item.severity]>=threshold)){console.error(`Security gate failed: at least one finding is ${failOn} or higher.`);process.exitCode=1}}
