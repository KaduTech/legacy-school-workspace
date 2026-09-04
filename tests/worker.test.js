import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import worker from '../src/worker.js';

const env = {
  AUTH_SECRET: 'test-secret-that-is-long-enough-for-local-validation',
  ASSETS: { fetch: request => new Response('asset', { status: 200 }) }
};

async function sessionCookie(userId, secret = env.AUTH_SECRET) {
  const encode = value => btoa(String.fromCharCode(...new TextEncoder().encode(value))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  const payload = encode(JSON.stringify({ sub: userId, exp: Date.now() + 60_000 }));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload))))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  return `legacy_session=${payload}.${signature}`;
}

async function signedState(payloadObject, secret = env.AUTH_SECRET) {
  const encode = value => btoa(String.fromCharCode(...new TextEncoder().encode(value))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  const payload = encode(JSON.stringify(payloadObject));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload))))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  return `${payload}.${signature}`;
}

async function encryptedSecret(value, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cryptoKey = await crypto.subtle.importKey('raw', Uint8Array.from(atob(key.replaceAll('-', '+').replaceAll('_', '/').padEnd(Math.ceil(key.length / 4) * 4, '=')), char => char.charCodeAt(0)), { name: 'AES-GCM' }, false, ['encrypt']);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, new TextEncoder().encode(value));
  const encode = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  return { version: 1, algorithm: 'AES-GCM', iv: encode(iv), ciphertext: encode(ciphertext) };
}

test('health endpoint is public and reports service readiness', async () => {
  const response = await worker.fetch(new Request('https://app.example.test/api/health'), env);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { ok: true, service: 'legacy-school-workspace' });
});

test('static workspace assets receive browser security headers', async () => {
  const response = await worker.fetch(new Request('https://app.example.test/'), env);
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
});

test('protected endpoints reject requests without a session', async () => {
  const response = await worker.fetch(new Request('https://app.example.test/api/teachers'), env);
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: 'Authentication required' });
});

test('the configured bootstrap administrator is elevated to Super Admin without a public elevation route', async () => {
  const writes = [];
  const scopedEnv = {
    ...env,
    BOOTSTRAP_ADMIN_EMAIL: 'owner@example.test',
    DB: { prepare(query) { return { bind(...values) { this.values = values; return this; }, async first() { return { id: 'owner-1', email: 'owner@example.test', name: 'Owner', role: 'admin', status: 'active', is_super_admin: 0 }; }, async run() { writes.push({ query, values: this.values }); return { success: true }; } }; } }
  };
  const response = await worker.fetch(new Request('https://app.example.test/api/me', { headers: { cookie: await sessionCookie('owner-1') } }), scopedEnv);
  assert.equal(response.status, 200);
  assert.equal((await response.json()).user.is_super_admin, 1);
  assert.ok(writes.some(write => write.query.includes('SET is_super_admin=1')));
});

test('a regular administrator cannot create or invite operational staff', async () => {
  const scopedEnv = {
    ...env,
    DB: { prepare() { return { bind() { return this; }, async first() { return { id: 'admin-1', email: 'admin@example.test', name: 'Admin', role: 'admin', status: 'active', is_super_admin: 0 }; } }; } }
  };
  const response = await worker.fetch(new Request('https://app.example.test/api/staff', { method: 'POST', headers: { cookie: await sessionCookie('admin-1'), 'content-type': 'application/json' }, body: JSON.stringify({ name: 'Finance', email: 'finance@example.test', role: 'finance' }) }), scopedEnv);
  assert.equal(response.status, 403);
  assert.deepEqual(await response.json(), { error: 'Insufficient permissions' });
});

test('security report recipient service rejects a missing scanner token', async () => {
  const response = await worker.fetch(new Request('https://app.example.test/api/security/report-recipients', { method: 'POST' }), env);
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: 'Unauthorized' });
});

test('all operational workflow routes reject requests without a session', async () => {
  for (const path of ['/api/teachers/teacher-1/onboarding', '/api/teachers/teacher-1/payment-details', '/api/teachers/teacher-1/invite', '/api/staff', '/api/staff/staff-1/invite', '/api/onboarding/item-1/remind', '/api/time-entries', '/api/pay-cycles', '/api/pay-cycles/cycle-1/salary-reports', '/api/salary-reports/report-1', '/api/groups', '/api/forms', '/api/academic-dates', '/api/incidents']) {
    const response = await worker.fetch(new Request(`https://app.example.test${path}`), env);
    assert.equal(response.status, 401, path);
  }
});

test('the academic calendar endpoint returns only inclusive dates in the requested range', async () => {
  const calls = [];
  const scopedEnv = {
    ...env,
    DB: { prepare(query) { const call = { query, bindings: [] }; calls.push(call); return { bind(...values) { call.bindings = values; return this; }, async first() { return { id: 'teacher-user', email: 'teacher@example.test', name: 'Teacher', role: 'teacher', status: 'active' }; }, async all() { return { results: [{ id: 'acad-1', title: 'Labor Day', starts_on: '2026-09-07', ends_on: '2026-09-07', category: 'holiday', is_no_class: 1 }] }; } }; } }
  };
  const response = await worker.fetch(new Request('https://app.example.test/api/academic-dates?from=2026-09-01&to=2026-09-30', { headers: { cookie: await sessionCookie('teacher-user') } }), scopedEnv);
  assert.equal(response.status, 200);
  assert.equal((await response.json()).dates[0].title, 'Labor Day');
  const rangeQuery = calls.find(call => call.query.includes('FROM academic_dates'));
  assert.deepEqual(rangeQuery.bindings, ['2026-09-30', '2026-09-01']);
});

test('a no-show report enforces the group wait threshold before writing an incident', async () => {
  const scopedEnv = {
    ...env,
    DB: { prepare(query) { return { bind() { return this; }, async first() { return { id: 'teacher-user', email: 'teacher@example.test', name: 'Teacher', role: 'teacher', status: 'active' }; } }; } }
  };
  const response = await worker.fetch(new Request('https://app.example.test/api/incidents', { method: 'POST', headers: { cookie: await sessionCookie('teacher-user'), 'content-type': 'application/json' }, body: JSON.stringify({ kind: 'class_no_show', learningMode: 'group', occurredAt: '2026-09-04T10:00:00-04:00', waitedMinutes: 19, details: 'No learner joined.' }) }), scopedEnv);
  assert.equal(response.status, 409);
  assert.deepEqual(await response.json(), { error: 'A group no-show report requires at least 20 waited minutes.' });
});

test('student guardian contact is encrypted before being written to D1', async () => {
  const writes = [];
  const scopedEnv = {
    ...env,
    DATA_ENCRYPTION_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(9))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', ''),
    DB: { prepare(query) { return { bind(...values) { this.values = values; return this; }, async first() { return { id: 'lss-1', email: 'lss@example.test', name: 'LSS', role: 'lss', status: 'active' }; }, async run() { writes.push({ query, values: this.values }); return { success: true }; } }; } }
  };
  const response = await worker.fetch(new Request('https://app.example.test/api/students', { method: 'POST', headers: { cookie: await sessionCookie('lss-1'), 'content-type': 'application/json' }, body: JSON.stringify({ fullName: 'Learner One', gradeLevel: '7', guardianContact: { name: 'Parent One', email: 'parent@example.test' } }) }), scopedEnv);
  assert.equal(response.status, 201);
  const insert = writes.find(write => write.query.startsWith('INSERT INTO students'));
  assert.ok(insert);
  assert.notEqual(insert.values[6], JSON.stringify({ name: 'Parent One', email: 'parent@example.test' }));
  assert.match(insert.values[6], /ciphertext/);
  assert.equal((await response.json()).student.fullName, 'Learner One');
});

test('attendance rejects an unknown status before it can reach D1', async () => {
  const scopedEnv = {
    ...env,
    DB: { prepare() { return { bind() { return this; }, async first() { return { id: 'teacher-user', email: 'teacher@example.test', name: 'Teacher', role: 'teacher', status: 'active' }; } }; } }
  };
  const response = await worker.fetch(new Request('https://app.example.test/api/attendance', { method: 'POST', headers: { cookie: await sessionCookie('teacher-user'), 'content-type': 'application/json' }, body: JSON.stringify({ groupId: 'group-1', scheduledFor: '2026-09-04', records: [{ enrollmentId: 'enrollment-1', status: 'not_enrolled' }] }) }), scopedEnv);
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { error: 'groupId, scheduledFor and 1–200 attendance records with valid statuses are required.' });
});

test('a teacher can record one completed session only after an assigned class has ended', async () => {
  const writes = [];
  const scopedEnv = {
    ...env,
    DB: { prepare(query) { return { bind(...values) { this.values = values; return this; }, async first() {
      if (query.includes('FROM users')) return { id: 'teacher-user', email: 'teacher@example.test', name: 'Teacher', role: 'teacher', status: 'active' };
      if (query.includes('SELECT id FROM teachers')) return { id: 'teacher-1' };
      if (query.includes('FROM calendar_events')) return { id: 'event-1', group_id: 'group-1', ends_at: '2020-01-01T12:00:00.000Z', learning_mode: 'group' };
      if (query.includes('FROM teacher_groups')) return { assigned: 1 };
      if (query.includes('FROM recorded_sessions')) return null;
      return null;
    }, async run() { writes.push({ query, values: this.values }); return { success: true }; } }; } }
  };
  const response = await worker.fetch(new Request('https://app.example.test/api/calendar/events/event-1/session', { method: 'POST', headers: { cookie: await sessionCookie('teacher-user'), 'content-type': 'application/json' }, body: JSON.stringify({ outcome: 'completed' }) }), scopedEnv);
  assert.equal(response.status, 201);
  const insert = writes.find(write => write.query.startsWith('INSERT INTO recorded_sessions'));
  assert.ok(insert);
  assert.equal(insert.values[1], 'event-1');
  assert.equal(insert.values[5], 'group');
  assert.equal(insert.values[6], 'completed');
});

test('finance users cannot list student records', async () => {
  const scopedEnv = {
    ...env,
    DB: { prepare(query) { return { bind() { return this; }, async first() { return query.includes('FROM users') ? { id: 'finance-1', email: 'finance@example.test', name: 'Finance', role: 'finance', status: 'active' } : null; } }; } }
  };
  const response = await worker.fetch(new Request('https://app.example.test/api/students', { headers: { cookie: await sessionCookie('finance-1') } }), scopedEnv);
  assert.equal(response.status, 403);
  assert.deepEqual(await response.json(), { error: 'Insufficient permissions' });
});

test('a teacher can retrieve only their own teacher record', async () => {
  const calls = [];
  const scopedEnv = {
    ...env,
    DB: { prepare(query) { const call = { query, bindings: [] }; calls.push(call); return { bind(...values) { call.bindings = values; return this; }, async first() { return query.includes('FROM users') ? { id: 'user-1', email: 'teacher@example.test', name: 'Teacher', role: 'teacher', status: 'active' } : { id: 'teacher-own' }; }, async all() { return { results: [] }; } }; } }
  };
  const response = await worker.fetch(new Request('https://app.example.test/api/teachers', { headers: { cookie: await sessionCookie('user-1') } }), scopedEnv);
  assert.equal(response.status, 200);
  const listQuery = calls.find(call => call.query.includes('SELECT t.id'));
  assert.match(listQuery.query, /WHERE t\.id=\?/);
  assert.deepEqual(listQuery.bindings, ['teacher-own']);
});

test('a teacher dashboard is scoped to that teacher rather than school-wide totals', async () => {
  const calls = [];
  const scopedEnv = {
    ...env,
    DB: {
      prepare(query) { const call = { query, bindings: [] }; calls.push(call); return { bind(...values) { call.bindings = values; return this; }, async first() { if (query.includes('FROM users')) return { id: 'user-1', email: 'teacher@example.test', name: 'Teacher', role: 'teacher', status: 'active' }; return { id: 'teacher-own' }; } }; },
      async batch() { return [{ results: [{ count: 2 }] }, { results: [{ count: 3 }] }, { results: [{ hours: 1.5 }] }]; }
    }
  };
  const response = await worker.fetch(new Request('https://app.example.test/api/dashboard', { headers: { cookie: await sessionCookie('user-1') } }), scopedEnv);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { activeTeachers: 1, onboardingOpen: 2, classesToday: 3, adminHours: 1.5, portal: 'teacher' });
  assert.ok(calls.some(call => call.query.includes('FROM teachers') && call.bindings[0] === 'user-1'));
});

test('invalid magic-link request does not call the email provider', async () => {
  const response = await worker.fetch(new Request('https://app.example.test/api/auth/request-link', { method: 'POST', body: JSON.stringify({ email: 'not-an-email' }) }), env);
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { error: 'A valid email is required.' });
});

test('an invited teacher account activates only after its valid magic link is used', async () => {
  const writes = [];
  const scopedEnv = {
    ...env,
    DB: { prepare(query) { return { bind(...values) { this.values = values; return this; }, async first() { return { id: 'magic-1', user_id: 'teacher-user', used_at: null, expires_at: new Date(Date.now() + 60_000).toISOString(), status: 'invited' }; }, async run() { writes.push({ query, values: this.values }); return { success: true }; } }; } }
  };
  const response = await worker.fetch(new Request('https://app.example.test/auth/callback?token=valid-test-token'), scopedEnv);
  assert.equal(response.status, 302);
  assert.ok(writes.some(write => write.query.includes("UPDATE users SET status='active'")));
});

test('teacher onboarding invitations are rate-limited before an email is attempted', async () => {
  const scopedEnv = {
    ...env,
    RESEND_API_KEY: 're_test_key',
    RESEND_FROM: 'School <school@example.test>',
    DB: { prepare(query) { return { bind() { return this; }, async first() {
      if (query.includes('FROM users')) return { id: 'admin-1', email: 'admin@example.test', name: 'Admin', role: 'admin', status: 'active', is_super_admin: 0 };
      if (query.includes('FROM teachers t JOIN users')) return { id: 'teacher-1', full_name: 'Teacher One', email: 'teacher@example.test', user_id: 'teacher-user', account_status: 'invited' };
      if (query.includes('teacher_invitation_sends')) return { id: 'invite-1' };
      return null;
    } }; } }
  };
  const response = await worker.fetch(new Request('https://app.example.test/api/teachers/teacher-1/invite', { method: 'POST', headers: { cookie: await sessionCookie('admin-1') } }), scopedEnv);
  assert.equal(response.status, 409);
  assert.deepEqual(await response.json(), { error: 'An onboarding invitation was already sent for this teacher in the last 24 hours.' });
});

test('salary reports calculate payable counts and pay from recorded sessions rather than client totals', async () => {
  const writes = [];
  const scopedEnv = {
    ...env,
    DB: { prepare(query) { return { bind(...values) { this.values = values; return this; }, async first() {
      if (query.includes('FROM users')) return { id: 'teacher-user', email: 'teacher@example.test', name: 'Teacher', role: 'teacher', status: 'active', is_super_admin: 0 };
      if (query.includes('SELECT id FROM teachers')) return { id: 'teacher-1' };
      if (query.includes('FROM pay_cycles')) return { id: 'cycle-1', starts_on: '2099-01-01', ends_on: '2099-01-15', submission_due_on: '2099-01-17', status: 'open' };
      if (query.includes('FROM time_entries')) return { hours: 1.5 };
      return null;
    }, async all() { if (query.includes('FROM recorded_sessions')) return { results: [{ learning_mode: 'group', outcome: 'completed', count: 2 }, { learning_mode: 'one_to_one', outcome: 'completed', count: 1 }, { learning_mode: 'one_to_one', outcome: 'no_show', count: 1 }] }; return { results: [] }; }, async run() { writes.push({ query, values: this.values }); return { success: true }; } }; } }
  };
  const response = await worker.fetch(new Request('https://app.example.test/api/pay-cycles/cycle-1/salary-reports', { method: 'POST', headers: { cookie: await sessionCookie('teacher-user'), 'content-type': 'application/json' }, body: JSON.stringify({ groupAttendedCount: -999, notes: 'Recorded sessions reviewed.' }) }), scopedEnv);
  assert.equal(response.status, 201);
  const insert = writes.find(write => write.query.startsWith('INSERT INTO salary_report_submissions'));
  assert.ok(insert);
  assert.deepEqual(insert.values.slice(3, 12), [2, 0, 1, 1, 0, 90, 3000, 750, 3750]);
});

test('Google callback rejects a missing or forged OAuth state before using the database', async () => {
  const response = await worker.fetch(new Request('https://app.example.test/auth/google/callback?code=not-enough'), env);
  assert.equal(response.status, 401);
});

test('Google callback verifies and records the dedicated school Google account without storing its refresh token in plaintext', async () => {
  const writes = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async url => {
    if (url === 'https://oauth2.googleapis.com/token') return Response.json({ refresh_token: 'google-refresh-token', access_token: 'google-access-token', scope: 'openid email https://www.googleapis.com/auth/calendar.events' });
    if (url === 'https://openidconnect.googleapis.com/v1/userinfo') return Response.json({ email: 'school-google@example.test', email_verified: true });
    throw new Error(`Unexpected fetch: ${url}`);
  };
  try {
    const scopedEnv = {
      ...env,
      DATA_ENCRYPTION_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(3))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', ''),
      GOOGLE_CLIENT_ID: 'client-id', GOOGLE_CLIENT_SECRET: 'client-secret', GOOGLE_REDIRECT_URI: 'https://app.example.test/auth/google/callback', GOOGLE_OAUTH_ALLOWED_EMAIL: 'school-google@example.test',
      DB: { prepare(query) { return { bind(...values) { this.values = values; return this; }, async first() { return query.includes('FROM users') ? { id: 'admin-user', status: 'active', role: 'admin' } : null; }, async run() { writes.push({ query, values: this.values }); return { success: true }; } }; } }
    };
    const state = await signedState({ sub: 'admin-user', exp: Date.now() + 60_000, purpose: 'google-oauth' });
    const response = await worker.fetch(new Request(`https://app.example.test/auth/google/callback?code=code&state=${encodeURIComponent(state)}`), scopedEnv);
    assert.equal(response.status, 302);
    const integrationWrite = writes.find(write => write.query.includes('integration_settings'));
    assert.ok(integrationWrite);
    assert.match(integrationWrite.values[0], /school-google@example\.test/);
    assert.doesNotMatch(integrationWrite.values[0], /google-refresh-token/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('Google callback rejects a personal account that is not the approved school connection', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async url => url === 'https://oauth2.googleapis.com/token'
    ? Response.json({ refresh_token: 'google-refresh-token', access_token: 'google-access-token' })
    : Response.json({ email: 'unapproved@example.test', email_verified: true });
  try {
    const scopedEnv = {
      ...env,
      DATA_ENCRYPTION_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(4))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', ''),
      GOOGLE_CLIENT_ID: 'client-id', GOOGLE_CLIENT_SECRET: 'client-secret', GOOGLE_REDIRECT_URI: 'https://app.example.test/auth/google/callback', GOOGLE_OAUTH_ALLOWED_EMAIL: 'school-google@example.test',
      DB: { prepare(query) { return { bind() { return this; }, async first() { return query.includes('FROM users') ? { id: 'admin-user', status: 'active', role: 'admin' } : null; } }; } }
    };
    const state = await signedState({ sub: 'admin-user', exp: Date.now() + 60_000, purpose: 'google-oauth' });
    const response = await worker.fetch(new Request(`https://app.example.test/auth/google/callback?code=code&state=${encodeURIComponent(state)}`), scopedEnv);
    assert.equal(response.status, 403);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('an error-state form mapping is eligible for a retry rather than treated as missing', async () => {
  const calls = [];
  const encryptionKey = btoa(String.fromCharCode(...new Uint8Array(32).fill(8))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async url => {
    if (url === 'https://oauth2.googleapis.com/token') return Response.json({ access_token: 'access-token' });
    if (String(url).startsWith('https://forms.googleapis.com/v1/forms/form-1/responses?')) return Response.json({ responses: [] });
    throw new Error(`Unexpected fetch: ${url}`);
  };
  try {
    const scopedEnv = {
      ...env,
      DATA_ENCRYPTION_KEY: encryptionKey,
      GOOGLE_CLIENT_ID: 'client-id', GOOGLE_CLIENT_SECRET: 'client-secret',
      DB: { prepare(query) { const call = { query, values: [] }; calls.push(call); return { bind(...values) { call.values = values; return this; }, async first() {
        if (query.includes('FROM users')) return { id: 'admin-1', email: 'admin@example.test', name: 'Admin', role: 'admin', status: 'active' };
        if (query.includes('FROM form_mappings')) return { id: 'mapping-1', google_form_id: 'form-1', status: 'error', last_response_at: null };
        if (query.includes('FROM integration_settings')) return { config_json: JSON.stringify({ refreshToken: await encryptedSecret('refresh-token', encryptionKey) }) };
        return null;
      }, async run() { return { success: true }; } }; }, async batch() { return []; } }
    };
    const response = await worker.fetch(new Request('https://app.example.test/api/forms/mapping-1/sync', { method: 'POST', headers: { cookie: await sessionCookie('admin-1') } }), scopedEnv);
    assert.equal(response.status, 200);
    const mappingLookup = calls.find(call => call.query.includes('FROM form_mappings'));
    assert.match(mappingLookup.query, /status!='paused'/);
    assert.ok(calls.some(call => call.query.includes("SET status='active'")));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('a permitted operator can replace a non-payroll form mapping and reset its import cursor', async () => {
  const writes = [];
  const scopedEnv = {
    ...env,
    DB: { prepare(query) { return { bind(...values) { this.values = values; return this; }, async first() {
      if (query.includes('FROM users')) return { id: 'admin-1', email: 'admin@example.test', name: 'Admin', role: 'admin', status: 'active' };
      if (query.includes('SELECT id FROM form_mappings')) return { id: 'mapping-1' };
      return null;
    }, async run() { writes.push({ query, values: this.values }); return { success: true }; } }; } }
  };
  const response = await worker.fetch(new Request('https://app.example.test/api/forms/mapping-1', { method: 'PATCH', headers: { cookie: await sessionCookie('admin-1'), 'content-type': 'application/json' }, body: JSON.stringify({ googleFormId: 'editable-test-form-id', label: 'Test onboarding form', purpose: 'onboarding' }) }), scopedEnv);
  assert.equal(response.status, 200);
  const update = writes.find(write => write.query.startsWith('UPDATE form_mappings SET'));
  assert.ok(update);
  assert.match(update.query, /status='active',last_response_at=NULL/);
  assert.deepEqual(update.values.slice(0, 3), ['editable-test-form-id', 'Test onboarding form', 'onboarding']);
});

test('a permitted operator can remove an obsolete Form mapping', async () => {
  const writes = [];
  const scopedEnv = {
    ...env,
    DB: { prepare(query) { return { bind(...values) { this.values = values; return this; }, async first() {
      if (query.includes('FROM users')) return { id: 'admin-1', email: 'admin@example.test', name: 'Admin', role: 'admin', status: 'active' };
      if (query.includes('SELECT id,label,purpose FROM form_mappings')) return { id: 'mapping-1', label: 'Obsolete form', purpose: 'payment_method' };
      return null;
    }, async run() { writes.push({ query, values: this.values }); return { success: true }; } }; } }
  };
  const response = await worker.fetch(new Request('https://app.example.test/api/forms/mapping-1', { method: 'DELETE', headers: { cookie: await sessionCookie('admin-1') } }), scopedEnv);
  assert.equal(response.status, 200);
  assert.ok(writes.some(write => write.query === 'DELETE FROM form_mappings WHERE id=?' && write.values[0] === 'mapping-1'));
});

test('payment account numbers are encrypted before the worker writes them to D1', async () => {
  const writes = [];
  const scopedEnv = {
    ...env,
    DATA_ENCRYPTION_KEY: btoa(String.fromCharCode(...new Uint8Array(32).fill(7))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', ''),
    DB: { prepare(query) { return { bind(...values) { this.values = values; return this; }, async first() { return query.includes('FROM users') ? { id: 'finance-1', email: 'finance@example.test', name: 'Finance', role: 'finance', status: 'active' } : { id: 'teacher-1' }; }, async run() { writes.push({ query, values: this.values }); return { success: true }; } }; } }
  };
  const response = await worker.fetch(new Request('https://app.example.test/api/teachers/teacher-1/payment-details', { method: 'PUT', headers: { cookie: await sessionCookie('finance-1'), 'content-type': 'application/json' }, body: JSON.stringify({ paymentPlatform: 'Wise', accountName: 'Test Teacher', accountNumber: '123456789' }) }), scopedEnv);
  assert.equal(response.status, 200);
  const update = writes.find(write => write.query.startsWith('UPDATE teachers SET payment_platform'));
  assert.ok(update);
  assert.notEqual(update.values[2], '123456789');
  assert.match(update.values[2], /ciphertext/);
  assert.deepEqual(await response.json(), { ok: true, accountNumberMasked: '••••6789' });
});

test('the workspace portal keeps the operational workflows reachable after navigation', async () => {
  const source = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  for (const label of ['My profile', 'Onboarding', 'Payments', 'Time & admin', 'Calendar', 'Incidents', 'Integrations', 'Record session']) assert.match(source, new RegExp(label));
  assert.match(source, /root\.addEventListener\('click'/);
  assert.doesNotMatch(source, /\{once:true\}/);
  assert.match(source, /payment-details/);
  assert.match(source, /teachers\/\$\{encodeURIComponent\(id\)\}\/invite/);
  assert.match(source, /\/api\/attendance/);
  assert.match(source, /\/api\/forms/);
  assert.match(source, /form-edit/);
  assert.match(source, /form-delete/);
  assert.match(source, /Replace form/);
  assert.match(source, /Submit calculated salary report/);
});
