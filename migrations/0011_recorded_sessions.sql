-- Teacher payment reports are calculated from recorded scheduled sessions,
-- rather than a Google Form or manually-entered totals.
ALTER TABLE calendar_events ADD COLUMN learning_mode TEXT NOT NULL DEFAULT 'group'
  CHECK(learning_mode IN ('group','one_to_one','club'));

CREATE TABLE IF NOT EXISTS recorded_sessions (
  id TEXT PRIMARY KEY,
  calendar_event_id TEXT NOT NULL UNIQUE REFERENCES calendar_events(id) ON DELETE CASCADE,
  teacher_id TEXT NOT NULL REFERENCES teachers(id) ON DELETE RESTRICT,
  group_id TEXT REFERENCES groups(id) ON DELETE SET NULL,
  session_date TEXT NOT NULL,
  learning_mode TEXT NOT NULL CHECK(learning_mode IN ('group','one_to_one','club')),
  outcome TEXT NOT NULL CHECK(outcome IN ('completed','no_show','trial')),
  note TEXT,
  recorded_by_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_recorded_sessions_teacher_date
  ON recorded_sessions(teacher_id, session_date, outcome);

ALTER TABLE salary_report_submissions ADD COLUMN approved_admin_minutes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE salary_report_submissions ADD COLUMN class_pay_cents INTEGER NOT NULL DEFAULT 0;
ALTER TABLE salary_report_submissions ADD COLUMN admin_pay_cents INTEGER NOT NULL DEFAULT 0;
ALTER TABLE salary_report_submissions ADD COLUMN total_pay_cents INTEGER NOT NULL DEFAULT 0;
