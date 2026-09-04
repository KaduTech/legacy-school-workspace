-- Replaces the recurring salary-report Google Form. Counts intentionally keep
-- attended and no-show classes separate: a group with one learner is still a
-- group class, and no-shows must not be included in attended-class counts.
CREATE TABLE IF NOT EXISTS salary_report_submissions (
  id TEXT PRIMARY KEY,
  cycle_id TEXT NOT NULL REFERENCES pay_cycles(id) ON DELETE CASCADE,
  teacher_id TEXT NOT NULL REFERENCES teachers(id) ON DELETE CASCADE,
  group_attended_count INTEGER NOT NULL DEFAULT 0 CHECK(group_attended_count >= 0),
  group_no_show_count INTEGER NOT NULL DEFAULT 0 CHECK(group_no_show_count >= 0),
  one_to_one_attended_count INTEGER NOT NULL DEFAULT 0 CHECK(one_to_one_attended_count >= 0),
  one_to_one_no_show_count INTEGER NOT NULL DEFAULT 0 CHECK(one_to_one_no_show_count >= 0),
  one_to_one_trial_count INTEGER NOT NULL DEFAULT 0 CHECK(one_to_one_trial_count >= 0),
  notes TEXT,
  evidence_url TEXT,
  submitted_late INTEGER NOT NULL DEFAULT 0 CHECK(submitted_late IN (0,1)),
  status TEXT NOT NULL DEFAULT 'submitted' CHECK(status IN ('submitted','approved','rejected','paid')),
  submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  reviewed_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  reviewed_at TEXT,
  review_note TEXT,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(cycle_id, teacher_id)
);

CREATE INDEX IF NOT EXISTS idx_salary_report_cycle_status
  ON salary_report_submissions(cycle_id, status);
CREATE INDEX IF NOT EXISTS idx_salary_report_teacher_cycle
  ON salary_report_submissions(teacher_id, cycle_id);
