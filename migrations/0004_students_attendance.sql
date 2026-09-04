-- Student records are deliberately separated from employee/payment records.
-- Guardian contact data is encrypted by the Worker before it is persisted.
CREATE TABLE IF NOT EXISTS students (
  id TEXT PRIMARY KEY,
  full_name TEXT NOT NULL,
  preferred_name TEXT,
  school_email TEXT COLLATE NOCASE,
  grade_level TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','inactive','withdrawn')),
  guardian_contact_encrypted TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS enrollments (
  id TEXT PRIMARY KEY,
  student_id TEXT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'enrolled' CHECK(status IN ('enrolled','trial','withdrawn')),
  enrolled_on TEXT NOT NULL,
  ended_on TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(student_id, group_id, enrolled_on)
);

CREATE TABLE IF NOT EXISTS attendance_records (
  id TEXT PRIMARY KEY,
  enrollment_id TEXT NOT NULL REFERENCES enrollments(id) ON DELETE CASCADE,
  scheduled_for TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('present','absent','late','excused')),
  marked_by_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  note TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(enrollment_id, scheduled_for)
);

CREATE INDEX IF NOT EXISTS idx_enrollments_group_status ON enrollments(group_id, status, enrolled_on, ended_on);
CREATE INDEX IF NOT EXISTS idx_enrollments_student ON enrollments(student_id, status);
CREATE INDEX IF NOT EXISTS idx_attendance_scheduled ON attendance_records(scheduled_for, status);
