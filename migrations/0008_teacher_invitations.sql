-- An auditable, rate-limited invitation trail for new teacher accounts. This
-- is separate from individual onboarding-task reminders so operations can
-- distinguish the first welcome message from later follow-up communication.
CREATE TABLE IF NOT EXISTS teacher_invitation_sends (
  id TEXT PRIMARY KEY,
  teacher_id TEXT NOT NULL REFERENCES teachers(id) ON DELETE CASCADE,
  sent_by_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  sent_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_teacher_invitation_sends_teacher_sent
  ON teacher_invitation_sends(teacher_id, sent_at);
