-- Operational roles are managed only by the Super Admin. Their invitations
-- use the same one-time sign-in mechanism as teachers but retain a separate
-- audit and rate-limit trail.
CREATE TABLE IF NOT EXISTS operational_staff_invitation_sends (
  id TEXT PRIMARY KEY,
  staff_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sent_by_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  sent_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_operational_staff_invites_user_sent
  ON operational_staff_invitation_sends(staff_user_id, sent_at);
