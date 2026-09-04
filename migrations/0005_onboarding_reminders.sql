CREATE TABLE IF NOT EXISTS onboarding_reminders (
  id TEXT PRIMARY KEY,
  onboarding_item_id TEXT NOT NULL REFERENCES onboarding_items(id) ON DELETE CASCADE,
  sent_by_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  recipient_email TEXT NOT NULL,
  sent_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_onboarding_reminders_item_sent ON onboarding_reminders(onboarding_item_id, sent_at);
