CREATE TABLE IF NOT EXISTS form_mappings (
  id TEXT PRIMARY KEY,
  google_form_id TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL,
  purpose TEXT NOT NULL CHECK(purpose IN ('payment_method','onboarding','feedback','attendance')),
  field_map_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','paused','error')),
  last_response_at TEXT,
  created_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS form_response_imports (
  id TEXT PRIMARY KEY,
  mapping_id TEXT NOT NULL REFERENCES form_mappings(id) ON DELETE CASCADE,
  google_response_id TEXT NOT NULL,
  submitted_at TEXT,
  encrypted_payload_json TEXT NOT NULL,
  imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  processed_at TEXT,
  UNIQUE(mapping_id, google_response_id)
);

CREATE INDEX IF NOT EXISTS idx_form_imports_mapping_submitted ON form_response_imports(mapping_id, submitted_at);
