CREATE TABLE IF NOT EXISTS keys (
 id TEXT PRIMARY KEY,
 key_hash TEXT NOT NULL UNIQUE,
 key_prefix TEXT NOT NULL,
 label TEXT NOT NULL DEFAULT '',
 kind TEXT NOT NULL CHECK(kind IN ('temporary','permanent')),
 created_at INTEGER NOT NULL,
 expires_at INTEGER,
 revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS activations (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 activated_at INTEGER NOT NULL,
 key_prefix TEXT NOT NULL,
 client_id TEXT NOT NULL DEFAULT '',
 result TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_activations_time ON activations(activated_at);
