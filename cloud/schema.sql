-- Read-only, unverified device registry. Owner/fleet credentials are NOT here.
-- D1 database: autopatch-enrolment
CREATE TABLE IF NOT EXISTS device_registrations (
  device_id TEXT PRIMARY KEY CHECK(length(device_id) BETWEEN 3 AND 64),
  hostname TEXT NOT NULL CHECK(length(hostname) BETWEEN 1 AND 100),
  device_class TEXT NOT NULL CHECK(device_class IN ('windows')),
  credential_sha256 TEXT NOT NULL CHECK(length(credential_sha256) = 64),
  registration_state TEXT NOT NULL DEFAULT 'unverified'
    CHECK(registration_state IN ('unverified', 'revoked')),
  created_utc TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen_utc TEXT NOT NULL DEFAULT (datetime('now')),
  auto_patch INTEGER NOT NULL DEFAULT 0 CHECK(auto_patch = 0),
  remote_control INTEGER NOT NULL DEFAULT 0 CHECK(remote_control = 0)
);
CREATE TABLE IF NOT EXISTS daily_rate_counts (
  date_key TEXT NOT NULL,
  ip_sha256 TEXT NOT NULL CHECK(length(ip_sha256) = 64),
  requests INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (date_key, ip_sha256)
);
CREATE INDEX IF NOT EXISTS idx_devices_created
  ON device_registrations(created_utc);
