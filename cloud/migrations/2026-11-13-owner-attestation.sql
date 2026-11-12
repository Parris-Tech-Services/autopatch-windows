-- Apply once to the existing AutoPatch D1 device registry before deploying
-- cloud/worker.js owner-attestation UI. This records an authenticated owner's
-- explicit personal-use confirmation; it does NOT authorise a patch.
ALTER TABLE device_registrations
  ADD COLUMN owner_attested INTEGER NOT NULL DEFAULT 0
  CHECK(owner_attested IN (0, 1));
ALTER TABLE device_registrations
  ADD COLUMN owner_attested_utc TEXT;
