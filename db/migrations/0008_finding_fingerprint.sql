-- Cross-run finding identity.
--
-- findings had no stable identity: every re-scan produced a fresh set of rows
-- with no way to say which of them were the same issue as last time. The
-- fingerprint is that identity, computed by db.FindingFingerprint.
--
-- Nullable-but-defaulted rather than NULL: existing rows get '' and are
-- backfilled by the server on first listing, so a diff sees "no identity yet"
-- instead of a NULL that every query must special-case.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS fingerprint TEXT NOT NULL DEFAULT '';

-- Partial index: only rows that actually carry an identity are worth indexing,
-- and the diff always filters on fingerprint <> ''.
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint
    ON findings (fingerprint)
    WHERE fingerprint <> '';
