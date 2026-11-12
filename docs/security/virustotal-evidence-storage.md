# VirusTotal evidence persistence

## Separation from the local verdict

VirusTotal assessments are persisted independently from the ClamAV scan
verdict. The `scan_history` row remains the authoritative local result:
its status, engine, threats and error fields are not rewritten by a remote
assessment.

Schema version 2 adds `scan_intelligence`, keyed by `scan_id` and linked to
`scan_history(id)` with `ON DELETE CASCADE`. Each row records:

- provider and the explicitly selected API profile (`public` or `premium`);
- the SHA-256 digest used for the lookup;
- the UTC observation timestamp for the scan's enrichment step;
- lookup provenance and a bounded status (`found`, `not_found`, `error`);
- the normalized VirusTotal response as JSON metadata.

## Atomicity and lifecycle

`record_scan()` validates the optional JSON evidence envelope and inserts the
scan row, threat rows and intelligence row in one SQLite transaction. A
malformed or oversized optional envelope is ignored; it cannot invalidate an
otherwise valid ClamAV history record. The remote metadata column is bounded
to 64 KiB.

Deleting a scan, clearing history or purging matching scans cascades to the
associated intelligence row. The public history contract exposes
`get_scan_intelligence(scan_id)` so consumers can retrieve the remote
assessment without conflating it with `HistoryRecord.status`.

## Migration compatibility

The migration from schema version 1 to version 2 is transactional and only
creates the new table and its indexes. Existing scan history and threat rows
are retained. A database with a newer schema version is still rejected rather
than opened with potentially incompatible assumptions.

Existing v1 scan and threat rows remain untouched. Legacy stringified
VirusTotal metadata is not automatically promoted into the new table because
older records do not reliably contain an explicit API profile, observation
timestamp and provenance. The migration does not infer those values from an
API key or response shape; legacy scans therefore return no separate
intelligence record unless a valid evidence envelope was recorded.
