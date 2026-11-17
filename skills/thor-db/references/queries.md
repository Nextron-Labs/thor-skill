# Read-only ThorDB queries

All queries are SELECTs. Run them on a copy, opened read-only:
```sh
sudo cp /var/lib/thor/thor.db /tmp/thordb-copy.db && sudo chown "$USER" /tmp/thordb-copy.db   # v10: thor10.db
sqlite3 -header -column 'file:/tmp/thordb-copy.db?mode=ro'
```
Windows: copy `C:\ProgramData\thor\thor.db` from an elevated shell and open the copy with the sqlite3 CLI or
"DB Browser for SQLite" (read-only mode). Remember: `stats` and `times` hold only the **last** run.

## Which schema?

```sql
SELECT name FROM pragma_table_info('times');   -- 'count' listed = v11 schema, missing = v10
SELECT category, COUNT(*) AS rows FROM times GROUP BY category;   -- v10: feature_scan/deep_scan/bulk_scan, v11: hook/deep_scan/bulk_scan
SELECT COUNT(*) AS encrypted_entries FROM tbl; -- the only useful query on tbl
```

## stats (both versions)

Module totals of the last run:
```sql
SELECT module, duration AS seconds, datetime(started) AS started_utc
FROM stats WHERE element = 'Whole Module'
ORDER BY duration DESC;
```

Slowest directories / roots / event logs:
```sql
SELECT module, element, duration AS seconds, datetime(started) AS started_utc
FROM stats WHERE element <> 'Whole Module'
ORDER BY duration DESC LIMIT 25;
```

Directories that took at least 10 minutes (exclusion candidates):
```sql
SELECT element, duration/60 AS minutes FROM stats
WHERE module = 'Filescan' AND element <> 'Whole Module' AND duration >= 600
ORDER BY duration DESC;
```

Timeline of the run (start and end per row):
```sql
SELECT module, element, datetime(started) AS start_utc,
       datetime(started, '+' || duration || ' seconds') AS end_utc
FROM stats ORDER BY started;
```

Directory rows nest (a root contains its subdirectories), so do not sum `element` durations to get a total;
use the `Whole Module` rows.

## times (both versions, no `count`)

```sql
SELECT category, element, ROUND(duration/1e9, 1) AS seconds
FROM times ORDER BY duration DESC LIMIT 20;

SELECT category, COUNT(*) AS entries, ROUND(SUM(duration)/1e9, 1) AS seconds
FROM times GROUP BY category ORDER BY SUM(duration) DESC;

SELECT element, ROUND(duration/1e9, 1) AS seconds
FROM times WHERE category = 'deep_scan' ORDER BY duration DESC LIMIT 20;
```

## times (v11 only: `count`)

```sql
SELECT category, element, count, ROUND(duration/1e9, 1) AS seconds,
       ROUND(duration*1.0/count/1e6, 2) AS avg_ms
FROM times WHERE count > 0 ORDER BY duration DESC LIMIT 20;
```
On a v10 DB this fails with `no such column: count`.

## Interpreting results

| Finding | Meaning | Action |
|---|---|---|
| One Filescan directory dominates `stats` | Huge or slow folder (mail store, VM images, backups, container layers) | Exclude it (v10 `config/directory-excludes.cfg`, v11 `--exclude-path`) if acceptable for the investigation |
| `Whole Module` missing for a module | Module did not finish (abort, CTRL+C) or ThorDB was reset by a later run | Check the scan log end |
| Large `deep_scan` entry | Many files of that type were content-scanned | Expected cost; exclude folders, do not filter the selector |
| Large `bulk_scan` entry from a custom IOC/rule | Expensive custom signature | Rewrite or narrow that custom rule (`thor-custom-signatures` skill) |
| `times` empty, `stats` filled | Run was killed/crashed (times are written at exit) or still running | Use `stats`, or rerun |
| Both empty | Last run had no ThorDB activity (e.g. a quick test run after the scan) or is still starting | Copy the DB right after the run of interest |

## Not possible with SQL

- Reading resume position, scan context, scan ID, delta baselines: all in encrypted `tbl`.
- Per-YARA-rule runtime: not recorded.
- History of earlier runs: `stats`/`times` are recreated at every start.

Never run `DELETE`, `UPDATE`, `DROP` or `VACUUM` on a user's ThorDB: `stats`/`times` are recreated anyway
and changing `tbl` destroys resume state and delta baselines.
