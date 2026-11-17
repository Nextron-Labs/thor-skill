# ThorDB schema

Three tables, identical names in v10 and v11. No other tables, no schema version key.

## Exact DDL

v10 (10.7.x):
```sql
CREATE TABLE `tbl`   (`key` TEXT PRIMARY KEY NOT NULL, `value` TEXT NOT NULL);
CREATE TABLE `stats` (`module` TEXT NOT NULL, `element` TEXT NOT NULL, `started` DATETIME NOT NULL, `duration` INTEGER NOT NULL);
CREATE TABLE `times` (`category` TEXT NOT NULL, `element` TEXT NOT NULL, `duration` INTEGER NOT NULL);
```
v11:
```sql
CREATE TABLE `tbl`   (`key` TEXT PRIMARY KEY NOT NULL, `value` TEXT NOT NULL);
CREATE TABLE `stats` (`module` TEXT NOT NULL, `element` TEXT NOT NULL, `started` DATETIME NOT NULL, `duration` INTEGER NOT NULL);
CREATE TABLE `times` (`category` TEXT NOT NULL, `element` TEXT NOT NULL, `count` INTEGER NOT NULL, `duration` INTEGER NOT NULL);
```
Detect the version of a DB file: `PRAGMA table_info(times);` -> `count` column present = v11.
Any query that names `count` fails on a v10 DB with `no such column: count`.

## Lifetimes

| Table | Created | Cleared | Written |
|---|---|---|---|
| `tbl` | first run | never by THOR | continuously during the scan |
| `stats` | every start (DROP + CREATE) | at every THOR start | during the scan |
| `times` | every start (DROP + CREATE) | at every THOR start | once, at exit, unless THOR crashed or was killed |

So `stats`/`times` describe only the most recent run that used this DB file, including short runs such as a
quick test after the big scan. Copy the DB right after the run you want to analyse. A run with ThorDB
disabled (`--lab`, dropzone, `--no-thordb`) leaves the file untouched.

## `tbl`

Encrypted key/value store: every key segment and every value is stored as hex ciphertext, so SQL can only
count rows (`SELECT count(*) FROM tbl`; also logged as ENTRIES in `Successfully opened ThorDB`).
Logical content (not queryable): scan context and start/finish times per context, scan ID, per-module
start/finish/duration, Filescan resume position, and delta baselines for Autoruns, services, hosts file
entries, authorized_keys and ShimCache. There are no keys like `schema_version`, `resume_*` or `diff_*`.

## `stats`

| Column | Meaning |
|---|---|
| `module` | Module name (`Filescan`, `Eventlog`, `ProcessCheck`, ...) |
| `element` | `Whole Module` for the module total (only if the module finished), otherwise a scan root, a directory, or an event log name |
| `started` | UTC start time stored as text, e.g. `2026-11-16 09:14:02.123456789+00:00` (use `datetime(started)`; `'unixepoch'` returns NULL) |
| `duration` | Whole seconds (truncated) |

Rows written: one `Whole Module` row per completed module; Filescan rows per scan root and per directory
down to depth 2 **or** any directory that took at least 20 s (that is how deep slow folders show up);
Windows Eventlog rows per event log.

## `times`

| Column | Meaning |
|---|---|
| `category` | v10: `feature_scan`, `deep_scan`, `bulk_scan`; v11: `hook`, `deep_scan`, `bulk_scan` |
| `element` | The reason/rule/hook text (see below) |
| `count` | v11 only: how often this reason fired |
| `duration` | Total time attributed, in **nanoseconds** (`duration/1e9` = seconds) |

At most ~101 rows per category (the top entries by duration).

| Category | Element is | Meaning of the time |
|---|---|---|
| `deep_scan` | a DEEPSCAN selector meta rule (file type / extension / magic based) that caused a full content scan | time spent deep-scanning files selected by that selector |
| `bulk_scan` | a rule or IOC that caused a chunk of data (bulk) to be checked in detail | time of those detailed checks |
| `feature_scan` (v10) | a meta rule that triggered a feature scanner | time of those feature scans |
| `hook` (v11) | an internal processing step (e.g. "check if maximum file size is exceeded", "bulk scan") | time spent in that step |

None of this is per-YARA-rule cost. A large `deep_scan` total means many or large files of that type were
content-scanned; the answer is usually excluding a folder or accepting the cost, not filtering the selector
(filtering it stops deep scanning that file type). The same data is printed at scan end with the hidden flag
v10 `--bulkstats` / v11 `--statistics`.
