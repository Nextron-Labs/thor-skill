---
name: thor-db
description: Explains and safely inspects THOR's SQLite state database ThorDB (v10 thor10.db / thor10-lite.db, v11 thor.db): default locations per OS and user, --thordb-path/--dbfile, disabling it (--nothordb, --no-thordb, --exclude-component ThorDB), scan resume (--resume, --resume-scan, --resume-only), delta scans (--diff, --delta), and the plaintext timing tables stats and times of the last run. Use when users ask where thor.db or thor10.db is, why --resume did not resume, why lab scans cannot resume, what the database contains, how to find slow folders or modules, or want to query ThorDB with sqlite3. Includes read-only Python scripts that work on both schemas.
compatibility: THOR 10.7.x and THOR 11. Scripts need Python 3.8+ (stdlib sqlite3) and read access to the DB file (usually root/Administrator).
metadata:
  author: Nextron Systems
  version: "2.0"
---

# ThorDB

ThorDB is a small SQLite file THOR keeps between runs for: resume state, per-module last-run times
(delta scans), baselines for "new entry" checks (Autoruns, services, hosts file, authorized_keys,
ShimCache), and timing statistics of the **last** run. It is not a findings database: findings live only in
the scan logs.

Scope rules for answers:
- Most of the DB (`tbl`) is encrypted. Never promise to read resume state, baselines or settings with SQL.
- Only `stats` and `times` are plaintext, and both are dropped and recreated at **every** THOR start.
- Never write to, vacuum or "clean" a user's ThorDB. Open it read-only, preferably a copy.

## 1. File name and location

| | v10 (10.7.x) | v11 |
|---|---|---|
| File name | `thor10.db`; Lite `thor10-lite.db` | `thor.db`; Lite intended `thor-lite.db` (some 11.0.0 Lite builds still use `thor.db`; check the log line below) |
| Windows | `C:\ProgramData\thor\thor10.db` (also when not elevated) | admin: `C:\ProgramData\thor\thor.db`; non-admin: `%LOCALAPPDATA%\thor\thor.db` |
| Linux | `/var/lib/thor/thor10.db`; as non-root not writable -> ThorDB disabled with an Error | root: `/var/lib/thor/thor.db`; non-root: `~/.local/state/thor/thor.db` (`$XDG_STATE_HOME`) |
| macOS | `/var/lib/thor/thor10.db` (same rule as Linux) | root: `/var/lib/thor/thor.db`; non-root: `~/Library/Application Support/thor/thor.db` |
| AIX | `/var/lib/thor/thor10.db` | `/var/lib/thor/thor.db` |
| Custom path | `--dbfile <file>` | `--thordb-path <file>` (alias `--dbfile`) |

The path must be a **file**. A directory fails ("unable to open database file") and the scan runs without
ThorDB, i.e. no resume, no delta. Missing parent folders are created.

Authoritative answer for a given run: the Init line `Successfully opened ThorDB` (PATH, ENTRIES) or
`Successfully created ThorDB` (PATH). Errors: `Could not open ThorDB`, `ThorDB database is not writable`,
`Could not create ThorDB table` -> scan continues without ThorDB.

Non-admin v11 runs use a per-user DB, so an elevated and a non-elevated run of the same scan use different
DBs: resume and delta only work within the same user context.

## 2. Turning it off and when it is off

| | v10 | v11 |
|---|---|---|
| Disable for one run | `--nothordb` | `--no-thordb` (hidden alias `--nothordb`) or `--exclude-component ThorDB` |
| Automatically off | `--lab`, `--dropzone`, `--thunderstorm` | `--lab`, `--dropzone`, `--http-server` |

Disabling does not delete anything; the existing file stays as it was. Consequence of "off": no resume,
no delta, no timing tables. Test runs that must not touch the user's DB: disable it or use a scratch file
(`--thordb-path /tmp/test-thor.db`).

## 3. Resume

| | v10 | v11 |
|---|---|---|
| Flags | `--resume`, `--resumeonly` | `--resume-scan` (alias `--resume`), `--resume-only` (hidden alias `--resumeonly`) |
| First run | must already have `--resume` (position tracking is off by default since 10.5) | must already have `--resume-scan` to survive kills, crashes, reboots |
| Matching | all set flags except output/log/run options (log and report names, output dir, `--debug`, `--trace`, timeout, ThorDB path, license path, scan ID, ...) are hashed into a context key; order does not matter, any other change (paths, modules, threads, modes) means "different scan" | same |
| What is skipped | modules that finished in the interrupted run; Filescan directories before the stored position | same |
| Position granularity | directory, stored only for directories down to a few levels; elements after the last stored directory are scanned again, some queued elements may be skipped (gaps by design) | same |
| Clean stop (E/Q, timeout, resource control, SIGTERM) | known limitation: the Filescan position is overwritten with the value read at start, so the Filescan restarts at the beginning (finished modules are still skipped) | current position stored, message `Stored current position for resume` |
| Hard kill / power loss | last stored directory survives (only with `--resume`) | same (only with `--resume-scan`) |
| Nothing to resume | normal new scan (`--resume`), or nothing done (`--resumeonly`) | `Previous scan completed successfully; starting a new scan`; `--resume-only` logs `No previous scan with same context, stopping scan due to --resume-only flag` and scans nothing |
| Scan ID | reused: `Recovered previous Scan ID` | reused: `Recovered previous scan ID` |

Recommended command pattern: put the resume flag into the **original** command (or `resume: true` into the
scan template) and rerun exactly the same command after an interruption.

```
thor64.exe --resume -p C:\ -e C:\thor-out                    (v10)
thor64.exe --resume-scan -p C:\ --output-directory C:\thor-out   (v11)
```

Why resume "did not work", in order: ThorDB disabled (lab/dropzone/`--no-thordb`/unwritable path) ->
first run lacked the resume flag -> scan-relevant arguments differ -> a run without the resume flag came in
between (v11 resets the Filescan position) -> different DB (other user, `--thordb-path`) -> v10 clean stop
limitation above -> the previous scan actually completed.

## 4. Delta scans

v10 `--diff`, v11 `--delta` (alias `--diff`): for each module, set the lookback to the last time that module
completed successfully (recorded in ThorDB) and apply it globally. No previous completed run -> Info
`Ignoring diff mode since module didn't complete in previous THOR scans` (v10) and a full scan of that module.
Needs ThorDB, so it does not work in lab/dropzone mode or with ThorDB disabled. Deleting the DB resets
all delta baselines, including "new Autoruns/services/hosts entry" detections.

## 5. Reading the timing tables

Tables (exact DDL in [references/schema.md](references/schema.md)):

| Table | Content | Version differences |
|---|---|---|
| `tbl` | encrypted key/value store (resume, baselines, module times) | unreadable by design |
| `stats` | module, element, started, duration (whole seconds): `Whole Module` rows, scan roots, directories down to depth 2 or taking >= 20 s, event logs (Windows) | same in both |
| `times` | category, element, duration (nanoseconds), top ~100 per category, written at clean exit only | v10: no `count` column, categories `feature_scan`, `deep_scan`, `bulk_scan`; v11: `count` column, categories `hook`, `deep_scan`, `bulk_scan` |

Interpretation: `deep_scan` elements are DEEPSCAN selector rules (the time is spent scanning the files they
selected); `bulk_scan` elements are rules/IOCs that made a chunk be scanned in detail; v11 `hook` elements
are internal processing steps. None of these are "slow YARA rules" to filter: excluding a DEEPSCAN selector
(v10 `--init-filter`, v11 `--signature-exclude`) silently stops deep scanning of that file type and costs
detection. Use the numbers to find expensive folders and file types, then exclude folders or accept the cost.

Safe access (copy first; THOR may hold the file and the folder is root-only):
```sh
sudo cp /var/lib/thor/thor.db /tmp/thor-copy.db && sudo chown "$USER" /tmp/thor-copy.db
sqlite3 'file:/tmp/thor-copy.db?mode=ro' "SELECT module, element, duration FROM stats ORDER BY duration DESC LIMIT 20;"
```
More queries for both versions: [references/queries.md](references/queries.md).

## 6. Scripts (read-only, Python 3.8+, both schemas)

| Script | Purpose |
|---|---|
| `scripts/thor_db_summary.py DB` | Detects v10/v11 schema, slowest modules and directories, `times` per category with interpretation |
| `scripts/thor_db_top_times.py DB [-n 20] [-c deep_scan]` | Top entries of `times`, average per call where `count` exists |
| `scripts/thor_db_export_csv.py DB -t stats|times|all [-o DIR] [--json]` | Export the plaintext tables |

All accept `--copy` (read a temporary copy; use while THOR runs) and `--help`. They open the DB with
`mode=ro` and never write to it. `tbl` is not exported (encrypted).

## 7. Things not to do

- Do not delete or edit ThorDB to "speed up" THOR; it is tiny and rewritten each run. Deleting it drops
  resume state and delta baselines. If a fresh state is really wanted, let the user move the file aside.
- Do not run `strings`/`strace` against THOR to find the DB name; read the Init log line.
- Do not expect `stats`/`times` while a scan is running (`times` is filled at exit) or from lab scans.
- ThorDB is included in `thor-util diagnostics` packs (default path only); treat it as host data.

## References

- [references/locations.md](references/locations.md) - paths per version/OS/user, permissions, finding the DB of a given run.
- [references/schema.md](references/schema.md) - exact CREATE TABLE statements, column semantics, lifetimes.
- [references/queries.md](references/queries.md) - read-only SQL that works on v10 and v11.

Related skills: `thor-troubleshooting` (slow/stuck/aborted scans), `thor-scan` (command lines with
resume/delta flags).
