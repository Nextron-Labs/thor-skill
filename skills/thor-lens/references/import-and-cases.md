# Import and cases

## `thorlens import`

```bash
thorlens import (--log FILE ... | --log-dir DIR) --case NAME [options]
```

| Option | Meaning |
|---|---|
| `--log`, `-l` | input file; repeat for several files. A comma is part of the path (no CSV lists) |
| `--log-dir` | import every supported file directly in DIR (non-recursive): `.jsonl`, `.json`, `.log` and their `.gz`/`.zst`/`.zstd` copies; if a plain and a compressed copy exist, the plain one wins |
| `--case`, `-c` | case **name** (required). No path separators; must be a valid Windows folder name (no `< > : " \| ? *`, no trailing dot, no `CON`/`NUL`/`LPT1`…); no `[`, `]` or `=` |
| `--cases-dir` | case root (default `./cases`) |
| `--workers`, `-w` | 1–64, default 4 |
| `--replace` | replace an existing case after a successful staged import; old case kept as hidden sibling |
| `--discard-previous` | with `--replace`: delete the old case (and its notes) instead of keeping it |
| `--log-timezone` | IANA zone or `Local` (default) for zone-less timestamps extracted from log lines |

Global: `--debug`. Exit codes: 0 ok, 1 failure (`Error: …` on stderr), 2 usage error.

Examples:

```bash
thorlens import --log ./web01_thor_audit_2026-11-16_1004.jsonl.zst --case web01
thorlens import --log host1.jsonl --log host2.jsonl.gz --case campaign
thorlens import --log-dir /collect/thor --case campaign --workers 8
thorlens import --log ./audit.jsonl.zst --case web01 --log-timezone Europe/Berlin
thorlens import --log ./audit-rescan.jsonl.zst --case web01 --replace
thorlens import --log ./x.jsonl --case web01 --cases-dir /srv/lens-cases
```

## Format detection and input rules

- Format from content (first record): `type` = `THOR audit record`/`THOR audit message` →
  audit trail; `log_version`/`module`/v3 `meta` → standard THOR JSON log; `id`+`object`
  without `type` → legacy audit trail (early THOR 11 builds).
- Compression from magic bytes (gzip, zstd), not from the extension. A `.gz`/`.zst` name with
  plain content is rejected (`the name ends in .gz, but the content is not Gzip data`).
- Rejected: text logs, HTML, CSV (`no THOR records found`), pretty-printed JSON or JSON arrays
  (convert: `jq -c '.[]' in.json > out.jsonl`), UTF-16 (PowerShell `>` redirect; convert with
  `iconv -f UTF-16 -t UTF-8`), binary/archives (`binary input is not supported` — unpack ZIP/TAR
  first), pipes, `/dev/stdin`, process substitution (`is not a regular file`).
- Non-THOR lines next to THOR records are kept as unparsed records (counted, not fatal).
  Lines > 64 MiB are stored truncated with an `oversize_line` diagnostic.
- Import is staged in a hidden directory and published only when complete. Ctrl-C deletes
  the staging directory and creates nothing.

## How records become timeline rows

- One source record → one timeline row per timestamp (`time_kind` such as `MODIFIED`,
  `CREATED`, `LASTRUN`, …). `timeline_rows` ≥ `source_records`.
- Records without a usable timestamp are kept: `UNTIMED`, or "observed only" when only the
  scan time (`OBSERVED` / v3 `meta.time`) is known. Scan time is never treated as event time.
- Unset sentinel dates are excluded (Windows 2185-07-21…, OLE 1899-12-30, DOS 1979-11-30);
  1980-01-01 stays (real archive dates). Other odd years (1601, 1970) still appear: artifact
  metadata, not attacker activity.
- Audit records carry no total score; Lens derives it from positive reason scores. JSON logs
  keep THOR's score.
- Event IDs are deterministic (case name, source file name, line, content, time) and stay the
  same when the same files are imported again under the same case name.

## Case layout

```text
cases/<name>/
├── meta.json                 import metadata (read-only after import)
├── events/month=YYYY-MM-01/part-0000.parquet     timeline events (immutable)
├── annotations.sqlite        tags, comments, bookmarks, selections, exclusions, AI assessments, dispositions
├── agent_status.sqlite       agent runs, traces, steps
├── ui_config.json            timeline settings (after saving in Settings)
├── import_diagnostics.jsonl  per-line import problems (only when there are any)
└── .thorlens.lock            advisory lock while a service has the case open
```

Network-received cases: `events/batches/<batch>/month=…/part-0000.parquet` plus `.live/`;
their raw receive session lives in `cases/.incoming/<name>/`. Hidden work directories
(`.uploads/`, `.<name>.import-*`, `.thorlens-removing-*`) are cleaned up by `serve` after 24 h.

## meta.json fields that matter

| Field | Meaning |
|---|---|
| `case_name`, `tool_version`, `import_time` | identity |
| `source_format` | `audit_trail` or `thor_log` |
| `source_file`, `source_files` | input file(s) |
| `hostnames` | hosts seen (audit trail: from the `System Information` startup message) |
| `source_records` | THOR records read |
| `timeline_rows` | rows after timestamp expansion |
| `untimed_rows`, `observation_only_rows`, `fully_untimed_rows` | rows without timeline time |
| `min_ts`, `max_ts` | time range of the timeline |
| `object_type_counts` | rows per object type |
| `parse_errors`, `fallback_lines`, `blank_lines`, `import_diagnostics` | input problems |
| `log_timezone`, `log_timezone_resolved` | zone used for zone-less log-line times |
| `ingestion` | network/scan evidence: `network_received`, `lifecycle`, `health`, `completeness`, `identified_scans`, … |

There are no `event_count`, `min_time` or `max_time` keys; checks that read them always
report 0/null.

```bash
jq '{source_format, source_records, timeline_rows, min_ts, max_ts, hostnames, parse_errors}' cases/web01/meta.json
jq -r '.object_type_counts | to_entries | sort_by(-.value)[:10][] | "\(.value)\t\(.key)"' cases/web01/meta.json
scripts/case_inventory.sh cases/web01      # everything above + partitions + note counts
```

## Replacing a case

`import` refuses an existing name. `--replace`:

1. imports into staging; on failure the old case is untouched;
2. refuses if a running Lens service has the case open (close/deactivate it first);
3. renames the old case to `cases/.replaced-<name>-<UTC>` (printed in the summary).

Carry notes over (stop `serve` first, before opening the new case):

```bash
cp cases/.replaced-web01-20261116T101500Z/annotations.sqlite* \
   cases/.replaced-web01-20261116T101500Z/agent_status.sqlite* cases/web01/
```

Notes match only events whose ID did not change (same file names and content). Delete the
kept directory when done; it still uses the full disk space. `--discard-previous` skips the
backup (notes lost).

## Deleting a case

Start page → trash button (confirmation, cannot be undone, also deletes the receive session
of a network case). Or stop all services and `rm -r cases/<name>`. Original THOR files outside
the case folder are never touched.
