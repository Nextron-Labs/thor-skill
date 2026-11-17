# Output and reporting flags

Default files, names, exit codes and skip conditions are in the `thor` skill (versions-and-outputs reference).
This file covers the flags you put on a scan command.

## Output directory

`-e DIR` in both versions (v10 `--rebase-dir`, v11 `--output-directory`). Default is the current working directory,
which is `C:\Windows\System32` for scheduled tasks and GPO jobs. Only output names **without** a path separator are
placed into `-e`; a name with a separator is used literally. Both versions create missing directories (mode 0700); the v10
`--audit-trail` file is the exception (create its directory first).
v10 `--audit-trail` is never moved by `-e` and gets no placeholders: give it an absolute path.

Never write output onto the evidence or onto the scanned share; use a separate disk or a results share.

## Per-format flags

| Output | THOR 10.7 | THOR 11 |
|---|---|---|
| Text log | default on; `-l FILE` renames; `--nolog` disables (also the HTML) | off; `-l FILE` / `--text FILE` enables |
| JSON log | `--jsonfile=FILE` or bare `--jsonfile` (v1 schema); add `--jsonv2` for the v2 schema (one finding per line, easier to parse) | on (`.jsonl`, v3); `--json FILE` renames; `--no-json` disables JSON **and** HTML |
| HTML report | on; `--htmlfile FILE`, `--nohtml`; `--include-info-in-html` | on; `--html FILE`, `--no-html`; `--html-include-info` |
| CSV of findings (`md5,path,score`) | on; `-o FILE` (`--csvfile`), `--nocsv` | on; `-o FILE` (`--csv`), `--no-csv` |
| Scan summary CSV | `--stats-file=FILE` | `--stats-csv=FILE` |
| Audit trail | `--audit-trail /abs/HOST_audit.json.gz` (experimental, gzip JSON, value required) | `--audit-trail` (default name in `-e`) or `--audit-trail=FILE` (`.jsonl.zst`) |
| Append instead of overwrite | `--appendlog` | `--log-append` |
| Key/value text format | `--keyval` | `--key-value` |
| Console as JSON / key-value | `--cmdjson` / `--cmdkeyval` | `--console-json` / `--console-key-value` |
| Only Warning/Alert/Error lines | `--reduced` | `--reduced` |
| No console output | `--silent` | `--silent` (v11 also `--no-tui` to keep plain console lines) |

Rules: write v10 `--jsonfile` and `--stats-file`, and v11 `--stats-csv` and `--audit-trail`, with `=` when giving a value.
v11 `--json` needs a value.

## Audit trail

All assessed elements (also clean ones) with relations, for timelines and THOR Lens (`thor-lens` skill). Scope limits
(modules, lookback, excludes) apply; `--min` does not. Log lines, event log entries, registry values and journald entries
are only included when a signature matched or they reference a scanned file. Size: much larger than the normal log.
Not available in THOR Lite (v11 no-op, v10 Lite feature disabled) and not produced in memory dump (DeepDive) mode.
THOR Lens reads the v11 format; do not promise Lens support for v10 audit trails.

## Naming

| | v10 | v11 |
|---|---|---|
| Placeholders | `:hostname:`, `:time:` | `<hostname>`, `<time>` (quote them in shells) |
| Example | `--jsonfile=:hostname:_:time:.json` | `--json "<hostname>_<time>.jsonl"` |
| Hostname in names and lines | `-j HOST` (lab-type license) | same |
| Group runs | `-i CASE42-WKS001` (`--scanid`) | `-i CASE42-WKS001` (`--scan-id`) |

## Syslog, SIEM, local logging

`-s TARGET` (v10 `--syslog`, v11 `--remote-log`), repeatable. Target: `host[:port[:format[:protocol]]]`,
formats `DEFAULT`, `CEF`, `JSON`, `SYSLOGJSON`, `SYSLOGKV`; protocols `UDP` (default), `TCP`, `TCPTLS`. v11 also accepts
`https://host/path[:JSON]`. Examples: `-s 10.0.0.4:514`, `-s siem.corp:6514:DEFAULT:TCPTLS`, `-s arcsight:514:CEF:UDP`.
Message length: v10 `--maxsysloglength`, v11 `--syslog-length-limit` (2048, not for JSON). CEF threshold:
`--cef_level` / `--syslog-cef-level`. `--local-syslog` (local0), `--eventlog` (Windows Application log).
Syslog-only run (v11): `--no-html --no-csv --no-json -s syslog.corp`.

## Timestamps and privacy

| | v10 | v11 |
|---|---|---|
| UTC | `--utc` | `--timestamp-utc` |
| RFC 3339 in text log | `--rfc3339` | `--timestamp-rfc3339` (JSON is always RFC 3339) |
| Anonymise user names | `--suppresspi` / `--brd` | `--no-personal-data` |
| Value truncation | `--truncate 2048` | same |
| More reasons per finding | `--max-reasons 0` | `--alert-reason-limit 0` |
| Lower reporting threshold | `-x 30` (`--min`) | same |
| Log objects regardless of score | `--printshim`, `--printamcache` | `--log-object "TYPE[:LIMIT]"` |
| Hit cap per rule/IOC | `--max-hits` (10,000; 0 = none) | `--match-limit` (100,000; 0 = none) |
| Sigma muting (after 10 matches of one rule) | Notice "Sigma rule triggered more than 10 times"; lifted by `--showall`, `--lab` or hidden `--mute-sigma-rule 0` | Notice "Rule triggered more than 10 times"; live Eventlog module only; lifted by `--lab`, hidden `--show-all` or hidden `--mute-sigma-rule 0` (the Notice's hint `--showall` is not a v11 flag), **not** by `--match-limit 0` |

## Encryption

| | v10 | v11 |
|---|---|---|
| Enable | `--encrypt` (built-in default key) or `--encrypt --pubkey KEY.pem` | `--encryption-key KEY.pem` (alias `--pubkey`), RSA 1024/2048/4096 |
| Decrypt | `thor-util decrypt` | `thor-util decrypt --privkey KEY-private.pem FILE` |
| HTML | not generated | not generated |

The v10 default key gives no confidentiality: its private counterpart ships with `thor-util`. Use your own key pair.

## Sensible defaults by use case

| Use case | v10 | v11 |
|---|---|---|
| Endpoint sweep to a results share | `-e \\fs01\thor-results --utc --jsonfile=:hostname:_thor.json` | `-e \\fs01\thor-results --timestamp-utc` |
| Lab case | `-e /cases/HOST --jsonfile=HOST.json --audit-trail /cases/HOST/HOST_audit.json.gz` | `-e /cases/HOST --audit-trail` |
| SIEM streaming | `-s siem:514:JSON:TCP` | same |
| Parser expects text logs | default | `--text "<hostname>_thor_<time>.txt"` |
