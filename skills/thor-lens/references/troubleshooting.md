# Troubleshooting

Start with facts, not guesses:

```bash
./thorlens --version
scripts/validate_audit_trail.sh INPUTFILE          # format, integrity, host, version
scripts/case_inventory.sh ./cases/<name>           # meta.json, partitions, notes
curl -s http://127.0.0.1:8080/api/meta | jq '{case_name, source_format, timeline_rows, min_ts, max_ts}'
```

Run with `thorlens --debug …`; logs go to stderr. Do not paste raw log or audit-trail head
lines into tickets (license owner); the scripts above are safe to share.

## Import errors

| Message / symptom | Cause | Fix |
|---|---|---|
| `no THOR records found` | text log (`.txt`), HTML, CSV, THOR 10 audit trail | use THOR 11 `--audit-trail` output or a JSON log (`.jsonl`; v10 `--jsonfile`) |
| `no input records found` | empty or whitespace-only files | check the scan finished; `ls -l`, `zstd -t` |
| `unsupported JSON document format: expected newline-delimited JSON objects` | pretty-printed JSON or array | `jq -c '.[]' in.json > out.jsonl` |
| `the name ends in .gz, but the content is not Gzip data` (also `.zst`) | wrong suffix | rename to `.jsonl` |
| `gzip data is truncated` / zstd error with file and line | incomplete copy or scan still running | recopy; wait for the scan to end (`zstd -t`) |
| `UTF-16 input is not supported; convert to UTF-8` | PowerShell `>` redirect | `iconv -f UTF-16 -t UTF-8 in > out` |
| `binary input is not supported: the content is a ZIP archive` | collected archive | unpack, import the log inside |
| `… is not a regular file (pipes and devices are not supported)` | `<(…)`, `/dev/stdin` | write to a file first |
| `case already exists` | name in use | `--replace` (keeps `.replaced-<name>-<UTC>`) or another name |
| `--replace` refused, case open | a service has the case open | close it in the UI or stop that `serve` |
| case name refused | path separator, `< > : " \| ? * [ ] =`, trailing dot, `CON`/`NUL`… | pick a plain name |
| import slow | large file, slow disk | local SSD, `--workers 8`; zstd input is fine |

## Empty or wrong timeline

| Check | Meaning |
|---|---|
| `meta.json` `timeline_rows` = 0 | nothing imported: wrong file, see above |
| `source_format` = `thor_log` but you expected a full timeline | you imported the findings JSON, not the `*_thor_audit_*.jsonl.zst` |
| Hosts show the analysis machine, paths `/mnt/image/…` | image scanned without `-j` / `--path-remap` (needs a lab-type license): rescan |
| Very few files in an audit trail | scope was restricted (`-a`, `-p`, excludes, `--lookback`) or `--lab` was used on a live host (Filescan only) |
| No log lines / registry values | by design: those appear in the audit trail only when matched or referencing a scanned file |
| UI empty but `/api/meta` has rows | filters: reset time range to all, clear search, check exclusion filters and the "detections only"/host filters |
| Rows at 1601/1899/1970/2106 | artifact metadata dates; use the histogram brush or presets to focus |
| Old UI after rebuild | stop the old `serve`, start the new binary, hard-refresh |
| Placeholder page "built without its web interface" | binary built with plain `go build`; run `make build` |
| Annotations gone after `--replace` | copy `annotations.sqlite*` and `agent_status.sqlite*` from `.replaced-<name>-<UTC>` (stop `serve` first) |

Never verify with `.event_count`, `.min_time`, `.max_time`: those keys do not exist.

## Serve errors

| Message | Fix |
|---|---|
| `web interface address 127.0.0.1:8080 is already in use` | stop the other process (`lsof -i :8080`, Windows `netstat -ano \| findstr :8080`) or `--port 9000` |
| `case <name> is already open by another THOR Lens process` | close the case in that service or stop it; another port does not help |
| `Could not take the case lock` (warning) | case on FAT/exFAT or a share without locking; works, but two services are not detected |
| `upgrade annotations schema: database is locked` / `readonly database` | another program holds the SQLite file, or `annotations.sqlite`, `-wal`, `-shm` are read-only |
| `annotations.sqlite has schema version N, but this THOR Lens build supports versions 0 to M` | open with the newer Lens build |
| 403 from the browser | you are not using `127.0.0.1`/`localhost` (reverse proxy, LAN IP): use an SSH tunnel |
| Remote colleague cannot open the UI | loopback-only by design: SSH tunnel (`-L 127.0.0.1:8080:127.0.0.1:8080`) |
| Disk filling in `cases/` | hidden `.uploads/`, `.<name>.import-*`, `.thorlens-removing-*` (auto-cleaned after 24 h) and `.replaced-*` (kept until you delete them) |

## MCP problems

| Symptom | Cause / fix |
|---|---|
| Client shows no tools (HTTP) | `serve` not running, wrong port, or no case open (503 `no case is active`): open a case |
| 404 after it worked | the case was closed/switched; the client must re-initialize (reconnect) |
| `/mcp/sse` returns 404 | legacy SSE is off; use `/mcp`, or start with `--mcp-legacy-sse` |
| stdio: `--case is required when --mcp-stdio is used` | add `--case /abs/path/to/cases/<name>` |
| stdio: spawn error / ENOENT | use absolute paths for binary and case; binary executable; on macOS remove quarantine if downloaded |
| Remote client cannot connect | the endpoint is loopback only: tunnel first, keep the SSH session open, check the local forward port is free |
| `tool call exceeded 120s` | narrow `from`/`to`, `min_score`, `object_type`, smaller `limit` |
| Result too large (256 KiB) | smaller `limit`, `max_raw_bytes`, time range |
| `--mcp-port 0` set | MCP disabled; agent runs also refuse (503) |

Check the configuration file is valid JSON (`jq . .mcp.json`) and restart or reload the client
after changes. Verify by asking the client to call `get_case_info`.
