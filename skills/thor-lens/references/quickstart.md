# Quickstart

Shortest path from a THOR 11 scan to a Lens timeline. Assumes a Linux or macOS analysis
machine; Windows works the same with `thorlens.exe` and `thor64.exe`.

## 1. Get Lens

Lens is distributed by Nextron (private repository / release archives). With a release
archive, unpack it and use `thorlens` directly. From source:

```bash
cd thor-lens            # repository checkout provided by Nextron
make build              # web UI + ./thorlens
./thorlens --version    # thorlens version 0.7
```

Prerequisites: Go 1.26+, Node.js `^20.19.0` or `>=22.12.0`, npm, Make, gcc/clang.

## 2. Produce input with THOR 11

```bash
sudo ./thor-linux-64 --audit-trail -e /cases/web01     # on the host to investigate
```

Results in `/cases/web01/`: `web01_thor_<time>.jsonl` (findings), `.html`, `_files_md5s.csv`
and `web01_thor_audit_<time>.jsonl.zst` (audit trail). Copy the folder to the Lens machine.

No THOR 11? Import a THOR 10.7 JSON log (`--jsonfile=web01.json --jsonv2`) instead: you get
findings only, no clean elements.

## 3. Check the file

```bash
scripts/validate_audit_trail.sh /cases/web01/web01_thor_audit_*.jsonl.zst
```

## 4. Import

```bash
./thorlens import --log /cases/web01/web01_thor_audit_2026-11-16_1004.jsonl.zst --case web01
```

Creates `./cases/web01/` (`meta.json`, `events/month=YYYY-MM-01/part-0000.parquet`, …).

## 5. Serve

```bash
./thorlens serve --case ./cases/web01
```

Open http://127.0.0.1:8080. Remote browser: `ssh -N -L 127.0.0.1:8080:127.0.0.1:8080 user@lens-host`.
Without `--case`, the start page lets you import files in the browser and pick saved cases.

## 6. Sanity checks

```bash
jq '{source_format, source_records, timeline_rows, min_ts, max_ts, hostnames}' cases/web01/meta.json
curl -s http://127.0.0.1:8080/api/meta | jq '{timeline_rows, min_ts, max_ts}'
```

`source_format` must be `audit_trail` (or `thor_log` for JSON logs); `timeline_rows` > 0.

## 7. Optional: connect Claude Code

```bash
claude mcp add --transport http --scope project thor-lens http://127.0.0.1:8080/mcp
```

Keep `thorlens serve` running while the client is connected.

## First-run problems

| Symptom | Fix |
|---|---|
| `make: command not found` / cgo errors | install build tools: `xcode-select --install` (macOS), `build-essential` (Debian/Ubuntu), MinGW-w64 (Windows) |
| Node version error from Vite | Node.js `^20.19.0` or `>=22.12.0` |
| `web interface address 127.0.0.1:8080 is already in use` | `--port 9000` |
| `no THOR records found` | you imported a text log, HTML or CSV; use `.jsonl`/`.json`/audit trail |
| `case … already exists` | `--replace` (keeps the old case as `.replaced-<name>-<UTC>`) |
| Page says built without web interface | rebuild with `make build`, restart `serve`, hard-refresh |
