---
name: thor-lens
description: Builds, imports, serves and queries THOR Lens (thorlens), Nextron's local forensic timeline web UI and MCP server for THOR results. Use when the user wants a timeline or case view of THOR output, asks how to import a THOR 11 audit trail (--audit-trail, *_thor_audit_*.jsonl.zst) or THOR JSON logs (.jsonl/.json, also .gz/.zst, THOR 10 v1/v2 and THOR 11 v3) into a case, run `thorlens import`/`thorlens serve`, use --replace, --log-dir, cases/<name>/meta.json, Parquet month= partitions, reach the UI through an SSH tunnel, receive THOR logs over the network (--ingest-listen, --remote-log host:port:JSON:TCP), or connect Claude Code, Codex or another MCP client to http://127.0.0.1:8080/mcp. Also covers which THOR flags produce Lens-compatible output (v11 audit trail vs v10 audit trail, Lite) and fixing empty timelines, import errors and MCP connection problems.
compatibility: THOR Lens 0.7 (build needs Go 1.26+, Node.js ^20.19.0 or >=22.12.0, a C compiler). Full timeline input requires THOR 11; THOR 10.7 and THOR Lite JSON logs import as findings-only timelines.
metadata:
  author: Nextron Systems
  version: "2.0"
---

# THOR Lens

THOR Lens (`thorlens`) turns THOR output into a local investigation workspace: immutable
timeline events in Parquet (queried with DuckDB), analyst notes in SQLite, a React web UI
and an MCP server. It does not scan. THOR produces the data; Lens imports or receives it.

## When to use Lens

| Situation | Use |
|---|---|
| Reconstruct what happened on a host over time, incl. clean files, autoruns, services, references between elements | Lens with a **THOR 11 audit trail** |
| Triage findings of one or many hosts in one timeline, tag/comment/bookmark, export CSV/HTML | Lens with **THOR JSON logs** (v10 or v11) |
| Collect THOR 11 results live from many hosts during an incident | Lens network receiver (`--ingest-listen`) + THOR `--remote-log …:JSON:TCP` |
| Let an AI assistant query the case | Lens MCP server |
| Just read a few findings, explain a THOR line | the `thor-log-analysis` skill, not Lens |

## Get and build

- Lens is not a public download. The source repository is private: **get Lens (release
  archive or repository access) from Nextron**. Release archives exist for Linux amd64,
  Windows amd64 and macOS arm64; Linux arm64 and Intel macOS must build from source.
- Build from source: `make build` → `./thorlens` with the web UI embedded. Needs Go 1.26+,
  Node.js `^20.19.0` or `>=22.12.0` with npm, Make, and a C compiler (gcc/clang; MinGW-w64
  gcc on Windows) because DuckDB and SQLite use cgo. A plain `go build` without the UI build
  serves only a placeholder page (API and MCP still work).
- Check: `./thorlens --version` (e.g. `thorlens version 0.7`). Details:
  [build-and-prereqs](references/build-and-prereqs.md).

## Pick the right input

| Input | Produced by | Lens result |
|---|---|---|
| Audit trail `<hostname>_thor_audit_<time>.jsonl.zst` | THOR 11 `--audit-trail` | Full timeline: every assessed element, all its timestamps, parent/child references |
| JSON log v3 `<hostname>_thor_<time>.jsonl` | THOR 11 (default output) | Findings-only timeline (plus default-logged objects) |
| JSON log v1/v2 `.json` | THOR 10.7 `--jsonfile` (`--jsonv2` for v2) | Findings-only timeline |
| Live stream | THOR 11 `--remote-log <lens>:<port>:JSON:TCP` | Network-received case, queryable while scans run |
| Not importable | text log (`.txt`), HTML, CSV, THOR 10 `--audit-trail` (gzip, different schema) | Import fails (`no THOR records found`) |

- **THOR Lite** (v10 and v11) cannot write an audit trail; its JSON logs import as a
  findings-only timeline.
- Compression is detected by content: plain, gzip and zstd are all accepted; the name does not matter.
- Mixed inputs (several hosts, audit trail + JSON) can go into one case.

## Generate THOR output (v11)

The audit trail is an extra output file, not a scan mode. It needs no special license. It is
always zstd-compressed JSON Lines, whatever name you give it. `--audit-trail` takes an
optional value: write it bare (default name in the output directory) or as
`--audit-trail=<file>`, never `--audit-trail <file>`.

```bash
# Live Linux host: full scan, all outputs plus audit trail into one folder
sudo ./thor-linux-64 --audit-trail -e /cases/$(hostname -s)
# Windows (elevated)
thor64.exe --audit-trail -e C:\cases\%COMPUTERNAME%
# Quick restricted test run (does not touch the default ThorDB)
sudo ./thor-linux-64 -a Filescan -p /home/user --audit-trail --no-thordb -e /tmp/lens-test \
  | grep -v -e LICENSE_OWNER -e 'License file found' -e 'Scan Information'
```

- **Do not add `--lab` for a live system.** `--lab` restricts THOR to the Filescan module (no
  processes, registry, event logs, services …), needs a lab-type license (Forensic Lab, Incident
  Response or Trial) and is meant for mounted images and evidence copies.
- Mounted image (lab-type license): `--lab -p /mnt/image --path-remap /mnt/image:C
  --target-os windows -j ORIGHOST --audit-trail -e /cases/ORIGHOST`. `-j`, `--path-remap`
  (alias `--virtual-map`) and `--lab` are refused by other licenses.
- Scope flags (`-a`, `--exclude-path`, `--lookback`, `--timeout`) limit the audit trail; output
  filters such as `--min` do not. Log lines, event log/journald/audit-log entries and registry
  keys/values appear only if something matched or they reference a scanned file.
- `--no-personal-data` and `--encryption-key` apply to the audit trail; `--log-size-limit` does
  not. Plan disk space: an audit trail holds a record for every scanned element.
- THOR 10.7: use `--jsonfile=<file>` (optional-value flag, always with `=`) and `--jsonv2`.
  Its `--audit-trail` writes a schema Lens cannot read.

More: [audit-trail-generation](references/audit-trail-generation.md).

## Validate before import

```bash
scripts/validate_audit_trail.sh /cases/host1/host1_thor_audit_2026-11-16_1004.jsonl.zst
```

It checks compression and integrity, classifies the format, prints host, THOR version and
scan ID, and never prints raw lines. Manual checks:

```bash
zstd -t FILE                                    # integrity (gzip -t for .gz)
zstd -dcq FILE | jq -c 'select(.type=="THOR audit record") | {id, t: .object.type, ts: .timestamps}' | head -3
```

**Never `head`/`zcat` the first lines of a THOR log or audit trail into a chat or ticket**: the
startup messages contain the licensee name and e-mail (`License file found … OWNER: …`, and in
THOR 11 JSON logs and audit trails the `Scan Information` message with `license.owner`). Filter
with `grep -v -e LICENSE_OWNER -e 'License file found' -e 'Scan Information'`, or in jq select
`THOR audit record`/`THOR assessment` types only.

## Import

```bash
./thorlens import --log /cases/host1/host1_thor_audit_2026-11-16_1004.jsonl.zst --case host1
./thorlens import --log host1.jsonl --log host2.jsonl --case campaign        # one cross-host case
./thorlens import --log-dir /collect/results --case campaign                  # non-recursive
./thorlens import --log new.jsonl.zst --case host1 --replace                  # replace existing case
```

- `--case` is a **name** for `import` (created below `--cases-dir`, default `./cases`) and a
  **path** for `serve` (`--case ./cases/host1`).
- An existing name is refused unless `--replace`; the old case stays as
  `cases/.replaced-<name>-<UTC>` (copy `annotations.sqlite*`/`agent_status.sqlite*` back to keep
  notes). `--replace --discard-previous` deletes it.
- `--log-timezone Europe/Berlin` for zone-less timestamps extracted from log lines (default `Local`).
- `--workers 1-64` (default 4). Exit codes: 0 ok, 1 failure, 2 usage error.

Details: [import-and-cases](references/import-and-cases.md).

## Serve and open

```bash
./thorlens serve                                  # start page: browser import + case list
./thorlens serve --case ./cases/host1 --port 8080  # open one case directly
```

Open `http://127.0.0.1:8080`. The web UI and MCP always bind to **127.0.0.1**; there is no
bind-address option and no authentication. From another machine use an SSH tunnel:

```bash
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:8080:127.0.0.1:8080 user@lens-host
```

Do not put Lens behind a reverse proxy: requests with a non-loopback `Host` or a foreign
`Origin` are rejected (403). One Lens service per case (`.thorlens.lock`). UI, keys and
API: [serve-and-ui](references/serve-and-ui.md).

## Connect an AI client (MCP)

Preferred: Streamable HTTP on the running server.

```bash
claude mcp add --transport http --scope project thor-lens http://127.0.0.1:8080/mcp   # Claude Code
codex mcp add thor-lens --url http://127.0.0.1:8080/mcp                                 # Codex
```

Generic `.mcp.json`: `{"mcpServers":{"thor-lens":{"type":"http","url":"http://127.0.0.1:8080/mcp"}}}`.
Stdio (no web UI, needs `--case`, absolute paths):
`{"command":"/abs/thorlens","args":["serve","--case","/abs/cases/host1","--mcp-stdio"]}`.
Remote client: SSH tunnel as above, then the same local URL.

Suggested tool flow: `get_case_info` → `get_high_score_events` / `search_events` →
(multi-host) `get_event_statistics`, `find_hosts`, `get_host` → `get_event` →
`find_related_events` / `get_events_around_time` / `get_log_line_neighborhood` → tag/comment.
MCP tags and comments never create structured AI verdicts. Tool list, limits, sessions:
[mcp-integration](references/mcp-integration.md).

## Verify a case

Use the real `meta.json` keys (there is no `event_count`, `min_time` or `max_time`):

```bash
jq '{case_name, source_format, source_records, timeline_rows, untimed_rows, min_ts, max_ts, hostnames, parse_errors}' cases/host1/meta.json
curl -s http://127.0.0.1:8080/api/meta | jq '{timeline_rows, source_records, min_ts, max_ts}'
scripts/case_inventory.sh cases/host1
```

Expect `source_format` `audit_trail` or `thor_log`, `timeline_rows` ≥ `source_records`
(one row per timestamp), Parquet under `events/month=YYYY-MM-01/`. Old dates (1601, 1899,
1970, 1980) and far-future dates come from artifact metadata, not from attacker activity.

## Network receiver (THOR 11 only)

```bash
./thorlens serve --ingest-listen 10.0.0.5:9443 --ingest-allow-cidr 10.0.0.0/16
# on each host:
sudo ./thor-linux-64 --remote-log 10.0.0.5:9443:JSON:TCP
```

TCP or TCPTLS only (no UDP); JSON or SYSLOGJSON only; THOR 10 senders are not supported.
Without `--ingest-allow-cidr` any host that reaches the port can submit records.
See [network-ingestion](references/network-ingestion.md).

## Rules

1. Detect the THOR version first. Full timeline = THOR 11 audit trail; everything else is
   findings-only. Tell Lite and v10 users that, then offer the JSON-log path.
2. Never recommend `--lab` for live hosts; never run `--lab` without `-p`.
3. Never show raw first lines of logs or audit trails (license owner). Never paste
   `meta.json` `source_file` paths or host names into external services.
4. Do not delete case folders to re-import; use `--replace`.
5. Lens has no authentication: keep it on loopback, use SSH tunnels, and remember any local
   user or process can call the API and MCP.
6. Agent runs (`thorlens-agents`, Agents page) send evidence to the configured LLM provider;
   confirm the user accepts that before suggesting cloud providers.

## References

| File | Read when |
|---|---|
| [quickstart](references/quickstart.md) | first-time setup, shortest working path |
| [build-and-prereqs](references/build-and-prereqs.md) | build fails, toolchain versions, make targets |
| [audit-trail-generation](references/audit-trail-generation.md) | choosing THOR flags, audit trail schema, images, v10/Lite |
| [import-and-cases](references/import-and-cases.md) | import options, case layout, meta.json, `--replace` |
| [serve-and-ui](references/serve-and-ui.md) | serve flags, UI, keys, HTTP API, SSH tunnel |
| [network-ingestion](references/network-ingestion.md) | receiving THOR 11 logs over TCP/TLS |
| [mcp-integration](references/mcp-integration.md) | MCP setup for any client, tool reference, limits |
| [troubleshooting](references/troubleshooting.md) | empty UI, import errors, MCP not connecting, locks |
| [examples/end-to-end-local](examples/end-to-end-local.md) | live host → audit trail → Lens → MCP |
| [examples/case-from-mounted-image](examples/case-from-mounted-image.md) | E01/raw image with lab-type license |
| [examples/case-from-sshfs](examples/case-from-sshfs.md) | appliance or remote Linux via SSHFS |
| `scripts/validate_audit_trail.sh FILE` | check a file before import (read-only, privacy-safe) |
| `scripts/case_inventory.sh CASE_DIR` | summarize a case (read-only, needs jq, optional sqlite3) |

Related skills: `thor-scan` (full scan command lines), `thor-log-analysis` (interpreting
findings), `thor-deployment` (collecting logs from many hosts).
