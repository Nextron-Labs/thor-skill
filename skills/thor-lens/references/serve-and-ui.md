# Serve, UI and HTTP API

## `thorlens serve`

```bash
thorlens serve                                   # start page: browser import, case list, network receiver tab
thorlens serve --case ./cases/web01              # open one case (PATH, not name)
thorlens serve --port 9090 --cases-dir ./investigations
```

| Option | Default | Meaning |
|---|---|---|
| `--case`, `-c` | none | path to a case directory to open immediately |
| `--cases-dir` | `./cases` | saved cases and target of browser imports |
| `--port`, `-p` | `8080` | web UI/API port (always on 127.0.0.1) |
| `--mcp-port` | same as web | `0` disables MCP (and built-in agent runs); another port = separate loopback MCP listener |
| `--mcp-stdio` | off | MCP over stdio only, no web server; requires `--case` |
| `--mcp-legacy-sse` | off | recent builds: also serve `/mcp/sse` + `/mcp/message`; otherwise those answer 404 |
| `--scenario-dir` | `./scenarios` | agent scenarios |
| `--ingest-*` | off | network receiver, see [network-ingestion](network-ingestion.md) |

Check the flags of the installed build with `thorlens serve --help`; older builds lack
`--mcp-legacy-sse` and serve SSE by default.

Startup fails cleanly when the port is taken
(`web interface address 127.0.0.1:8080 is already in use`) or the case is open in another
Lens process (`case <name> is already open by another THOR Lens process`). A different port
does not help with the second: the case is locked, not the port. `--mcp-stdio` does not take
the lock and can run next to a web service on the same case.

## Network exposure

- Web UI, API and MCP bind to the fixed loopback address `127.0.0.1`. No flag changes this.
- There is no authentication. Requests are refused (403) when `Host` is not
  `127.0.0.1`/`localhost`/`[::1]`, when `Origin` is foreign, or for cross-site browser requests.
  Non-GET `/api` calls also need `X-THOR-Lens-Request: 1` and a JSON content type. These are
  CSRF/DNS-rebinding guards, not access control: every local user and process can call the API.
- Remote access = SSH local forward from the client machine:

```bash
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:8080:127.0.0.1:8080 analyst@lens-host
# port 8080 busy on the client:
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:18080:127.0.0.1:8080 analyst@lens-host   # → http://127.0.0.1:18080
```

`~/.ssh/config` form:

```sshconfig
Host thor-lens
  HostName lens-host.example.internal
  User analyst
  LocalForward 127.0.0.1:8080 127.0.0.1:8080
  ExitOnForwardFailure yes
  ServerAliveInterval 30
```

The **Connect AI** tab on the start page generates these for you. Reverse proxies with a
public host name do not work (Host check) and would remove the only protection.

## Web UI

- **Start page**: import one or more files into one case (atomic, progress, cancel), open,
  search/sort and delete saved cases, per-case "System & scan details" (OS, versions, scan
  settings from the THOR `Init` messages), Network receiver tab, Connect AI tab.
- **Timeline**: histogram (count or score mode, brush to select, presets), filters (object type,
  time kind/basis, assessments vs scan activity, detections only, host, score, tags, search,
  exclusions), evidence table, detail inspector (normalized fields, reasons, references with
  drill-down, raw JSON, source file/line), tags/comments/bookmarks.
- **Case**: lanes *Actionable*, *Needs review*, *AI-cleared*, *Dismissed*; analyst verdicts;
  CSV or printable HTML export.
- **Agents**: run YAML investigation scenarios with an LLM provider (OpenAI, Anthropic,
  OpenRouter, Ollama); writes structured AI assessments; rollback of a run's annotations.
  Evidence is sent to the chosen provider: decide deliberately; redaction settings exist.
- **Operations**: case/volume capacity, receiver state, MCP binding, workers.
- Case-name menu: **Close case…** (frees the case, interrupts MCP) and **Switch case…**.
  Closing never deletes data.

Keyboard: `j`/Down next event, `k`/Up previous, `Enter`/Right open details, Left/`Esc` back or
close, `b` bookmark, `t` tag input, `/` search, `Shift+F` exclude entity, `Shift+P` exclude parent
path (both with a confirmation that counts hidden rows), `d` clear histogram selection,
`c` clear search, `Shift+F10`/context-menu key for the event menu. Older builds used plain `f`/`p`.

## HTTP API (local scripts)

All under `http://127.0.0.1:<port>`; errors are `{"error": "…"}` with an HTTP status.

| Route | Use |
|---|---|
| `GET /api/meta` | active case summary (`timeline_rows`, `source_records`, `min_ts`, `max_ts`, …) |
| `GET /api/app-state`, `GET /api/cases` | service state, saved cases |
| `GET /api/events`, `GET /api/event/{id}` | paged events, full event |
| `GET /api/buckets`, `/api/buckets-by-type`, `/api/buckets-by-score` | histogram data |
| `GET /api/hostname-counts`, `/api/time-kinds`, `/api/filtered-counts` | counts |
| `GET /api/case-events/export?format=csv\|html` | Case view export |
| `POST /api/imports` | browser-style multipart import (send `-H 'Expect:'` with curl) |
| tags/comments/bookmarks/selections/exclusion-filters | under `/api/event/{id}/…`, `/api/selections`, `/api/exclusion-filters` |

```bash
curl -s http://127.0.0.1:8080/api/meta | jq '{case_name, timeline_rows, source_records, min_ts, max_ts}'
curl -s 'http://127.0.0.1:8080/api/events?limit=5' | jq .
```

Write calls need `-H 'X-THOR-Lens-Request: 1' -H 'Content-Type: application/json'`.
Prefer MCP or the UI over hand-written write calls.

## Logs

`thorlens` logs to stderr; add `--debug` for detail:
`thorlens --debug serve --case ./cases/web01 2> lens.log`.
