# MCP integration

The Lens MCP server lets AI clients query and annotate the case that the Lens service has
open. It reads evidence and writes tags, comments, bookmarks, selections and exclusion
filters. It never writes structured AI verdicts (only Lens agent runs do).

## Transports

| Transport | Start | Notes |
|---|---|---|
| Streamable HTTP (preferred) | `thorlens serve --case ./cases/web01` (or `serve` + open a case in the UI) | `http://127.0.0.1:8080/mcp`; loopback only; same port as the UI unless `--mcp-port N`; `--mcp-port 0` disables MCP |
| stdio | client spawns `thorlens serve --case /abs/case --mcp-stdio` | no web UI; requires `--case`; does not take the case lock (can run next to a web service) |
| Legacy SSE | `/mcp/sse` + `/mcp/message?sessionId=…` | recent builds only with `--mcp-legacy-sse`; use `/mcp` instead |

HTTP sessions (recent builds): `initialize` returns `Mcp-Session-Id`; a session belongs to one
case activation. When the analyst closes or switches the case, the next request gets 404 and
the client must re-initialize, so it cannot silently continue in another case. With no case
open, requests get 503 `no case is active`. Every result carries
`_meta.thor_lens_case_activation_id`: re-check `get_case_info` when it changes.

## Client setup

Claude Code (project scope writes `.mcp.json`; use `--scope user` for all projects):

```bash
claude mcp add --transport http --scope project thor-lens http://127.0.0.1:8080/mcp
claude mcp list            # verify
```

Codex:

```bash
codex mcp add thor-lens --url http://127.0.0.1:8080/mcp
```

Any client that reads an `mcpServers` JSON file (Claude Desktop, Cursor, others):

```json
{ "mcpServers": { "thor-lens": { "type": "http", "url": "http://127.0.0.1:8080/mcp" } } }
```

stdio form (absolute paths; Windows: `C:\\path\\thorlens.exe`):

```json
{ "mcpServers": { "thor-lens": {
    "command": "/opt/thor-lens/thorlens",
    "args": ["serve", "--case", "/srv/lens/cases/web01", "--mcp-stdio"] } } }
```

Client on another machine: open the SSH tunnel
(`ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:8080:127.0.0.1:8080 user@lens-host`) and use
the same local URL. The **Connect AI** tab shows the effective endpoint and copy-ready commands.
Restart/reload the client after changing its MCP configuration.

## Tools (THOR Lens 0.7)

| Group | Tools |
|---|---|
| Case and schema | `get_case_info`, `get_schema`, `get_object_type_counts`, `get_time_kind_counts`, `get_hostname_counts`, `get_top_entities` |
| Event queries | `search_events`, `get_event`, `get_events_by_ids` (≤50 IDs), `get_events_around_time`, `get_high_score_events` (default `min_score` 50) |
| Aggregation | `get_time_buckets`, `get_buckets_by_type`, `get_buckets_by_score`, `get_filtered_counts`, `summarize_time_range` |
| Investigation helpers | `find_related_events` (references, same entity, time), `get_log_line_neighborhood` (surrounding lines of the same log), `get_file_activity`, `get_process_activity`, `get_registry_activity` |
| Multi-host population | `get_event_statistics` (how common is this?), `find_hosts` (which hosts have it?), `get_host` (host summary), `list_scans` (scan identities and completion) |
| Tags | `list_tags`, `get_event_tags`, `add_tag`, `remove_tag`, `bulk_add_tag` (≤100), `get_events_by_tags` |
| Comments | `get_event_comments`, `add_comment` |
| Bookmarks | `list_bookmarks`, `get_bookmarked_events`, `set_bookmark`, `remove_bookmark` |
| Selections | `list_selections`, `create_selection`, `get_selection_events`, `add_to_selection`, `remove_from_selection`, `bulk_add_to_selection` (≤100) |
| Exclusion filters | `list_exclusion_filters`, `add_exclusion_filter`, `remove_exclusion_filter` |
| Agent provenance | `apply_agent_annotation_bundle`; recent builds: `begin_agent_run`, `end_agent_run` |

Resource: `case://info` (same as `get_case_info`). The exact tool set depends on the build;
trust the client's tool list.

## Conventions and limits

- Event IDs: 16 lowercase hex characters; only use IDs returned by a tool.
- Times: RFC 3339 (no offset = UTC) or a date; range 1677-09-22 … 2262-04-11.
- Lists: default 100, max 500 (larger `limit` is rejected); paginated tools return
  `has_more`/`next_offset`.
- Results over 256 KiB fail with a hint (narrow `from`/`to`, `limit`, `max_raw_bytes`), except
  the core read tools used by agents.
- `raw_*` fields are cut to `max_raw_bytes` (default 32,768; `0` = full) and then end with
  `...[truncated sha256=… bytes=…]`.
- Each call has a 120 s limit (`tool call exceeded 120s; narrow the query …`).
- Read tools honour the analyst's exclusion filters by default (`respect_exclusions`).
- Tags are canonicalized (lower case, hyphenated; `cobaltstrike` → `cobalt-strike`).
- Untimed evidence: `time_kind: UNTIMED`; add `include_untimed: true` to range searches.
- `observed_at` is scan time, not event time.
- Network cases: absence in a `receiving` or `partial` scan is not negative evidence; read
  `population_context` and `count_basis` in aggregate results.

## Investigation flow for an assistant

1. `get_case_info` (+ count tools) → scope, hosts, time range, source format.
2. Pivots: `get_high_score_events`, `search_events`, `get_*_activity`.
3. Multi-host: `get_event_statistics` on a pivot (rare vs common), `find_hosts`, then `get_host`.
4. Evidence: `get_event` / `get_events_by_ids`.
5. Context: `find_related_events`, `get_events_around_time`, `get_log_line_neighborhood`.
6. Annotate only with evidence; prefer tags such as `needs-review`, `false-positive`,
   `lateral-movement`; comments state the reason.

For interpreting individual THOR findings (scores, reasons, rule names) use the
`thor-log-analysis` skill.

## Security

- No authentication. Any local user or process can call the endpoint and change annotations.
  Keep Lens on single-user analysis machines; use SSH tunnels, not port forwards to other
  interfaces.
- Tool results contain case evidence (host names, user names, paths). An MCP client backed by
  a cloud model sends that evidence to the model provider; confirm this is acceptable.
