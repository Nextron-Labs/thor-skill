# SIEM and syslog forwarding

THOR sends log events in real time to one or more remote targets while it still writes its
local files. Use it to centralize results from many hosts; keep the local/share files as the
authoritative copy (UDP can drop, connections can break).

## Syntax

| | THOR 10.7 | THOR 11 |
|---|---|---|
| Flag | `-s`, `--syslog` (repeat for several targets) | `--remote-log` (aliases `-s`, `--syslog`), repeatable |
| Target | `server[:port[:type[:protocol]]]` | same, or `url[:type]` with `http`/`https` |
| Defaults | port 514, `DEFAULT`, `UDP` | same |
| Types | `DEFAULT`, `CEF`, `JSON`, `SYSLOGJSON`, `SYSLOGKV` | same |
| Protocols | `UDP`, `TCP`, `TCPTLS` | same |
| YAML key | `syslog:` | `remote-log:` |

```bash
-s siem01                                  # siem01:514, text format, UDP
-s siem01:514:CEF:TCP                      # CEF over TCP (ArcSight etc.)
-s siem01:6514:JSON:TCPTLS                 # JSON over TLS
--remote-log https://collector.corp.internal/thor:JSON     # v11 only: HTTP(S) endpoint
-s siem01:514:CEF:TCP -s lens01:9443:JSON:TCP              # two targets
```

`config/thor.yml` (v11): `remote-log: ['siem01:514:CEF:TCP']`; v10: `syslog: ['siem01:514:CEF:TCP']`.

## Formats

| Type | Content |
|---|---|
| `DEFAULT` | THOR text log line with syslog priority header (`<190>Oct  8 11:37:54 host/1.2.3.4 THOR: Info: MODULE: … MESSAGE: …`) |
| `CEF` | ArcSight CEF (`CEF:0\|Nextron Systems GmbH\|THOR\|…`); minimum level by `--syslog-cef-level` (v11) / `--cef_level` (v10), default 4 = Notice; 1 Debug, 3 Info, 5 Error, 8 Warning, 10 Alert |
| `JSON` | raw JSON event per message, same schema as the JSON log: v10 v1 (v2 with `--jsonv2`), v11 v3 |
| `SYSLOGJSON` | JSON with syslog header |
| `SYSLOGKV` | `KEY='value'` pairs with syslog header |

Prefer `JSON` (structured) or `CEF` for ArcSight-style SIEMs. THOR Lens's network receiver
accepts only v11 `JSON`/`SYSLOGJSON` over TCP/TCPTLS (`thor-lens` skill).

## Transport and TLS

- UDP is the default and loses messages under load or with long lines; use `TCP` or `TCPTLS`
  for sweeps.
- `TCPTLS` verifies the server certificate against the system roots. Private CA: `--ca <pem>`
  (both versions; v11 also `--no-system-ca`). `--insecure` skips verification (avoid).
- Length: non-JSON messages are truncated at `--syslog-length-limit` (v11, default 2048;
  v10 `--maxsysloglength`), `0` = no truncation. `--syslog-rfc3164` / `--syslog-rfc5424`
  (v10 `--rfc3164`, `--rfc5424`) truncate to 1024/2048; `--syslog-strict` (v10 `--rfc`) for
  strict RFC 3164 (short host name, shortened message).
- Placeholders and environment variables are expanded in the target string (`<hostname>` in
  v11, `:hostname:` in v10).

## Local sinks

| Flag | Effect |
|---|---|
| `--local-syslog` | local syslog, facility `local0` (Debian: `/var/log/syslog`; RHEL/rsyslog needs a rule such as `local0.* -/var/log/thor`) |
| `--eventlog` | Windows Application event log |

Then the endpoint's existing log shipper forwards THOR events.

## Only syslog, no local files

```bat
thor64.exe --no-html --no-csv --no-json --remote-log siem01:514:JSON:TCP     # v11
thor64.exe --nolog --nocsv -s siem01:514:JSON:TCP                              # v10 (--nolog = no text/HTML)
```

Not recommended for sweeps: a broken connection loses results without a local copy.

## SIEM side

- Size the collector: a full scan sends thousands of lines per host (Info/Notice/Warning/Alert
  messages); many hosts in a wave produce bursts.
- Splunk: THOR APT Scanner app and THOR add-on on Splunkbase (apps 3717, 3718).
- Analysis Cockpit (Nextron) for baselining many scan logs.
- Correlate by host name and scan ID (`SCANID` / `meta.scan_id`); set `--timestamp-utc`
  (v10 `--utc`) for fleets across time zones.
