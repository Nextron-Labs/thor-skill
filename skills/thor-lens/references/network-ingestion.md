# Network ingestion (receive THOR 11 logs live)

Lens can receive THOR JSON log v3 records over a separate TCP or TLS listener while scans
run. Received data becomes queryable within seconds; finalization seals the case later.
The web UI and MCP stay on loopback; only the receiver port is exposed.

## Limits

- THOR 11 only (JSON log v3). THOR 10 senders (JSON v1/v2) are not supported: collect their
  `.json` files and `thorlens import` them.
- Formats `JSON` or `SYSLOGJSON`; transports `TCP` or `TCPTLS`. No UDP (lost datagrams would
  make completeness unprovable). Newline-delimited and RFC 6587 octet-counted framing.
- No sender authentication. Anyone who can reach the port can submit records under any host
  name. Restrict with `--ingest-allow-cidr` and host firewall rules.
- Received data is findings-level (JSON log), not an audit trail.

## Start the receiver

```bash
# private interface of the Lens machine; web UI stays on 127.0.0.1:8080
./thorlens serve --ingest-listen 192.168.10.5:9443 --ingest-allow-cidr 192.168.10.0/24

# wildcard bind behind NAT/VPN: tell senders the reachable address
./thorlens serve --ingest-listen 0.0.0.0:9443 --ingest-sender-address lens.corp.example:9443 \
  --ingest-allow-cidr 10.20.0.0/16

# TLS
./thorlens serve --ingest-listen 0.0.0.0:9443 --ingest-sender-address lens.corp.example:9443 \
  --ingest-tls-cert receiver.crt --ingest-tls-key receiver.key --ingest-allow-cidr 10.20.0.0/16
```

| Option | Default | Meaning |
|---|---|---|
| `--ingest-listen` | off | bind address of the receiver |
| `--ingest-sender-address` | listen address | `host:port` shown in sender instructions (wildcard binds, NAT, containers) |
| `--ingest-case` | resume unfinished automatic case or `live-thor-network-YYYY-MM-DD[-N]` | case name |
| `--ingest-tls-cert`, `--ingest-tls-key` | none (plain TCP) | TLS; both required together |
| `--ingest-allow-cidr` | any source | allowed source networks (repeatable) |
| `--ingest-log-timezone` | `UTC` | zone for zone-less times inside received log lines |
| `--ingest-max-connections` | 1024 | concurrent senders (1–65536) |
| `--ingest-max-connections-per-source`, `--ingest-max-scans`, `--ingest-max-scans-per-connection`, `--ingest-max-diagnostics-mib`, `--ingest-max-session-mib`, `--ingest-min-free-mib` (1024) | | capacity guards in recent builds; see `thorlens serve --help` |

Without `--case`, the receiver's case becomes the active case (and the MCP target) after the
first batch arrives. Until then the Connect AI tab says *Waiting for receiver data*.

## Configure THOR on the hosts

Add one `--remote-log` target to the normal scan command (aliases `-s`, `--syslog`):

```bash
sudo ./thor-linux-64 --remote-log 192.168.10.5:9443:JSON:TCP
sudo ./thor-macosx   --remote-log 192.168.10.5:9443:JSON:TCP
thor64.exe --remote-log lens.corp.example:9443:JSON:TCPTLS        # elevated
```

For TLS with a private CA, add `--ca <ca.pem>` on the THOR side (`--insecure` skips
verification; avoid). THOR still writes its local files as usual; keep them as the
authoritative copy. Rollout to many hosts: the `thor-deployment` skill.

## Status and finalization

- Per scan (host + scan ID), Lens tracks transport state, ingestion health, THOR-reported
  completion and count coverage separately. A closed connection does not prove that THOR
  finished.
- Start page **Network receiver** tab / **Operations**: received scans, health, **Delete scan**
  for failed attempts, and **Seal**. Sealing stops receipt for all senders, compacts files and
  publishes the case; partial sealing must be requested explicitly. After sealing, Lens
  receives again only after a restart, into a new case.
- Absence of a finding in an incomplete scan is not evidence; population statistics
  (`get_event_statistics`, `find_hosts`) keep complete and incomplete scans apart.

## Storage

Case: `cases/<name>/events/batches/<batch>/month=…/part-0000.parquet` plus `.live/`.
Raw receive session: `cases/.incoming/<name>/` (deleted together with the case).
