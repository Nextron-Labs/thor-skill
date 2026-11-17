# THOR Thunderstorm

A web service that runs THOR in the background and scans files submitted over HTTP(S). Use it
for systems that cannot run THOR (ESXi, appliances, legacy or exotic OS, no admin rights) or
for continuous file submission (mail gateways, sandboxes, upload portals). Only submitted
files are scanned: no processes, registry, event logs or other live artifacts.

## v10 vs v11

| | THOR 10.7 | THOR 11 |
|---|---|---|
| Start | `thor-linux-64 --thunderstorm` / `thor64.exe --thunderstorm` (mode of the main binary) | separate binary `tools/thunderstorm` in the **Linux** package only; `thor --thunderstorm` exits with a pointer to it |
| Bind | `--server-host` (default `127.0.0.1`), `--server-port` (8080) | `--host` (default `127.0.0.1`), `--port` (8080) |
| TLS | `--server-cert`, `--server-key` | `--cert`, `--key` |
| Uploads | `--server-upload-dir` (default `<tmp>/thor-uploads`), `--server-store-samples none\|malicious\|all` | `--upload-dir` (default `/tmp/thunderstorm-uploads`), `--store-samples-score N` (default 200 = never) |
| Async cache | `--server-result-cache-size` | `--result-cache-size` (default 250000), `--queue-warn-size` (50000), `--queue-storage` (`.persisted-uploads`) |
| Other | `--pure-yara` (YARA only, faster), `--sync-only-threads N` | `--thor-location <THOR folder>` (default: package root), `--vfs-dir`, `--signature-update-interval` hours (24; 0 = never), `--debug`; THOR flags after `--` |
| Results | JSON v1 (v2 with `--jsonv2`) | JSON log v3 |

License: Thunderstorm/"Service" license (evaluations may get exceptions). A Service license
allows only Thunderstorm and drop-zone mode; it refuses normal scans. Not available in THOR Lite.

Default bind is loopback in both versions: set the host to the server's IP or `0.0.0.0`,
otherwise collectors cannot connect.

## Start

```bash
# THOR 11 (Linux), service license in the THOR folder
sudo /opt/thor/tools/thunderstorm --host 0.0.0.0 --port 8080 --upload-dir /var/lib/thunderstorm/uploads \
  -- --remote-log siem01:514:JSON:TCP

# THOR 10.7
sudo /opt/thor/thor-linux-64 --thunderstorm --server-host 0.0.0.0 --server-port 8080 \
  --server-store-samples malicious -s siem01:514:JSON:TCP
```

Installer script for a systemd service (Linux; inspect before running):
https://github.com/NextronSystems/nextron-helper-scripts/tree/master/thunderstorm
(config `/etc/thunderstorm`, logs `/var/log/thunderstorm`, update helper `thunderstorm-update`
/ `thunderstorm-update full`). Updates: stop the service, `thor-util update` or
`thor-util upgrade`, start it again.

## API

API documentation is served at the service root (`http://<server>:8080/`).

| Endpoint | Use |
|---|---|
| `POST /api/check` | synchronous scan, returns the result (empty = no detection) |
| `POST /api/checkAsync` | queue the file, returns a receipt ID (fast bulk submission) |
| `GET /api/status` | queue state |
| `GET /api/signatures` | signature info (v11) |

```bash
curl -X POST "http://ts01:8080/api/check?source=web01" -F "file=@sample.exe"
```

`source=` sets the host name in the results (default: sender FQDN or IP).

## Collectors

https://github.com/NextronSystems/thunderstorm-collector: Go binaries and standalone scripts
(Bash, POSIX sh/ash for BusyBox, Python 3 and 2.7, Perl, PowerShell 3+ and 2, Batch). Pick by
the runtime available on the target; flags differ per collector, check its README. Example
(Python collector, revised version):

```bash
python3 ./thunderstorm-collector.py --server ts01.corp.internal --port 8080 \
  --dirs /etc /tmp /var/www --source esxi01 --max-age 14 --dry-run    # preview, then --no-dry-run
```

ESXi: use the Python collector. Collectors select by age and size (defaults are small,
e.g. 2 MiB), so large files are not submitted unless you raise the limit.

Python API client: `pip install thunderstormAPI` (`--asyn` for async; certificate checks only
with `--verify`).

## Operations

- Async mode for bulk: faster submission, server queues on disk; watch `/api/status` and
  queue warnings. Sync mode when the client needs the verdict.
- TLS roughly halves throughput; use it mainly to pass IDS/IPS or untrusted networks.
- Logs: forward with `--remote-log`/`-s` or read the service log; results can also be imported
  into THOR Lens as JSON logs (findings-only).
- Stored samples (upload dir, VFS dir) are potentially malicious files: restrict access.
