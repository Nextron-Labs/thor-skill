# Producing THOR output for Lens

## Which version produces what

| THOR | Lens-compatible output | Not compatible |
|---|---|---|
| 11 (full) | audit trail (`--audit-trail`), JSON log v3 (default `.jsonl`), `--remote-log …:JSON:TCP[TLS]` stream | text log (`--text`), HTML, CSV |
| 11 Lite | JSON log v3 | no audit trail (the flag has no effect in Lite builds) |
| 10.7 (full/Lite) | JSON log v1 (`--jsonfile=<f>`) or v2 (`--jsonfile=<f> --jsonv2`) | text log, HTML, CSV, 10.7 `--audit-trail` (gzip, `{info, findings, references}` schema, not recognized by Lens) |

Only the THOR 11 audit trail gives the full timeline (clean elements, all timestamps,
references). JSON logs give findings only.

## The THOR 11 `--audit-trail` flag

| Property | Value |
|---|---|
| Syntax | `--audit-trail` (bare) or `--audit-trail=<file>`; optional value, always use `=` |
| Default name | `<hostname>_thor_audit_<time>.jsonl.zst` in the output directory |
| Relative names | placed in `--output-directory`/`-e` (default: current working directory) |
| Placeholders | `<hostname>` (value of `-j` if set), `<time>` = `YYYY-MM-DD_HHMM` local (UTC with `--timestamp-utc`); environment variables expanded |
| Compression | always zstd, regardless of the extension you choose; name it `.jsonl.zst` |
| License | no special license; not available in THOR Lite |
| Scope | not a scan mode: module selection, excludes, `--lookback`, `--timeout` limit it; `--min` and other output filters do not |
| Privacy/crypto | `--no-personal-data` applies; `--encryption-key` applies (compressed, then encrypted; decrypt with `thor-util decrypt`, result is still `.zst`) |
| Not applied | `--log-size-limit` (no size cap), `--log-append` (file is always truncated) |
| Write errors | Error `Could not write audit trail, further writing disabled for this scan`; the scan continues |

Size: one record per assessed element. As an order of magnitude, a 35-minute default
scan of a Linux server produced about 740,000 records, 87 MB compressed (≈850 MB
uncompressed). Windows hosts with MFT/USN parsing produce more. Check free space in `-e`.

## Content

Every line is one JSON object with `type`:

- `THOR audit message`: `time`, `level`, `module`, `message`, `fields`, `log_version`. All
  non-debug THOR messages, starting with startup info (`Thor Version: …`, `System
  Information` with `fields.object.hostname`, `Scan Information` with `fields.object.scan_id`
  **and `fields.object.license.owner`**) and, if a license file is found, the license line with
  the owner. Never print these messages; filter with
  `grep -v -e LICENSE_OWNER -e 'License file found' -e 'Scan Information'` or select records only.
  The file starts with such messages.
- `THOR audit record`: `id`, `object` (with `object.type`, e.g. `file`, `process`,
  `Windows service`), `timestamps` (all timestamps of the object in UTC; if none, a single
  `OBSERVED` = scan time), `reasons` (only reasons with score > 0), `references`
  (`relation`: `child of` for the direct parent, `points to` for derived elements),
  `log_version` (`v3.0.0`).
- No total score in records: Lens computes it from the reason scores with THOR's formula.
  Reasons ≤ 0 (false-positive filters) are omitted, so Lens can show a higher score than the
  JSON log for the same object.
- Written only if a signature matched, other elements were found inside, or they reference
  a scanned file: log lines, event log entries, Linux audit log entries, journald entries,
  registry keys and registry values.

Inspect safely (never print raw head lines):

```bash
zstd -dcq FILE | jq -r '.type' | sort | uniq -c
zstd -dcq FILE | jq -r 'select(.type=="THOR audit record") | .object.type' | sort | uniq -c | sort -rn | head -20
zstd -dcq FILE | jq -c 'select(.type=="THOR audit record" and (.reasons|length)>0) | {t: .object.type, path: (.object.path // .object.name // null), r: [.reasons[].signature.rule_name]}' | head
```

## Commands (THOR 11)

Live hosts: no `--lab`. `--lab` limits the scan to Filescan and requires a lab-type license (Forensic Lab, Incident Response or Trial).

```bash
# Linux / macOS live host, all results in one folder per host
sudo ./thor-linux-64 --audit-trail -e "/cases/<hostname>"
sudo ./thor-macosx   --audit-trail -e "/cases/<hostname>"
# Windows live host (elevated cmd)
thor64.exe --audit-trail -e "C:\cases\<hostname>"
# Explicit file name
sudo ./thor-linux-64 --audit-trail=/cases/web01_audit.jsonl.zst -e /cases/web01
# Narrow test (does not touch the default ThorDB)
sudo ./thor-linux-64 -a Filescan -p /var/www --audit-trail --no-thordb -e /tmp/lens-test \
  | grep -v -e LICENSE_OWNER -e 'License file found' -e 'Scan Information'
```

Quote `<hostname>` and `<time>`: `<` and `>` are redirections in every shell.

### Mounted images and remote file systems (lab-type license)

| Flag | Purpose |
|---|---|
| `--lab` | evidence mode: Filescan only, deep, all cores, no ThorDB, no resource limits; always add `-p` |
| `-p /mnt/image` | what to scan |
| `--path-remap /mnt/image:C` | report paths as on the original system (`current:original`; alias `--virtual-map`) |
| `--target-os windows` | path style, heuristics and excludes of the source OS (no license needed) |
| `-j ORIGHOST` | original host name in all outputs and in `<hostname>` (alias `--overwrite-hostname`) |

```bash
sudo ./thor-linux-64 --lab -p /mnt/image --path-remap /mnt/image:C --target-os windows \
  -j WS01 --audit-trail -e /cases/WS01
```

Without a lab-type license THOR refuses `--lab`, `-j` and `--path-remap` ("The current license type
doesn't allow …"). It still scans a kernel-mounted image with `-a Filescan -p /mnt/image` (with a
notice that the directory looks like a mounted image), but paths stay `/mnt/image/…` and the
host name is the analysis machine. FUSE mounts (`ntfs-3g`, sshfs) count as network file systems
in THOR 11 and are skipped or refused without a lab-type license: mount with the kernel `ntfs3`
driver or copy the files locally.

## THOR 10.7 and Lite: findings-only input

```bash
thor64.exe --jsonfile=C:\cases\WS01.json --jsonv2 -e C:\cases          # 10.7 full or Lite
sudo ./thor-lite-linux-64 -e /cases/web01                               # Lite 11: .jsonl by default
```

`--jsonfile` has an optional value in 10.7: write `--jsonfile=<file>` or bare `--jsonfile`
(default `:hostname:_thor_:time:.json`).

## Many hosts

Write each host's results to a share with the host name in the path
(`-e "\\fs01\thor-results\<hostname>"` on v11), then import the folder:
`thorlens import --log-dir … --case campaign` (one level, non-recursive) or repeated `--log`.
Or stream THOR 11 JSON directly into a Lens receiver: see [network-ingestion](network-ingestion.md).
Rollout methods: the `thor-deployment` skill.

## Checklist before import

- [ ] THOR 11 for an audit trail; v10/Lite → JSON log
- [ ] `zstd -t` passes (scan finished, copy complete)
- [ ] `scripts/validate_audit_trail.sh FILE` → exit 0
- [ ] Images: `-j` and `--path-remap` were used (else hosts/paths are those of the analysis box)
- [ ] Nobody pasted the first lines of the file anywhere (license owner)
