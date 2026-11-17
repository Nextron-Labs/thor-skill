# Example: forensic disk image → Lens case

Scenario: E01 image of Windows workstation `WS01`, analysed on a Linux box with THOR 11 and
a lab-type license (Forensic Lab, Incident Response or Trial; needed for `--lab`, `-j`,
`--path-remap`). Without one, see the last section.

## 1. Mount read-only

```bash
sudo mkdir -p /mnt/ewf /mnt/ws01
sudo ewfmount /evidence/WS01.E01 /mnt/ewf                        # libewf
sudo mmls /mnt/ewf/ewf1                                         # find the NTFS partition start sector (sleuthkit)
sudo mount -t ntfs-3g -o ro,loop,show_sys_files,offset=$((1026048*512)) /mnt/ewf/ewf1 /mnt/ws01
ls /mnt/ws01/Windows/System32/config/SYSTEM                     # sanity check
```

Raw image: `sudo mount -o ro,loop,offset=$((START*512)) WS01.dd /mnt/ws01`. Never mount
evidence read-write. Replace the offset with the start sector `mmls` reports.

## 2. Original host name

Take it from case documentation or the SYSTEM hive
(`ControlSet001\Control\ComputerName\ComputerName`), e.g. with `regripper`/`reglookup`.
Do not grep `strings` of the hive: unreliable.

## 3. Scan with audit trail

```bash
sudo ./thor-linux-64 --lab \
  -p /mnt/ws01 \
  --path-remap /mnt/ws01:C \
  --target-os windows \
  -j WS01 \
  --audit-trail \
  -e /cases/WS01
```

| Flag | Why |
|---|---|
| `--lab` | evidence mode: Filescan only, deep, all cores, no ThorDB; `-p` is mandatory |
| `--path-remap /mnt/ws01:C` | report `C:\Windows\…` instead of `/mnt/ws01/Windows/…` (`current:original`) |
| `--target-os windows` | Windows path style, heuristics and excludes on a Linux analysis host |
| `-j WS01` | original host name in all output and in the file names |
| `--audit-trail` | writes `WS01_thor_audit_<time>.jsonl.zst` into `-e` |

Several volumes: scan each with its own remap (`--path-remap /mnt/ws01_d:D`) and the same
`-j`; add `--scan-id WS01-image` to all runs to group them, then import all audit trails
into one case.

Memory image of the same host: `--memory-dump-file` (`-m`, lab-type license) is a separate scan.
It writes no audit trail; import its JSON log (findings only) if needed.

## 4. Validate and import

```bash
scripts/validate_audit_trail.sh /cases/WS01/WS01_thor_audit_*.jsonl.zst
zstd -dcq /cases/WS01/WS01_thor_audit_*.jsonl.zst | jq -r 'select(.type=="THOR audit record") | .object.path // empty' | head -5
#   expect C:\... paths, not /mnt/ws01/...
./thorlens import --log /cases/WS01/WS01_thor_audit_2026-11-16_1004.jsonl.zst --case WS01
jq '{source_format, timeline_rows, min_ts, max_ts, hostnames}' cases/WS01/meta.json   # hostnames: ["WS01"]
```

## 5. Analyse

```bash
./thorlens serve --case ./cases/WS01
```

- Images carry MFT/USN-derived rows (if those were parsed) and many artifact timestamps; use
  the histogram score mode and "detections only" first, then widen around hits.
- Rows dated 1601, 1899, 1970 or far in the future are artifact metadata.
- `find_related_events` (MCP) or the References tab connect files to services, tasks and
  autoruns that point at them.

## 6. Clean up

```bash
sudo umount /mnt/ws01 && sudo umount /mnt/ewf
```

## Without a lab-type license

THOR refuses `--lab`, `-j` and `--path-remap`. THOR 11 also treats FUSE mounts (the `ntfs-3g`
mount from step 1) as network file systems: a single `-p` on one turns on all-drives, which a
Server or Workstation license refuses. Mount the partition with the kernel `ntfs3` driver
instead (`sudo umount /mnt/ws01` first), then scan:

```bash
sudo mount -t ntfs3 -o ro,loop,offset=$((1026048*512)) /mnt/ewf/ewf1 /mnt/ws01
sudo ./thor-linux-64 -a Filescan -p /mnt/ws01 --target-os windows --audit-trail --no-thordb -e /cases/WS01
```

A scan that finishes in seconds with almost no files usually means THOR skipped a FUSE mount.

THOR notes that the directory looks like a mounted image and scans it with normal limits
(64 MB file size limit, resource checks). Paths stay `/mnt/ws01/…` and the host name is the
analysis machine's; record the mapping in the case notes. THOR Lite cannot write an audit
trail at all (findings-only JSON log).
