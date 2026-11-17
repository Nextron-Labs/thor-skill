# Example: appliance or remote Linux via SSHFS → Lens case

Use when THOR cannot run on the target (appliance, unsupported OS or architecture, no
space) but you have SSH read access. THOR 11 runs on the analysis host and scans the
mounted file system. Only files are scanned: no processes, network connections, or live
system state of the target.

## 1. Mount read-only

```bash
mkdir -p /mnt/fw01
sshfs -o ro,reconnect,ServerAliveInterval=15 admin@fw01:/ /mnt/fw01
# key / jump host: -o IdentityFile=~/.ssh/id_ed25519   -o ProxyJump=bastion
ls /mnt/fw01/etc
```

Root (or an account that can read everything) is needed for full coverage; unreadable files
are skipped. Install: `apt install sshfs`, `dnf install fuse-sshfs`, macOS needs macFUSE.

## 2. Scan

THOR 11 treats `fuse.sshfs` as a network file system: it is skipped unless all-drives is on.
`--lab` turns all-drives on, so a lab-type license (Forensic Lab, Incident Response or Trial)
scans the mount directly and keeps the original paths and host name:

```bash
sudo ./thor-linux-64 --lab \
  -p /mnt/fw01/etc -p /mnt/fw01/var -p /mnt/fw01/home -p /mnt/fw01/tmp -p /mnt/fw01/opt \
  --path-remap /mnt/fw01:/ \
  -j fw01 \
  --audit-trail \
  -e /cases/fw01
```

- Restrict `-p` to the interesting trees: every byte crosses the network, and `--lab` scans
  deeply (all files, 200 MB file size limit, all cores). Never pass `/proc`, `/sys`, `/dev`.
- `--path-remap /mnt/fw01:/` reports `/etc/…` instead of `/mnt/fw01/etc/…`.
- Do not combine `--lab` with `--fast`/`--quick`: lab mode disables fast mode anyway.
- Windows target paths: add `--target-os windows`.

Without a lab-type license (Server or Workstation): scanning the sshfs mount does not work.
Several `-p` paths on it are skipped, and a single one turns on all-drives, which the license
refuses. Copy the trees locally and scan the copy:

```bash
sudo mkdir -p /cases/fw01/copy
sudo rsync -a /mnt/fw01/etc /mnt/fw01/var /cases/fw01/copy/
sudo ./thor-linux-64 -a Filescan -p /cases/fw01/copy --audit-trail --no-thordb -e /cases/fw01
```

Paths show `/cases/fw01/copy/…` and the host name is the analysis host; note the mapping in
the case. THOR Lite may scan the mount (all-drives is allowed) but writes no audit trail.

If `sudo` cannot read the FUSE mount, mount with `-o allow_other` (requires `user_allow_other`
in `/etc/fuse.conf`) or run THOR as the user who mounted it.

## 3. Unmount, validate, import

```bash
fusermount -u /mnt/fw01              # macOS: umount /mnt/fw01
scripts/validate_audit_trail.sh /cases/fw01/fw01_thor_audit_*.jsonl.zst
./thorlens import --log /cases/fw01/fw01_thor_audit_2026-11-16_1004.jsonl.zst --case fw01
jq '{source_format, timeline_rows, min_ts, max_ts, hostnames}' cases/fw01/meta.json
./thorlens serve --case ./cases/fw01
```

## Troubleshooting

| Problem | Fix |
|---|---|
| Mount drops during the scan | `-o reconnect,ServerAliveInterval=15`; scan smaller `-p` sets |
| Very slow | fewer/smaller paths; fast network; avoid scanning `/proc`, `/sys`, `/dev` (never pass them) |
| Permission denied on files | SSH user lacks read rights; use root or sudo-capable access on the target |
| `The current license type doesn't allow …` | no lab-type license: copy locally and scan the copy |
| Scan finishes in seconds, no files scanned | sshfs paths skipped as network file systems: use `--lab` or a local copy |
| Paths in Lens show `/mnt/fw01` | `--path-remap` missing (lab-type license) |

Alternative for many such systems: THOR Thunderstorm with a collector script that uploads
files (see the `thor-deployment` skill). Thunderstorm results are JSON logs, not audit trails.
