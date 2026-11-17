# macOS scan examples

Binary: `thor-macosx` (one binary for Intel and Apple Silicon; Lite: `thor-lite-macosx`). Minimum macOS:
10.13/10.14 for THOR 10.7, macOS 11 for THOR 11.

Prerequisites:

1. Run as root (`sudo`).
2. Grant **Full Disk Access** to the terminal app (System Settings > Privacy & Security > Full Disk Access).
   Without it THOR logs the warning "THOR should be started with Full Disk Access ..." and misses protected files.
3. If Gatekeeper blocks the downloaded binary, verify its signature first (`thor-util verify`, see `thor-maintenance`)
   before removing the quarantine attribute.

## Standard scan

```bash
sudo ./thor-macosx -e /var/tmp/thor-out
```

## Quick triage

```bash
sudo ./thor-macosx --quick -e /var/tmp/thor-out   # v10
sudo ./thor-macosx --fast -e /var/tmp/thor-out    # v11
```

## Conservative scan on a user's laptop

```bash
sudo ./thor-macosx --soft -e /var/tmp/thor-out
```

Soft already lowers priority and the CPU limit; `-c 40` instead keeps all checks but pauses while system CPU > 40%.

## One folder (user home, Applications)

```bash
sudo ./thor-macosx -a Filescan -p /Users/alice -p /Applications -e /var/tmp/thor-out
```

## Recent activity

```bash
sudo ./thor-macosx --lookback 7 --global-lookback -e /var/tmp/thor-out   # v10 (lookback alone does nothing on macOS)
sudo ./thor-macosx --lookback 7 --lookback-global -e /var/tmp/thor-out   # v11
```

## JSON output

```bash
sudo ./thor-macosx --jsonfile=mac01.json -e /var/tmp/thor-out   # v10 (note the =)
sudo ./thor-macosx -e /var/tmp/thor-out                          # v11 writes .jsonl by default
```

## External disks, mounted images and shares

| Location | THOR 10.7 | THOR 11 |
|---|---|---|
| `/Volumes/...` (USB disks, mounted DMG or image) | skipped unless `--alldrives` (lab-type or Lite license; `--lab` sets it) | scanned |
| sshfs mounts, `~/Library/CloudStorage` | skipped unless `--alldrives` | skipped unless `--all-drives` |
| SMB/NFS shares | skipped unless `--alldrives` | skipped unless `--all-drives` |

## Lab: mounted macOS image

```bash
# v10
sudo ./thor-macosx --lab -p /Volumes/MacImage --virtual-map /Volumes/MacImage:/ -j MAC01 -e /cases/MAC01
# v11
sudo ./thor-macosx --lab -p /Volumes/MacImage --path-remap /Volumes/MacImage:/ --target-os MacOS -j MAC01 -e /cases/MAC01
```

## Lab: mounted Windows image on a Mac

```bash
# v10
sudo ./thor-macosx --lab -p /Volumes/WinImage --virtual-map /Volumes/WinImage:C -j WKS001 -e /cases/WKS001
# v11 (--target-os is required for a Windows-style original path)
sudo ./thor-macosx --lab -p /Volumes/WinImage --path-remap /Volumes/WinImage:C --target-os Windows -j WKS001 -e /cases/WKS001
```

Mount images read-only (`hdiutil attach -readonly`, or a read-only NTFS driver).

## Debug one folder

```bash
sudo ./thor-macosx -a Filescan -p /tmp/suspect --nothordb --debug --printall -e /var/tmp/thor-debug     # v10
sudo ./thor-macosx -a Filescan -p /tmp/suspect --no-thordb --debug --print-files -e /var/tmp/thor-debug # v11
```

## Notes

- macOS modules: Filescan, ProcessCheck, Autoruns, Users, LoggedIn, Profiles, Hosts, Env, Timestomp, KnowledgeDB.
- Some SIP-protected locations stay unreadable even as root with Full Disk Access; that is expected.
