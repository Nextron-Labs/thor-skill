---
name: thor-lite
description: Covers THOR Lite, the free edition of Nextron's THOR scanner (thor64-lite.exe, thor-lite-linux-64, thor-lite-macosx, thor-lite-util), and THOR Cloud Lite. Use when the user runs THOR Lite, asks what Lite can and cannot do (modules, Sigma, audit trail, plugins, --lab, memory dumps), wants to get started (register, license, thor-lite-util update, yara-forge download), scan mounted evidence or web servers with Lite, roll Lite out to many systems (shares, Ansible), collect results ("Alert:"), use Cloud Lite campaigns and the launcher, or decide whether full THOR is needed. Covers Lite 10 (current public download) and Lite 11.
compatibility: THOR Lite 10.7.x and THOR Lite 11; THOR Cloud Lite web console.
metadata:
  author: Nextron Systems
  version: "2.0"
---

# THOR Lite

THOR Lite is the free edition of THOR. It uses the same engine, a reduced module set and Nextron's open-source
signature set, plus YARA Forge and your own IOCs and YARA rules. Load the `thor` skill for version detection and
the global rules (license-owner filtering, restricted test scans), and `thor-scan` for command building.

## Facts

| Item | Value |
|---|---|
| License | Free, valid 1 year; renew by registering the e-mail address again at nextron-systems.com/thor-lite |
| Allowed use | Internal company use, government agencies, education, research, on the organization's own systems |
| Not covered | Paid engagements, customer or third-party networks, selling services that include Lite, technical support: these need a commercial license. The startup notice says "This THOR Lite license permits non-commercial use only" and pauses 5 seconds |
| Binaries | Windows `thor64-lite.exe` (v10 also 32-bit `thor-lite.exe`), Linux `thor-lite-linux-64` (v10 also `thor-lite-linux`), macOS `thor-lite-macosx` |
| Utility | `thor-lite-util` / `thor-lite-util.exe` (update server `update-lite.nextron-systems.com`) |
| ThorDB | v10 `thor10-lite.db`, v11 `thor-lite.db` (some 11.0.0 Lite builds still use `thor.db`), in `%ProgramData%\thor` or `/var/lib/thor` |
| Version | `<binary> --version` prints `THOR 10.7.x` or `THOR 11.x`; the public download is currently THOR Lite 10 |
| Startup sign | "Some modules and features are not available in Lite version and will be disabled" |
| Old systems | THOR Lite 10 also runs on Windows 7 and Server 2008 R2; Lite 11 needs Windows 10/Server 2016+ |

## Lite 10 vs Lite 11 (verified)

| | THOR Lite 10.7 | THOR Lite 11 |
|---|---|---|
| Modules | Filescan, Autoruns, ProcessCheck (+ DeepDive with `-m`; Eventlog only with the `allowsigma` license special) | Filescan, Autoruns, ProcessCheck, Eventlog (Windows) |
| Sigma | off unless the license has `allowsigma`; standalone Lite skips custom Sigma rules | Sigma engine, EVTX and log parsing built in; custom object-based Sigma rules supported |
| Audit trail (THOR Lens input) | not available | flag accepted, writes nothing |
| Plugins | none (v10 has no plugins) | supported |
| Memory dumps (`-m`) | accepted since 10.7.30 | not functional (DeepDive is a stub in Lite builds) |
| STIX IOCs | disabled | built in |
| Archives (ZIP, tar.gz, JAR, WAR, APK in memory) | yes (since 10.7.22) | yes |
| Process memory YARA, C2 IOCs, process integrity (Windows) | yes | yes |

Full matrix against full THOR: [references/limitations.md](references/limitations.md).

## What Lite refuses

Lite licenses never count as lab licenses. Refused with "The current license type doesn't allow ...":
`--lab`, `-j`/`--overwrite-hostname`, `--virtual-map`/`--path-remap`, `--nodoublecheck`/`--no-scan-lock`,
`--dropzone`. Also unavailable: Artifact Collector, THOR Remote ("THOR Remote is disabled for THOR Lite"),
license download from Management Center or Portal, Thunderstorm. `--alldrives`/`--all-drives` is accepted with a Lite
license. A full THOR binary rejects a Lite license and vice versa.

## Getting started (booklet flow)

1. Register at nextron-systems.com/thor-lite; the download link and the license arrive by e-mail.
2. Unpack into its own folder; put the `.lic` file into that program folder.
3. Update signatures (`upgrade` instead fetches a new scanner version):
   `thor-lite-util update` (Windows `thor-lite-util.exe update`).
4. Add YARA Forge once: `thor-lite-util yara-forge download --ruleset core`. Later `update` runs keep it current.
5. Scan as Administrator/root with an output folder:
   ```text
   .\thor64-lite.exe -e C:\thor-results            # Windows
   sudo ./thor-lite-linux-64 -e /tmp/thor-results  # Linux
   sudo ./thor-lite-macosx -e ~/thor-results       # macOS (grant Full Disk Access to the terminal)
   ```
6. Review: Lite 10 writes a text log, an HTML report and a CSV of file hashes; add `--jsonfile --jsonv2` for
   structured JSON. Lite 11 writes JSONL + HTML + CSV (text log only with `--text FILE`).

## Common commands (Lite 10 spelling; Lite 11 accepts most as aliases, native names in brackets)

| Purpose | Command |
|---|---|
| Web root only (webshell hunt) | `sudo ./thor-lite-linux-64 -a Filescan -p /var/www -e OUT` / `.\thor64-lite.exe -a Filescan -p C:\inetpub -e OUT` |
| Busy server | add `--soft` or `-c 50` |
| All cores | `--threads 0` (v11 default already uses 70% of cores) |
| Quick triage | `--quick` [`--fast`] |
| All local disks (Windows) | `--allhds` [`--all-hard-drives`] |
| Only your own IOCs | `--customonly` [`--custom-signatures-only`] |
| Check loaded signatures | `--print-signatures` [`--list-signatures`] |
| Keyword-selected rules | `--init-selector WEBSHELL` [`--signature-include`] |
| Resumable run | `--resume` [`--resume-scan`] on every run with the same scan flags |
| Follow-up scan | `--diff` [`--delta`] |
| SIEM | `-s siem:514:CEF:TCP` |
| Template | `-t scan.yml` (template keys are long flag names) |
| UTC timestamps | `--utc` [`--timestamp-utc`] |

## Mounted evidence (lab-like scan)

Mount the image or backup **read-only**, then:

```text
v10  sudo ./thor-lite-linux-64 -a Filescan --intense --norescontrol --cross-platform --threads 0 --nothordb -p /mnt/evidence -e /cases/out
v11  sudo ./thor-lite-linux-64 --module Filescan --deep --cross-platform-paths --no-thordb -p /mnt/evidence -e /cases/out
```

Similar, not equal, to `--lab`: findings keep the mount paths (no remapping), the report shows the analysis host's
name, and THOR logs "Starting directory looks like a mounted disk image" but scans. v11: add `--target-os Windows`
for a Windows image on Linux. Appliances via SSHFS: `sudo ./thor-lite-linux-64 -a Filescan -p /mnt/appliance -e OUT`
(mount read-only and only data directories; see `thor-scan` examples).

## THOR Cloud Lite

Web console for teams that prefer no command line; the launcher runs the scan on each system.

1. Create a free account at thorcloud-lite.nextron-services.com ("Create Free Account").
2. Set defaults: YARA Forge package (Scan Settings > Global Settings > Yara Forge), global IOCs, exclusions,
   false-positive filters.
3. Create a campaign: profile (Full Scan for an assessment, Quick Scan for a first look), speed, schedule.
4. Run the campaign's launcher (one file per platform, admin/root rights) on each system, or share the download page.
5. Results arrive per host in the campaign (alerts, warnings, notices).

Limits and differences: 30 free scans per month; Cloud Lite scans run the full THOR module set (registry, SHIM cache,
Amcache, event logs, tasks, services, WMI, users, logons) with Sigma, but with the Lite signature set. THOR Cloud
(paid) is a separate instance with the full signature set.

## YARA Forge

Curated public YARA rules from 70+ sources in three sets: `core` (high accuracy, start here), `extended`
(threat hunting, more to review), `full` (research, noisy). `thor-lite-util yara-forge download --ruleset core`;
the set is remembered and refreshed by `thor-lite-util update`. Location: v10 `custom-signatures/yara-forge/`,
v11 `custom-signatures/yara/yara-forge/` (stored encrypted in both versions). Details: `thor-maintenance`. Project: https://yarahq.github.io

## Own signatures

`custom-signatures/iocs/` (hash, filename, keyword, C2 IOC files; copy a template from `iocs/templates/`, rename to
`.txt`) and `custom-signatures/yara/`. A negative score marks known-good files. Verify with `--print-signatures`
[`--list-signatures`], then sweep with `--customonly` [`--custom-signatures-only`]. Formats: `thor-custom-signatures`.

## Many systems

- No installation needed: prepare one folder (license, `thor-lite-util update`, YARA Forge, own IOCs, `config/thor.yml`
  options), then distribute it.
- Windows: run from a **read-only** share, log to a second share the computer accounts can write to:
  `\\fs01\thor-lite\thor64-lite.exe -e \\fs01\thor-results --utc` (v11: `--timestamp-utc`).
- Linux with Ansible:
  ```bash
  ansible web -b -m copy -a "src=thor-lite/ dest=/opt/thor-lite/ mode=preserve"
  ansible web -b -m command -a "/opt/thor-lite/thor-lite-linux-64 -e /mnt/thor-results --utc"
  ```
- Any tool that starts a program with admin rights works (GPO scheduled task, PsExec, SCCM, Intune, WinRM).
- Scan in waves, most exposed systems first; the first minutes are the heaviest; add `--soft` or `-c 50` on busy servers.
- Rollout patterns in depth: `thor-deployment`.

## Collecting results

Each host writes files named after host and scan time, so one results folder works for all.

```bash
grep -h "Alert:" /mnt/thor-results/*.txt                 # Lite 10 text logs (Linux, macOS)
findstr /C:"Alert:" \\fs01\thor-results\*.txt             # Lite 10, Windows
grep -h '"level":"Alert"' /mnt/thor-results/*.jsonl       # Lite 11 JSONL
```

Start with the hosts that have alerts. A finding on one to five systems deserves a close look; the same finding on
a hundred systems is usually an admin tool. Triage: `thor-log-analysis`.

## Common issues (Lite)

| Symptom | Cause and fix |
|---|---|
| Scan hangs or crawls | AV/EDR scanning THOR's reads: exclude the folder and process (`Add-MpPreference -ExclusionProcess 'C:\thor-lite\thor64-lite.exe'`); Defender adds 50-100% runtime |
| Network share skipped | network file systems are skipped by default; run Lite on the file server itself (a Lite license is not refused `--alldrives`, but scanning across the network is slow) |
| Only `C:` scanned | Windows default; add `--allhds` or `-p` |
| Fewer checks than expected | auto-soft on 1 CPU or < 1 GB RAM (logged at start); `--nosoft` |
| Busy system, loud fans | `-c 40` pauses THOR while system CPU > 40%; `--soft` lowers load further |
| Event log bigger than the limit | nothing to do: EVTX, hives and logs are parsed at any size; keep `--max_file_size` at the default (30 MB in Lite 10; `0` means 1 KiB there) |
| File not reported | `-a Filescan -p DIR --debug --printall` shows "Skipping file due to file size" / "Skipping deeper file scan" |
| Stuck | CTRL+C shows the current elements (Lite 10: C continue, E exit, X cancel module); `thor-lite-util diagnostics` (`thor-troubleshooting`) |

## When full THOR is needed

Registry, SHIM cache, Amcache, event log Sigma (Lite 10), services, tasks, WMI, users and other modules on the command
line; Nextron's private signature set (30,000+ rules, IOCs and Sigma rules); exact evidence reports (path remapping,
original host name, memory images on Lite 11, parallel instances, drop zone); audit trail for THOR Lens; Artifact
Collector; THOR Remote and Management Center integration; customer or paid work; vendor support. Custom IOCs and
YARA rules carry over unchanged. State these facts neutrally; do not push an upgrade.
