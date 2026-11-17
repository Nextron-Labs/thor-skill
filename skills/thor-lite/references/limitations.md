# THOR Lite feature matrix

Verified against THOR 10.7 and THOR 11 Lite builds, with the THOR Lite booklet for usage terms.
"License" rows depend on the license, not the build. Signature counts are not given here because they change with
every signature release; check `--print-signatures` / `--list-signatures`.

## How to recognise Lite

- Binary name contains `lite` (`thor64-lite.exe`, `thor-lite-linux-64`, `thor-lite-macosx`, `thor-lite-util`).
- Startup notice: "Some modules and features are not available in Lite version and will be disabled", then the
  non-commercial notice with a 5-second pause.
- Disabled components are logged with reasons: v10 "Disabling module X due to Lite version" /
  "Disabling feature X due to Lite version" (or "... due to license restrictions"); v11 "Component is not available in
  THOR Lite", "License restrictions", "Component unavailable for this platform", "Deactivated by default".
- ThorDB file `thor10-lite.db` (v10) or `thor-lite.db` (v11).

## Modules

| Module | Lite 10.7 | Lite 11 | Full THOR |
|---|---|---|---|
| Filescan (files, archives, logs, EVTX files as files) | yes | yes | yes |
| ProcessCheck (process memory YARA, handles, connections) | yes | yes | yes |
| Autoruns | yes | yes | yes |
| Eventlog (live Windows event logs, Sigma) | only with license special `allowsigma` | yes (Windows) | yes |
| DeepDive (`-m` memory dump) | yes, license accepted since 10.7.30 | no (stub) | yes, lab-type license |
| RegistryChecks, SHIM cache, Amcache, services, scheduled tasks, WMI, users, logons, network sessions/shares, mutex, pipes, DNS cache, hosts, firewall, rootkit, MFT, cron, kernel modules, and others | no | no | yes |
| Artifact Collector | no | no | Incident Response license or `deepforensic` special |

Since 10.7.29 a Lite license can carry an explicit module list that enables more modules; standard Lite licenses don't.

## Features and outputs

| Feature | Lite 10.7 | Lite 11 | Full THOR |
|---|---|---|---|
| YARA (files, process memory) | yes | yes | yes |
| Filename, hash, keyword, C2 IOCs | yes | yes | yes |
| STIX IOCs | no | yes | yes |
| Sigma (built-in and custom) | only with `allowsigma`; standalone Lite skips custom Sigma | engine built in; custom object-based Sigma supported (manual) | yes |
| EVTX parsing | only with `allowsigma` | yes | yes |
| Log file scanning, ETL, journald, Linux audit log | log files and ETL yes | yes | yes |
| Archive scanning | yes (10.7.22+) | yes | yes |
| Registry hive, Amcache, prefetch, LNK, WER, web history and other artifact parsers | no | no | yes |
| Process integrity (PE-Sieve, Windows) | yes | yes | yes |
| ThorDB (resume, delta, timing) | yes | yes | yes |
| Plugins | n/a | yes | yes (v11) |
| Audit trail (THOR Lens input) | no | flag accepted, no output | v10 experimental, v11 yes |
| JSON / HTML / CSV / syslog | yes | yes | yes |
| VirusTotal lookups | no | yes | yes |
| Private Nextron signature set | no (open-source set) | no | yes |
| YARA Forge | yes | yes | yes |

## Modes, flags and licensing

| Item | Lite 10.7 | Lite 11 | Full THOR |
|---|---|---|---|
| Default, `--soft`, `--quick`/`--fast`, `--intense`/`--deep`, `--diff`/`--delta`, lookback | yes | yes | yes |
| `--threads` | yes | yes | yes |
| `--lab` | refused | refused | lab-type license |
| `-j`, `--virtual-map`/`--path-remap` | refused | refused | lab-type license or special |
| `--target-os` | n/a | yes (not license-gated) | yes |
| `--alldrives`/`--all-drives` | accepted | accepted | lab-type license or special |
| `--nodoublecheck`/`--no-scan-lock`, `--dropzone` | refused | refused | lab-type license (drop zone also Thunderstorm) |
| THOR Remote | disabled | disabled | yes (Windows) |
| License download from Management Center / Portal | no | no | yes |
| Thunderstorm | no | no | v10 built in, v11 separate tool |
| Commercial / customer engagements | no (internal use, government, education, research only) | same | yes |
| Support | community | community | Nextron support |

## Lab-like scan without `--lab`

```text
v10  -a Filescan --intense --norescontrol --cross-platform --threads 0 --nothordb -p /mnt/evidence -e OUT
v11  --module Filescan --deep --cross-platform-paths --no-thordb -p /mnt/evidence -e OUT   (+ --target-os Windows for a Windows image on Linux)
```

| Flag | Why |
|---|---|
| `-a Filescan` / `--module Filescan` | only the file walk; live-system modules make no sense on a mounted image |
| `--intense` / `--deep` | every file deep-scanned, 200 MB size limit, built-in excludes off |
| `--norescontrol` (v10) | no free-RAM stop; v11 `--deep` implies it |
| `--cross-platform` / `--cross-platform-paths` | filename IOCs match both `\` and `/` path styles (it does not change YARA or hash IOCs) |
| `--threads 0` (v10) | all cores; v11 deep uses all cores already |
| `--nothordb` / `--no-thordb` | keeps lab work out of the host's ThorDB |

Still missing compared to `--lab`: path remapping (findings keep mount paths), original host name, parallel instances.

## THOR Cloud Lite vs standalone Lite

| | THOR Lite (standalone) | THOR Cloud Lite |
|---|---|---|
| Operation | command line, scripts, offline systems | web console, campaigns, launcher per platform |
| Modules | Lite module set (above) | full THOR module set incl. registry, SHIM cache, Amcache, event logs, tasks, services, WMI, users, logons |
| Rules | open-source signatures, YARA Forge, own IOCs and YARA | same plus Sigma rules and own Sigma |
| Quota | none | 30 free scans per month |
| Results | files per host | uploaded to the campaign |
