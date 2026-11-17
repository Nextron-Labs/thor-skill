# Scripted rollout with your own tools

All methods below start the same prepared THOR folder with admin/root rights. Prepare the
folder once (update, YARA Forge, custom signatures, `config/thor.yml`, licenses) as described
in SKILL.md, then pick the launcher.

## The portable folder

```text
thor/                          (v11 Windows example)
├── thor64.exe   thor-util.exe   *.sig
├── config/thor.yml            options applied on every run (also from UNC)
├── config/thor.yml.defaults   v11 reference of all keys
├── custom-signatures/{iocs,yara,sigma,stix,misc}/
├── signatures/  plugins/  tools/  docs/
└── licenses/*.lic             host licenses (any subfolder is searched)
```

Lite: `thor64-lite.exe`, `thor-lite-linux-64`, `thor-lite-macosx`, `thor-lite-util`.
v10 additionally ships 32-bit binaries (`thor.exe`, `thor-linux`); v11 is 64-bit only
(x64 and ARM64 use the same names).

Options per version (YAML key = long flag name):

| Purpose | v10.7 | v11 |
|---|---|---|
| output directory | `rebase-dir` / `-e` | `output-directory` / `-e` |
| UTC timestamps | `utc` | `timestamp-utc` (alias `utc`) |
| JSON log | `jsonfile` (off by default; v1, `jsonv2: true` for v2) | on by default (`.jsonl`, v3) |
| text log | on by default (`.txt`) | only with `text`/`-l` |
| SIEM | `syslog` / `-s` | `remote-log` / `-s` |
| CPU limit | `cpulimit` / `-c` (95) | `cpu-limit` / `-c` (70) |
| runtime limit | `max_runtime` (h, 168) | `timeout` (h, 168) |
| template file | `-t/--template` | `-t/--config` (alias `--template`) |
| stats line per host | `--stats-file[=f]` | `--stats-csv[=f]` |

Precedence: command line > `-t` file > `config/thor.yml`.

## Windows network share

1. Read-only share `\\fs01\thor` with the unpacked folder (licenses in `licenses\`).
2. Writable share `\\fs01\thor-results`.
3. `Domain Computers`: read on the program share, write (create files) on the results share,
   on both share and NTFS permissions. Tasks running as SYSTEM authenticate as `DOMAIN\HOST$`.
4. `config\thor.yml` on the program share: output directory (and other options).
5. Test interactively (elevated prompt) and as SYSTEM (`psexec -s …`) with a restricted scan:
   `\\fs01\thor\thor64.exe -a Filescan -p C:\Windows\Temp --no-thordb` (v10 `--nothordb`); check
   that the license is accepted and files appear on the results share. A full run on 2-3 pilot
   hosts is a user-approved pilot, not a test.

Running THOR directly from UNC works for the scan itself. THOR Remote is the exception: it
must be started from a local disk.

Full walkthrough with GPO: `examples/windows-share-gpo.md` in this skill.

## Launchers

### GPO Scheduled Task (domain)

Computer Configuration → Preferences → Control Panel Settings → Scheduled Tasks → New →
*Immediate Task (At least Windows 7)* (one-time) or *Scheduled Task* (fixed time/recurring).
User `NT AUTHORITY\System`, *Run whether user is logged on or not*, *Run with highest
privileges*; action `\\fs01\thor\thor64.exe` (arguments optional if `thor.yml` holds them);
Settings: *Stop the task if it runs longer than* > expected scan time (3 days default is fine);
Common: *Apply once and do not reapply* for Immediate Tasks. Hosts pick it up at the next
policy refresh (90 min ± 30) or `gpupdate /force`. Link the GPO to one OU per wave.

### PsExec

```bat
:: create a one-time task on a host
psexec \\srv01 -u DOMAIN\admin -p **** schtasks /create /tn "THOR Run" /tr "\\fs01\thor\thor64.exe" /sc ONCE /st 08:00:00 /ru SYSTEM /rl HIGHEST
:: or start directly as SYSTEM, detached
psexec \\srv01 -s -d \\fs01\thor\thor64.exe
```

Prefer Kerberos (run PsExec as the domain admin, no `-u/-p`): explicit credentials expose
them on the target.

### WMIC / remote process creation

```bat
wmic /node:10.0.2.10 /user:MYDOM\scanadmin process call create "cmd.exe /c \\fs01\thor\thor64.exe"
```

The process runs as the connecting user; that user (not the computer account) needs share
access. WMIC is deprecated on current Windows; `Invoke-CimMethod -ClassName Win32_Process
-MethodName Create` is the PowerShell equivalent.

### SCCM / Configuration Manager

Package or script deployment as SYSTEM that starts `\\fs01\thor\thor64.exe` (or a copy in the
package content). Same share permissions as GPO. Configure the program's maximum run time
above the scan time, or have the deployment create a one-time scheduled task that runs THOR
detached.

### Intune

Platform script or Win32 app running as SYSTEM. Intune-managed devices are often not
domain-joined and cannot reach SMB shares: ship the folder with the app (large: signatures) or
download it from an internal web server, write results locally and upload them, or use THOR
Cloud launchers instead. Start THOR via a one-time scheduled task so Intune's script/installer
timeouts do not kill the scan.

### EDR live response / THOR Seed

THOR Seed is Nextron's PowerShell wrapper for automated deployment, typically through an EDR's
live-response feature: https://github.com/NextronSystems/nextron-helper-scripts/tree/master/thor-seed.
Check the EDR's upload size and session time limits; start THOR detached.

### Ansible

Linux/macOS over SSH, Windows over WinRM: copy the folder, run THOR, fetch results, clean up.
Full playbook: `examples/ansible-linux.md`. The playbook template in the THOR manual is
outdated (binary `thor-x64`, ramfs size 60 MB, text log flag); do not copy it unchanged.

### Velociraptor

Nextron artifacts `Generic.Scanner.Thor`, `Generic.Scanner.ThorZIP`,
`Generic.Scanner.ThorCloud`: https://github.com/NextronSystems/velociraptor-artifacts-thor.
See `examples/velociraptor.md` (v11 caveats).

### Plain SSH loop (small Linux sets)

```bash
while read -r h; do
  ssh -n root@"$h" 'mkdir -p /opt/thor && tar -xzf - -C /opt/thor' < thor-linux.tar.gz &&
  ssh -n root@"$h" '/opt/thor/thor-linux-64 -e /var/tmp/thor-results --timestamp-utc' &&
  scp -r root@"$h":/var/tmp/thor-results ./results/"$h"
done < hosts.txt
```

(v10: `--utc` instead of `--timestamp-utc`.) Run hosts in parallel batches (`xargs -P`) for
waves; keep each SSH session alive for the full scan or start THOR with `nohup`/`systemd-run`.

## Linux and macOS specifics

- Run as root. macOS: grant Full Disk Access to the launching process (terminal, MDM agent),
  otherwise protected folders are skipped.
- Do not run from a `noexec` mount (`/tmp` often is); use `/opt/thor` or a dedicated path.
- NFS/SMB-mounted program folders work if executable; results written by root to root-squashed
  NFS fail: use a local `-e` and fetch.
- Remove the folder after the scan if policy requires; ThorDB stays in `/var/lib/thor/`
  (v11 `thor.db`, v10 `thor10.db`; Lite `thor-lite.db` / `thor10-lite.db`).

## Load control

| Lever | v10 | v11 |
|---|---|---|
| reduced impact mode | `--soft` (CPU ≤ 70 %, skips heavy modules, auto on 1 CPU or < 1 GB RAM) | `--soft` (CPU 50 %, 1 thread, skips heavy modules); not with `--deep`/`--lab`/`--no-resource-check` |
| CPU pause threshold | `-c/--cpulimit` (default 95) | `-c/--cpu-limit` (default 70, also sets threads) |
| threads | `--threads` (default 1) | `--threads` (default from CPU limit) |
| priority | `--lowprio`, `--verylowprio` | `--low-priority` (alias `--lowprio`) |
| hard stop | `--max_runtime 24` | `--timeout 24` |

Waves: start the most exposed systems first; ~1 h between waves; smaller groups for VDI/VM
farms and WAN sites. Each host pulls program and signatures from the share at start.

## Pre-flight checklist

- [ ] Package version and signatures current; same folder for all hosts of an OS
- [ ] `config/thor.yml` sets output directory, UTC, SIEM target (if any)
- [ ] Licenses for every host (or IR license) in `licenses/`; test host accepted it
- [ ] Results share writable by computer accounts, not readable by them if possible
- [ ] Test run as SYSTEM/root completed with HTML report and expected file names
- [ ] Wave plan, stop condition (`--timeout`), contact for affected system owners
- [ ] Collection plan (see `collecting-results.md`)
