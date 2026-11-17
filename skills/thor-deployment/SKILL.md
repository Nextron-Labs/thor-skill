---
name: thor-deployment
description: Plans rollouts of THOR, THOR Lite and THOR Cloud scans to many systems and the collection of results. Use when the user wants to scan dozens to thousands of hosts, run thor64.exe or thor-linux-64 from a read-only network share with logs to a writable share, push THOR with Ansible, GPO scheduled tasks, PsExec, WMIC, SCCM, Intune, Velociraptor or THOR Seed, use THOR Remote (--remote-host / --remote), the Management Center (formerly ASGARD; --management-center, --management-center-token), THOR Cloud or THOR Cloud Lite campaigns and launchers, a Thunderstorm service (tools/thunderstorm, --thunderstorm), syslog/SIEM forwarding (-s / --syslog / --remote-log host:port:CEF|JSON:TCP|TCPTLS), output placeholders (:hostname:, <hostname>), license distribution (licenses/ folder, --portal-api-key, THOR_LICENSE), scan waves and load control (--soft, --cpu-limit, -c), or merging results from many hosts (grep "Alert:", jq, thor-util report, THOR Lens). Covers THOR 10.7 and THOR 11.
compatibility: THOR 10.7.x and THOR 11 (Tech Preview / release candidates), full and Lite editions; Windows, Linux and macOS targets. Some features need specific licenses or a Management Center / THOR Cloud subscription.
metadata:
  author: Nextron Systems
  version: "2.0"
---

# THOR deployment

THOR needs no installation: one folder holds binary, signatures, config and licenses. Any
tool that can start a program with admin/root rights can run it. The work is in preparing
the folder once, controlling load, getting the right license onto each host, and bringing
the results back.

Detect the THOR version (`--version`, binary banner; the `thor` skill has the full procedure)
before writing commands. Flag names, placeholders and outputs differ.

## Choose a method

| Situation | Method | Details |
|---|---|---|
| Management Center (ASGARD) in place | MC scan campaigns with agents; results to Analysis Cockpit | [management-center-and-remote](references/management-center-and-remote.md) |
| No infrastructure, want a console, agentless | THOR Cloud / THOR Cloud Lite campaign + launcher | [thor-cloud](references/thor-cloud.md) |
| Windows domain | read-only program share + GPO Immediate/Scheduled Task as SYSTEM | [examples/windows-share-gpo](examples/windows-share-gpo.md) |
| Linux/macOS fleet with Ansible | copy folder, run, fetch logs; Windows via WinRM | [examples/ansible-linux](examples/ansible-linux.md) |
| Velociraptor deployed | Nextron artifacts (`Generic.Scanner.Thor*`) | [examples/velociraptor](examples/velociraptor.md) |
| SCCM, Intune, PsExec, WMIC, EDR live response | same portable folder, started as SYSTEM | [scripted-rollout](references/scripted-rollout.md) |
| Quick IR push to some Windows hosts, admin creds, ports 135/445 | THOR Remote (full THOR, Windows only) | [management-center-and-remote](references/management-center-and-remote.md) |
| Systems that cannot run THOR (ESXi, appliances, legacy) | Thunderstorm service + collector scripts, or SSHFS mount | [thunderstorm](references/thunderstorm.md) |
| Air-gapped site / field office | hand over the prepared ZIP, collect results | `thor-maintenance` skill (offline packs) |

THOR Lite: share, scheduled task, Ansible, Velociraptor and THOR Cloud Lite work. Not
available in Lite: THOR Remote, license retrieval from Management Center or Portal,
Thunderstorm, audit trail.

## Prepare the folder once

1. Unpack the package for each target OS (`thor-windows`, `thor-linux`, `thor-macos`; Lite:
   `thor-lite-*`). Same binary names on x64 and ARM64 in v11 (`thor64.exe`, `thor-linux-64`).
2. Update on one connected machine: `thor-util update` (signatures) or `thor-util upgrade`;
   optional `thor-util yara-forge download --ruleset core`. Lite: `thor-lite-util`. Details
   and offline packs: `thor-maintenance` skill. Careful: `thor-util upgrade` without a version
   constraint installs the stable channel (10.7) and can downgrade a THOR 11 folder.
3. Add custom IOCs/YARA/Sigma to `custom-signatures/` (v11: in `iocs/`, `yara/`, `sigma/`
   subfolders) → `thor-custom-signatures` skill.
4. Put scan options into `config/thor.yml` (always loaded from the folder next to the
   binary, also from a UNC path) or a template passed with `-t <file>`. Precedence:
   command line > `-t` template > `config/thor.yml`. YAML keys are the flag names.
5. Put licenses into `licenses/` (any subfolder of the program folder is searched).
6. Test on 2–3 representative hosts per OS/role, as SYSTEM/root, from the real location.
7. Hash or sign-check the folder (`thor-util verify`) and make the program share read-only.

Minimal `config/thor.yml` for a share rollout:

| v10.7 | v11 |
|---|---|
| `rebase-dir: '\\fs01\thor-results'` | `output-directory: '\\fs01\thor-results'` |
| `utc: true` | `timestamp-utc: true` |
| `jsonfile: ':hostname:_thor_:time:.json'` (JSON is off by default) | (JSON `.jsonl` is on by default) |
| `syslog: ['siem01:514:CEF:TCP']` | `remote-log: ['siem01:514:CEF:TCP']` |

Use single quotes in YAML for Windows paths (double quotes turn `\` into escapes).

## Output naming (hosts must not overwrite each other)

- Default file names already contain the host name: v10 `:hostname:_thor_:time:.txt/.html`,
  `:hostname:_files_md5s.csv`; v11 `<hostname>_thor_<time>.jsonl/.html`,
  `<hostname>_files_md5s.csv`. All hosts can write into one flat results share.
- Placeholders in your own names/paths: **v10 `:hostname:` and `:time:`**, **v11
  `<hostname>` and `<time>`** (`<time>` = `YYYY-MM-DD_HHMM`, local or UTC with
  `--timestamp-utc`). v11 does not expand the v10 spelling and vice versa. Quote `<…>` on the
  command line (shell redirection).
- Output goes to the current directory unless set. Scheduled tasks start in
  `C:\Windows\System32`: always set `-e` (`--rebase-dir` v10 / `--output-directory` v11).
- Missing directories in output paths are created (mode 0700 on Unix).

## Licenses for many hosts

| License | Use in rollouts |
|---|---|
| Workstation | Windows clients and macOS only; refused on Windows Server and Linux |
| Server ("Server & Workstation") | any OS and role; choose it when unsure; Linux always needs it |
| Incident Response (type Enterprise) | one license file for all hosts of an engagement |
| Forensic Lab / Trial | analysis machines; not host-bound Lab/Trial licenses ask an interactive challenge → unusable in unattended runs |
| Silent | rollout tests (no output) and update-only hosts |
| Thunderstorm / Service | only for Thunderstorm and drop-zone mode |
| THOR Lite | one license file for the folder; internal use only |

- Host-based licenses are bound to the short host name (case-insensitive). Generate them in
  bulk in the Customer Portal or Management Center and drop all `.lic` files into `licenses/`;
  THOR uses the first one valid for the host. Renamed hosts fail.
- Fetch at scan start: `--management-center <host> --management-center-token <token>` or
  `--portal-api-key <key> [--portal-contracts 3,5] [--portal-existing-license]` (v10 also
  `--portal-key`, `--portal-nonewlic`). THOR saves the result as `<hostname>.lic` in the license
  path; on a read-only share that save cannot succeed, so pre-generate or point
  `--license-path` (`-q`) at a writable location. The flag `--management-center-host` does
  not exist (manual error).
- `THOR_LICENSE` = base64 of a `.lic` file: inject one license through the deployment tool.
- Keys/tokens on the command line reach every endpoint (and possibly attackers): prefer
  contract download tokens and rotate them after the campaign.
- Never `grep` `.lic` files (encrypted). v11 `--list-licenses` lists what THOR finds, but its
  output contains owner names: don't paste it.

## Load planning

- Start in waves (e.g. 50–200 hosts, ~1 h apart); the first 10–15 minutes of each scan are
  the heaviest (fast modules, program and signature download from the share). Smaller
  waves for VMs on shared hypervisors/storage and sites behind slow WAN links.
- Busy servers: `--soft` or a lower CPU limit (`-c 50`). v10: `--cpulimit` default 95,
  `--threads` default 1, `--soft` caps CPU at 70 %. v11: `--cpu-limit` default 70 and also sets
  the thread count, `--soft` = CPU 50 % + 1 thread and is refused together with `--deep`,
  `--lab` or `--no-resource-check`.
- Hard stop: `--timeout <hours>` (v11) / `--max_runtime <hours>` (v10), default 168.
- GPO tasks: "Stop the task if it runs longer than" must exceed the scan time; tools that kill
  long-running jobs (SCCM/Intune/EDR timeouts) need THOR started as a detached scheduled task.
- One THOR per host at a time: a second instance is refused (scan lock) unless the license
  allows otherwise; schedule re-runs, don't stack them.
- Never `--lab` or `--deep` (v10 `--intense`) for fleet sweeps: lab = Filescan only and Lab
  license; deep = much slower. Repeat sweeps: `--lookback <days>` (both) or `--delta` (v11;
  v10 `--diff`), which needs the host's ThorDB from the previous run.

## Collect and merge results

- One flat share with host-named files, plus per-host stats: v11 `--stats-csv` / v10
  `--stats-file` (optional-value flags: bare or `--stats-csv=<file>`) → one CSV line per host
  with start, end, version, alert/warning/notice/error counts. Concatenate to see who
  finished.
- Finished scans end with `Thor Scan finished`; an HTML report exists only if THOR exited 0.
- Strongest findings first: v10 `grep -h "Alert:" /mnt/thor-results/*.txt`
  (Windows `findstr /C:"Alert:" \\fs01\thor-results\*.txt`); v11 JSON:
  `jq -r 'select(.type=="THOR assessment" and .meta.level=="Alert") | [.meta.hostname,.score,.message] | @tsv' *.jsonl`.
- Rare beats common: a finding on 1–5 hosts deserves attention; the same finding on 100
  hosts is usually admin software.
- HTML per host: `thor-util report --logdir <dir>` (one report per log; decrypt encrypted
  logs first). Many hosts in one timeline: THOR Lens `thorlens import --log-dir <dir>`
  (`thor-lens` skill). Large volumes: Analysis Cockpit or Splunk app/add-on, or SIEM forwarding.
- Interpretation of findings: `thor-log-analysis` skill.

Details: [collecting-results](references/collecting-results.md).

## Rules

1. Test on a few hosts as SYSTEM/root from the real share before any wave; never start a
   fleet-wide run as a "test".
2. Program share read-only, results share write-only where possible (`Domain Computers`:
   read on program share, write on results share, both share and NTFS permissions).
3. Always set an explicit output directory; check host-unique names.
4. Keep THOR's own folder clean of results (`-e` elsewhere) so the next wave isn't slowed or
   polluted.
5. Results, audit trails and diagnostics contain host and user data and license info:
   protect the share; never paste license-owner lines (filter
   `grep -v -e LICENSE_OWNER -e 'License file found' -e 'Scan Information'`).
6. Prefer TCP/TLS over UDP for SIEM forwarding; keep local log files as the authoritative copy.

## References

| File | Read when |
|---|---|
| [scripted-rollout](references/scripted-rollout.md) | shares, GPO, PsExec, WMIC, SCCM, Intune, Ansible, Velociraptor, THOR Seed, folder preparation |
| [management-center-and-remote](references/management-center-and-remote.md) | Management Center, license retrieval, THOR Remote (v10/v11 flags) |
| [thor-cloud](references/thor-cloud.md) | THOR Cloud and THOR Cloud Lite campaigns, launchers |
| [thunderstorm](references/thunderstorm.md) | sample-submission service, collectors, v10 vs v11 |
| [siem-forwarding](references/siem-forwarding.md) | `-s`/`--remote-log` syntax, CEF/JSON, TLS, local syslog, Event Log |
| [collecting-results](references/collecting-results.md) | merging, completeness checks, triage across hosts |
| [examples/windows-share-gpo](examples/windows-share-gpo.md) | end-to-end domain rollout |
| [examples/ansible-linux](examples/ansible-linux.md) | playbook for Linux (and Windows via WinRM) |
| [examples/velociraptor](examples/velociraptor.md) | hunts with the Nextron artifacts |
