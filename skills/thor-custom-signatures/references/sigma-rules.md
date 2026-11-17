# Sigma rules in THOR

Read this when writing custom Sigma rules, when a Sigma rule does not load or match, or when mapping your own log
files. Folder: THOR 10 anywhere below `custom-signatures/` (convention `custom-signatures/sigma/`); THOR 11 only
`custom-signatures/sigma/`. Extensions `.yml` (multi-document files allowed) and `.yms` (encrypted). `.yaml` is
**not** loaded as Sigma.

## 1. What THOR applies Sigma to

| Kind | THOR 10 | THOR 11 |
|---|---|---|
| Windows event logs | live logs (Eventlog module) and `.evtx` files found by Filescan | same |
| Text log files | log files found by Filescan (`File:<path>` sources) | same, plus journald and Linux audit log |
| Running processes | rules with `category: process_creation` (fields `Image`, `CommandLine`, `User`, `ParentImage`, `ParentCommandLine`) | use object rules on `category: process` instead |
| Any THOR object | - | object-based rules (`service: THOR`, section 4) |

THOR Lite: v10 Lite skips Sigma unless the license includes it (Cloud Lite); v11 Lite enables Sigma.
Sigma rules are applied by THOR, not by Sigma backends: no conversion step, the YAML is loaded directly.

## 2. Loading rules (applies to custom rules too)

- **Minimum level**, checked at load time: rules below it are dropped (Debug "Skipping Sigma rule that is below
  minimum Sigma level"). Default `high`; `--intense` (10) / `--deep` (11) lower it to `medium` unless set.
  Set it with `--minimum-sigma-level <level>` (THOR 10) or `--sigma-threshold <level>` (THOR 11, old name accepted).
  Levels: informational, low, medium, high, critical. A rule without `level` is always loaded (score 40).
- **THOR 11 `score:` field** in the rule (`score: 75`, integer) replaces the level-based score **and** bypasses the
  minimum level. THOR 10 ignores it.
- Level → score: low 40, medium 50, high 70, critical 100, other/empty 40. Alert needs a total >= 81 and at least one
  subscore >= 76 (both versions), so only `critical` or `score: 81+` rules alone produce Alerts.
- **THOR 11 `--sigma-ruleset core|core+|core++|emerging_threats|threat_hunting|all`** selects built-in rules by
  status/level/`detection.*` tags. When any ruleset is given, the minimum level is not applied (custom rules included).
- Skipped: `status: deprecated`; legacy aggregations (`| count()`; Debug only); rules without `condition`
  (THOR 11 Error "Invalid sigma rule (missing condition)").
- Errors: `Could not parse rules from Sigma file` (YAML/Sigma syntax, whole file skipped), `Could not add Sigma rule`
  (THOR 10 then drops the rest of that file).
- Matches per rule are muted after 10 hits with a Notice: "Sigma rule triggered more than 10 times" (THOR 10),
  "Rule triggered more than 10 times" (THOR 11, live Eventlog module only). Raise with hidden `--mute-sigma-rule N`
  (both versions, 0 = never mute). Show all: `--showall` (THOR 10), `--show-all` (THOR 11; its Notice wrongly
  says `--showall`), or `--lab`.
- Selectors/filters (`--init-selector`, `--signature-include` …) test title + description + references.

## 3. Log-based rules

Use standard SigmaHQ log sources and field names; THOR's built-in mapping (the THOR config in the SigmaHQ repo,
`tests/thor.yml`) maps them to event log channels and log files.

```yaml
title: Service Installed from User-Writable Folder
id: 2e5b8f41-7c3d-4a19-b6e2-9d0c1f4a7e10
status: experimental
description: Detects service installations (System 7045) whose image path points to a user-writable folder
author: Your Name
date: 2026-11-16
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
        ImagePath|contains:
            - '\Users\Public\'
            - '\AppData\'
            - '\Windows\Temp\'
    condition: selection
falsepositives:
    - Software installers
level: high
```

Own log files: define a log source in `config/sigma.yml` (THOR program folder; template `config/tmpl-sigma.yml`).
`sources` are glob patterns on `File:<full path>` (files found by Filescan) or `WinEventLog:<channel>`:

```yaml
logsources:
  myapp-access:
    product: myapp
    service: access
    sources:
      - "File:/var/log/myapp/*.log"
```
Rule side: `logsource: {product: myapp, service: access}`. Plain log lines have no fields: use keyword detection
(a list under a search identifier without field names, e.g. `keywords: ['/wp-admin/setup-config.php']` +
`condition: keywords`).

## 4. Object-based rules (THOR 11 only)

THOR registers one log source per object type: `product` = target OS (`windows`, `linux`, `macos`; from
`--target-os` when scanning images), `service: THOR`, `category` = object type.

```yaml
logsource:
    service: THOR
    category: process          # object type, exact spelling and case
    product: linux             # optional
```

Rules:
- `category` must equal the object type name (`Windows service`, `autorun entry`, `cron job`, `AmCache entry`).
  A misspelled category produces **no error**: the rule loads and never matches.
- The pre-release form `product: THOR` + `service: <type>` does not match anything in current THOR 11.
- Fields = JSON field names as in the JSON log, nested with dots, arrays by index: `image.path`, `command`,
  `parent_info.exe`, `hashes.sha256`, `commands.0.command`. Case-sensitive, lowercase. UPPERCASE text-log names
  (`COMMAND`, `IMAGE`) never match. `field: null` = field missing, `field: ''` = empty.
- Sub-object categories `process.handles` and `process.connections` evaluate each handle/connection on its own
  together with the process fields (on name collisions the handle/connection field wins).
- Every object of every module is evaluated: keep selections specific, avoid lone `|contains` on short strings.

Find types and fields (no scan needed):
```bash
./thor-linux-64 --describe-object-type all            # every type with JSON schema
./thor-linux-64 --describe-object-type "Windows service"
./thor-linux-64 --module Autoruns --log-object "autorun entry:5" --console-json --no-thordb   # real values
```

Verified fields of common types (THOR 11):

| Object type (`category`) | Useful fields |
|---|---|
| `process` | `pid`, `name`, `command`, `owner`, `image.path`, `image.hashes.sha256`, `parent_info.pid`, `parent_info.exe`, `parent_info.command`, `tree`, `created`, `session` |
| `Windows service` | `service_name`, `key`, `key_name`, `start_type`, `service_type`, `user`, `description`, `command`, `failure_command`, `image.path` |
| `autorun entry` | `autorun_type`, `location`, `entry`, `launch_string`, `arguments`, `image.path` |
| `scheduled task` | `name`, `path`, `commands.0.command`, `commands.0.image.path`, `user`, `run_level`, `logon_type`, `enabled`, `triggers` |
| `cron job` | `user`, `schedule`, `command` |
| `systemd service` | `command`, `run_as_user`, `run_as_group`, `unit.path`, `image.path` |
| `Linux kernel module` | `name`, `size`, `included_in_kernel`, `ref_count`, `used_by`, `version`, `load_state`, `file.path` |
| `AmCache entry` | `sha1`, `file.path`, `product`, `company`, `first_run` |
| `file` | `path`, `extension`, `magic_header`, `size`, `hashes.md5`, `hashes.sha1`, `hashes.sha256` |
| `registry value` | `key`, `value`, `modified`, `size` |

All 84 object types: AIX platform information, AmCache entry, antivirus exclusion, antivirus product, at job,
audit log entry, authorized_keys entry, autorun entry, cron job, DetectionAdd MPLog entry, DNS cache entry,
DoublePulsar Handshake, eBPF program, EMS detection MPLog entry, end of life report, environment variable,
EstimatedImpact MPLog entry, event, eventlog entry, file, file chunk, firewall rule, groups.xml user, hosts file
entry, hotfix summary, init.d service, journal log entry, jump list entry, KnowledgeDB entry, Linux kernel module,
Linux platform information, log line, logged in user, LSA session, MacOS platform information, MFT entry,
MS Office connection cache entry, mutex, named pipe, network connecting thread, network session, network share,
pipe list, PowerShell module analysis cache module entry, prefetch info, process, process start, quarantine event,
raw firewall rule, reason, registered debugger, registry key, registry scheduled task, registry value, rootkit,
scheduled task, SDN query MPLog entry, shellbag entry, shim cache, shim cache entry, shim database entry, sparse
data, SRUM Resource Usage Entry, structured data from plugin, system information, systemd service, TeamViewer
password, THOR assessment, THOR invocation information, THOR message, Tomcat user, Unix permissions, Unix user,
User Access Log Entry, user profile, USN entry, web download, web page visit, Windows permissions, Windows platform
information, Windows service, Windows user, WMI element, WMI startup command. Plugins can add more. The set can
change between THOR 11 builds; `--describe-object-type all` is authoritative.

Tested example rules (service, autorun, cron job, process): `examples/sigma-object-rules.md` in this skill.

## 5. Testing

```bash
# Load check only
./thor-linux-64 --list-signatures | grep -i "my rule title"          # THOR 11
./thor-linux-64 --print-signatures | grep -i "my rule title"         # THOR 10
# Log-based: exported .evtx / .log files in a test folder are parsed by Filescan
./thor-linux-64 --custom-signatures-only --module Filescan --path /tmp/evtx-test --no-thordb -e /tmp/thor-out   # THOR 11
./thor-linux-64 --customonly -a Filescan -p /tmp/evtx-test --nothordb -e /tmp/thor-out                        # THOR 10
# Object-based (THOR 11): run only the module that produces the object type
./thor-linux-64 --custom-signatures-only --module Cron --no-thordb -e /tmp/thor-out
```
Filter license lines from console output: `| grep -v -e LICENSE_OWNER -e 'License file found' -e 'Scan Information'`.
Startup: THOR 11 `Successfully compiled N Sigma rules`; THOR 10 `Adding sigma rules from N files in <dir>` and
`Successfully compiled N sigma rules`. Use `--debug` to see "Skipping Sigma rule …" reasons.
Module names producing common objects: `ProcessCheck` (process), `Autoruns` (autorun entry), `ServiceCheck`
(Windows/systemd service), `ScheduledTasks` (scheduled task), `Cron` (cron job), `lsmod` (Linux kernel module),
`Eventlog` (live event logs).

## 6. Encryption

`thor-util encrypt my-rule.yml` → `my-rule.yms` (same folder or `--destdir`). Place it in the Sigma folder.
