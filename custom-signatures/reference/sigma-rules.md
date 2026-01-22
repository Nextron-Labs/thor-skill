# Sigma Rules in THOR

Sigma is a generic rule format for detections on structured data. Sigma is for log data what Snort is for network packets and YARA is for files.

THOR ships with the public Sigma rule set from [SigmaHQ](https://github.com/SigmaHQ/sigma) plus Nextron internal rules.

## Two Modes of Sigma Matching

| Mode | Available In | Targets |
|------|--------------|---------|
| **Log-based** | THOR v10, v11, Lite | Windows Eventlogs, `.log` files |
| **Object-based** | THOR v11 only (incl. Lite) | All 90+ THOR object types |

**Key insight:** In THOR v11, Sigma rules can match on **any object** THOR encounters - processes, services, autoruns, cron jobs, kernel modules, etc. This goes far beyond traditional log-based Sigma.

## File Format

- Extension: `.yml` (plain) or `.yms` (encrypted)
- Placement: `thor/custom-signatures/sigma/`

## Log-Based Sigma (v10 and v11)

Traditional Sigma rules that match on Windows Eventlogs and log files.

### Logsource Examples

```yaml
# Windows Eventlog
logsource:
    product: windows
    service: security

# Linux auth logs
logsource:
    product: linux
    service: auth
```

### Common Windows Services

- `security` - Security.evtx
- `system` - System.evtx
- `application` - Application.evtx
- `powershell` - PowerShell logs
- `sysmon` - Sysmon logs

### Example: Process Creation Detection

```yaml
title: Suspicious PowerShell Download
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'powershell'
            - 'downloadstring'
    condition: selection
level: high
```

## Object-Based Sigma (v11 Only)

THOR v11 allows Sigma rules to match on **any object type** THOR produces. This enables detection of:

- Suspicious processes and their properties
- Persistence mechanisms (autoruns, cron, services, scheduled tasks)
- Fileless malware indicators
- Kernel rootkits
- Network artifacts
- And much more

**This feature works in both full THOR v11 and THOR Lite v11.**

### Logsource Format for Object Types

```yaml
logsource:
    product: THOR
    service: <Object Type Name>
```

The `service` field must match the object type name exactly (e.g., `Linux kernel module`, `AmCache entry`, `cron job`).

### Discovering Object Types

Use these flags to explore available object types:

| Flag | Purpose |
|------|---------|
| `--describe-object-type all` | List all object types with JSON schemas |
| `--describe-object-type "<type>"` | View schema for specific type |
| `--log-object "<type>"` | Log all objects of a type during scan |
| `--log-object "<type>:<limit>"` | Log objects with limit (e.g., `"process:50"`) |

```bash
# View process object schema
./thor-linux-64 --describe-object-type "process"

# Log process objects during a scan
./thor-linux-64 --module ProcessCheck --log-object "process:10"

# Output as JSON for analysis
./thor-linux-64 --module ProcessCheck --log-object "process:10" --console-json
```

### Field Naming Convention

Fields from the JSON schema are converted to **UPPERCASE** in Sigma rules:

| JSON Schema Field | Sigma Field |
|-------------------|-------------|
| `included_in_kernel` | `INCLUDED_IN_KERNEL` |
| `command` | `COMMAND` |
| `service_name` | `SERVICE_NAME` |

To match null/empty fields:

```yaml
detection:
    selection:
        FILE: null
```

### Object Type Reference

THOR includes 90+ object types. Most commonly used for detection:

**Process and Memory:**

- `process` - Running processes
- `process connection` - Network connections per process
- `process handle` - Open handles
- `thread` - Thread information

**Persistence Mechanisms:**

- `autorun entry` - Windows autoruns
- `cron job` - Linux cron jobs
- `scheduled task` - Windows scheduled tasks
- `at job` - at scheduler jobs
- `Windows service` - Windows services
- `systemd service` - Linux systemd services
- `init.d service` - SysV init services
- `WMI startup command` - WMI persistence

**File System Artifacts:**

- `file` - File metadata
- `MFT entry` - NTFS MFT entries
- `jump list entry` - Windows jump lists
- `prefetch info` - Windows prefetch
- `shim cache entry` - Application compatibility cache

**Registry:**

- `registry key` - Registry keys
- `registry value` - Registry values

**Users and Authentication:**

- `Windows user` - Windows user accounts
- `Unix user` - Unix user accounts
- `authorized_keys entry` - SSH authorized keys
- `logged in user` - Currently logged in users
- `LSA session` - LSA session information

**Network:**

- `DNS cache entry` - DNS cache
- `firewall rule` - Firewall rules
- `hosts file entry` - Hosts file entries
- `network session` - Network sessions
- `network share` - Network shares

**Security and Kernel:**

- `Linux kernel module` - Loaded kernel modules
- `eBPF program` - eBPF programs
- `mutex` - System mutexes
- `named pipe` - Named pipes
- `antivirus exclusion` - AV exclusions

**Logs and Events:**

- `eventlog entry` - Windows eventlog entries
- `log line` - Log file lines
- `journal log entry` - systemd journal entries
- `audit log entry` - Linux audit log entries

**Execution History:**

- `AmCache entry` - Windows AmCache
- `shim cache` - Shim cache entries
- `web page visit` - Browser history
- `web download` - Browser downloads

### Quick Reference Table

| Use Case | Object Type | Key Fields |
|----------|-------------|------------|
| Process monitoring | `process` | COMMAND, NAME, OWNER, PID |
| Linux persistence | `cron job` | COMMAND, USER, SCHEDULE |
| Windows persistence | `scheduled task` | COMMANDS, USER, RUN_LEVEL |
| Autoruns | `autorun entry` | LAUNCH_STRING, LOCATION |
| Services (Windows) | `Windows service` | SERVICE_NAME, IMAGE |
| Services (Linux) | `systemd service` | COMMAND, RUN_AS_USER |
| Kernel rootkits | `Linux kernel module` | FILE, INCLUDED_IN_KERNEL |
| File hashes | `file` | MD5, SHA1, SHA256, PATH |
| Execution history | `AmCache entry` | SHA1, PATH, PRODUCT |

## Detection Examples

### Example 1: Execution of Known Malicious Hash via AmCache

```yaml
title: Execution of Known Malicious Hash via Amcache
logsource:
    product: THOR
    service: AmCache entry
detection:
    selection:
        SHA1: DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF
    filter:
        PATH|endswith: \benign.exe
    condition: selection and not filter
falsepositives:
    - Known good files matching the hash
level: critical
```

### Example 2: Linux Kernel Module Without File (Rootkit Detection)

```yaml
title: Kernel Module Without File
status: experimental
description: Detects dynamically loaded kernel modules without associated files
logsource:
    product: THOR
    service: Linux kernel module
detection:
    selection:
        FILE: null
        INCLUDED_IN_KERNEL: false
    condition: selection
falsepositives:
    - Custom kernels with manually loaded modules
level: medium
```

### Example 3: Suspicious Process with Encoded PowerShell

```yaml
title: Process with Encoded PowerShell Execution
logsource:
    product: THOR
    service: process
detection:
    selection:
        COMMAND|contains:
            - ' -enc '
            - ' -EncodedCommand '
        NAME|endswith:
            - 'powershell.exe'
            - 'pwsh.exe'
    condition: selection
level: high
```

### Example 4: Suspicious Cron Job (Linux Persistence)

```yaml
title: Cron Job with Suspicious Download Command
logsource:
    product: THOR
    service: cron job
detection:
    selection_download:
        COMMAND|contains:
            - 'wget '
            - 'curl '
    selection_pipe:
        COMMAND|contains:
            - '| bash'
            - '| sh'
    condition: selection_download and selection_pipe
level: medium
```

### Example 5: Autorun Entry from Suspicious Location

```yaml
title: Autorun Entry from Suspicious Location
logsource:
    product: THOR
    service: autorun entry
detection:
    selection_path:
        LAUNCH_STRING|contains:
            - '\AppData\Roaming\'
            - '\Users\Public\'
            - '\Temp\'
    selection_script:
        LAUNCH_STRING|contains:
            - '.vbs'
            - '.hta'
            - 'powershell'
    condition: selection_path and selection_script
level: high
```

### Example 6: Windows Service with Suspicious Binary Path

```yaml
title: Windows Service from Temp Directory
logsource:
    product: THOR
    service: Windows service
detection:
    selection:
        IMAGE|contains:
            - '\Temp\'
            - '\Users\Public\'
            - '\AppData\'
    condition: selection
level: high
```

## Rule Levels and Scoring

| Sigma Level | THOR Score | Default Visibility |
|-------------|------------|-------------------|
| `critical` | 100 | Always shown |
| `high` | 70 | Always shown |
| `medium` | 50 | With `--intense` or `--sigma-threshold medium` |
| `low` | 40 | With `--sigma-threshold low` |

Adjust the threshold:

```bash
./thor-linux-64 --sigma-threshold medium
```

## Scanning Commands

### Windows Eventlog Scan

```bash
# Scan only eventlogs
thor64.exe -a Eventlog

# Scan specific evtx files
thor64.exe -a Eventlog -p C:\path\to\evtx\files
```

### Linux Log Scan

```bash
# Scan /var/log with Sigma
./thor-linux-64 -a Filescan -p /var/log
```

### Testing Object-Based Rules (v11)

```bash
# Examine real objects before writing rules
./thor-linux-64 --module ProcessCheck --log-object "process:10" --console-json

# Test with lowered threshold
./thor-linux-64 --sigma-threshold medium -p /target
```

## Deployment

1. Save your rule as a `.yml` file
2. Copy to the THOR custom signatures folder:

```bash
cp my-rule.yml /path/to/thor/custom-signatures/sigma/
```

3. For encrypted rules, use `.yms` extension
4. Verify rules loaded:

```bash
./thor-linux-64 --list-signatures | grep "my-rule"
```

## Encryption

```bash
thor-util encrypt --file my-sigma-rule.yml
# Creates my-sigma-rule.yms
```

## THOR Lite Note

- **Log-based Sigma:** Not available in THOR Lite (Sigma module is disabled)
- **Object-based Sigma (v11):** Available in THOR Lite v11

This means THOR Lite v11 users can write custom Sigma rules for object types but cannot use the pre-packaged Sigma rules for eventlog analysis.

## Resources

- Official Sigma repo: https://github.com/SigmaHQ/sigma
- THOR ships with SigmaHQ public rules + Nextron private rules (full THOR only)
