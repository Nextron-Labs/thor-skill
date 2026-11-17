# Management Center, license retrieval and THOR Remote

## Management Center (formerly ASGARD Management Center)

Nextron's on-premises appliance for distributed THOR scans: agents for Windows, Linux and
macOS, scan templates, scheduled and staggered sweeps, Update Service, License Service
(central sublicense generation), asset inventory, IOC/YARA rule management, evidence and
memory collection, response actions. Scan logs go to the **Analysis Cockpit** (baselining,
case management) or a SIEM.

With a Management Center, prefer it over hand-built rollouts: it handles waves, licensing,
updates and log collection. THOR flags still matter inside scan templates (same flags as on
the command line for the THOR version the MC deploys).

### Licenses from the Management Center for standalone THOR

```bat
thor64.exe --management-center mc.corp.internal --management-center-token <download-token>
```

```bash
sudo ./thor-linux-64 --management-center mc.corp.internal --management-center-token <download-token>
```

| Fact | Detail |
|---|---|
| Flags | `--management-center <host>` + `--management-center-token <token>`, both v10 and v11. Old names `--asgard`, `--asgard-token` still accepted. **`--management-center-host` does not exist** (error in the manual) |
| Token | MC web UI → *Downloads* (download token) or *Licensing* |
| When used | only if no valid local license is found (env `THOR_LICENSE`, license path) |
| Result | stored as `<hostname>.lic` in the license path (default: THOR program folder) |
| TLS | MC with internal CA: `--ca <ca.pem>` (MC CA download: `https://<mc>:8443/ca.pem`), last resort `--insecure` |
| Lite | not available ("License generation via Management Center is not available for THOR Lite") |

Bulk generation without running THOR: MC *Licensing → Generate Licenses* (web UI) or the MC
API. The API help box in that page shows the current `curl` request; the THOR 10 manual
documents the form
`curl -XPOST "https://<mc>:8443/api/v0/licensing/issue?token=<token>" -o licenses.zip -d "type=server" -d "hostnames=SRV001" -d "hostnames=SRV002"`.
Needed per host: host name and type (`server` or `workstation`; Linux always `server`).
Unzip into `licenses/` of the program folder.

## Licenses from the Customer Portal

```bat
thor64.exe --portal-api-key <key> --portal-contracts 3,5 --portal-existing-license
```

| Flag (v11) | v10 spelling | Meaning |
|---|---|---|
| `--portal-api-key` | `--portal-key` | user API key or contract download token; API access must be enabled by Nextron |
| `--portal-contracts 3,5` | same | contract IDs to draw from (default: first valid contract of the needed type) |
| `--portal-existing-license` | `--portal-nonewlic` | only reuse an existing license for this host; never issue a new one |

- Works only with host-based Workstation / Server contracts. If the host has no license yet,
  the Portal issues one (consumes quota) unless `--portal-existing-license` is set.
- Proxy: `HTTPS_PROXY`/`HTTP_PROXY` (`http://user:pass@proxy:3128/`).
- The Portal never stores host names; manual API use requires an HMAC of the lower-case short
  host name (see the THOR manual's licensing chapter).
- Saved as `<hostname>.lic` in the license path; on a read-only share use pre-generated
  licenses or `-q/--license-path` to a writable directory.
- The key travels to every endpoint (process list, deployment tool logs): prefer a contract
  download token, scope it to the needed contract, rotate after the campaign.

## Other license mechanics

- Search order: `THOR_LICENSE` env var and `.lic` files below the license path (default:
  program folder, all subfolders; first valid one wins) → Management Center → Portal.
- `THOR_LICENSE=$(base64 < host.lic)` (Linux) injects one license without a file.
- `-q/--license-path <dir>` changes where THOR looks.
- v11 `--list-licenses` prints all licenses found and exits (contains owner names; do not share).
- Host binding uses the short host name, case-insensitive (Windows `%COMPUTERNAME%`).

## THOR Remote

Agentless push from a Windows admin workstation: THOR copies itself to each target over SMB
(admin share), starts the scan through the Service Control Manager, streams status into its
own TUI and collects the log files.

| Requirement | Detail |
|---|---|
| Edition | full THOR only; THOR Lite refuses it ("THOR Remote is disabled …") |
| Launcher | Windows; run from a **local disk**, not a network share (`CreateFile .: The system cannot find the path specified.`) |
| Targets | Windows, reachable on 135/tcp (SCM) and 445/tcp (SMB, `ADMIN$`/`C$`) |
| Account | domain account with local admin rights on targets; with explicit `--remote-user/--remote-password` (NTLM) the credentials remain on targets; better run the launcher as that account (Kerberos) |
| Licenses | one per target in the program folder (or one Incident Response license); none needed for the launching workstation; MC/Portal retrieval downloads all target licenses to the launcher |

Flags (all other THOR flags on the command line are passed to the remote scans):

| v11 | v10 | Default | Meaning |
|---|---|---|---|
| `--remote-host H` (repeat) | `--remote H` (repeat) | — | target host; v11 accepts `--remote` as alias |
| `--remote-user U` | same | integrated auth | user for targets |
| `--remote-password P` | same | — | password (ends up in shell history) |
| `--remote-password-prompt` | `--remote-prompt` | off | prompt instead |
| `--remote-dir D` | same | v11 `C:\Program Files\Thor-Remote\Temp`, v10 `C:\WINDOWS\TEMP\thor10-remote` | upload directory on targets |
| `--remote-connections N` | `--remote-workers N` | 25 | concurrent scans |
| `--remote-scan-delay S` | `--remote-rate S` | 30 | seconds; v11: between finishing one host and starting the next, v10: between scan starts |
| `--remote-debug` | same | off | debug output |

Target lists from YAML (`-t`): v11 key `remote-host:`, v10 key `remote:`.

```yaml
# targets.yml (v11)
remote-host:
  - winatl001.corp.internal
  - winatl002.corp.internal
```

```bat
C:\thor> thor64.exe -t targets.yml --remote-connections 10 --soft
C:\thor> thor64.exe --remote-host srv01 --remote-host srv02 --management-center mc.corp.internal --management-center-token <token>
```

Output: `<output dir>\remote-logs\` (default `.\remote-logs\`), files prefixed with the target
host; v11 also writes `thor-remote.log` there.

Errors: `System Error 5` / access denied on admin shares → UAC remote restrictions for local
accounts (use a domain account) or missing admin rights; RPC/SMB timeouts → firewall on 135/445.
