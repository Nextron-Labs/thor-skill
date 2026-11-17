# THOR editions and licenses

## Editions

| Edition | What it is | Binaries |
|---|---|---|
| THOR (full) | Commercial scanner, full module set, Nextron's private signature set | `thor64.exe`, `thor-linux-64`, `thor-macosx`, `thor-aix`; `thor-util` |
| THOR 11 Tech Preview / release candidates | Next major version; same binary names; obtained with `thor-util download --techpreview` or `thor-util upgrade --techpreview` | as above (64-bit and ARM64 only) |
| THOR Lite | Free edition, 1-year license, open-source signatures, reduced module set (see the `thor-lite` skill) | `thor64-lite.exe`, `thor-lite-linux-64`, `thor-lite-macosx`; `thor-lite-util` |
| THOR Legacy | Reduced THOR 10 build for old systems (Windows XP/2003/2008 pre-R2, CentOS 6); needs a `legacy` license option. Lacks ProcessCheck, Eventlog, scheduled tasks, ETW, Thunderstorm, HTML report, UPX unpacking, ADS, diagnostics | separate package, `thor-legacy-util.exe` |
| Thunderstorm | Scan service that receives samples over HTTP. v10: `--thunderstorm` mode of THOR; v11: `tools/thunderstorm` in the Linux package | see `thor-deployment` |
| THOR Cloud / THOR Cloud Lite | Web console with campaigns and a launcher per platform; Cloud Lite is the free variant (30 scans per month) | launcher |

A full THOR binary rejects a Lite license ("invalid scanner"), and Lite cannot download licenses from
Management Center or the Customer Portal ("License generation via Management Center is not available for THOR Lite").

## License types

The license type is shown in the startup line `License file found LICENSE: ... TYPE: ... SCANNER: ... VALID: ... REASON: ...`
(the `OWNER` field in that line is personal data; see "Safe ways to check the license").

| License (shown TYPE) | Runs on | Lab features | Notes |
|---|---|---|---|
| THOR Workstation (`Workstation`, internal `client`) | Windows workstations and macOS | no | Refused on Windows Server ("workstation license on a server") and on Linux |
| THOR Server & Workstation (`Server`) | Windows, Linux, macOS, servers and workstations | no | Linux always needs this type |
| Forensic Lab (`Lab`) | any | **yes** | If not bound to a hostname: interactive 3-digit challenge at every start |
| Incident Response / Compromise Assessment (`Enterprise`) | any | **yes** | Also enables the Artifact Collector |
| Trial (`Trial`) | any | **yes** | Challenge like Lab if not host-bound; "some output will be removed due to license restrictions" |
| Thunderstorm / Service (`Thunderstorm`) | any | drop zone only | Only Thunderstorm (HTTP server) and drop zone modes; a normal scan is refused |
| Silent (`Silent`) | any | no | No scan output; for testing rollouts and for hosts that only run `thor-util` updates |
| THOR Lite (`Lite`, scanner "THOR Lite") | Lite binaries only | no (except `--alldrives`) | Startup notice plus a 5-second pause; non-commercial terms (see `thor-lite`) |

"Lab-type license" in this skill set means Lab, Enterprise (Incident Response) or Trial, and never a Lite license.

### Lab-gated flags

Without a lab-type license, THOR marks the license invalid for the requested feature, prints the license list
with the reason and exits 1 with "No valid license file found". A license **special** (add-on) can unlock a single feature.

| Feature | v10 flag | v11 flag | Unlock without lab-type license | Refusal text starts with |
|---|---|---|---|---|
| Lab mode | `--lab` | `--lab` | none | "the current license type doesn't allow lab mode scans" |
| Hostname override | `-j, --overwrite-hostname` | same | special `allowhostnamerewrite` | "... doesn't allow setting the hostname" |
| Path remapping | `--virtual-map` | `--path-remap` | special `allowvirtualmapping` | "... doesn't allow virtual mapping" |
| Memory dump (DeepDive) | `-m, --image_file` | `-m, --memory-dump-file` | special `allowdeepdive`; v10.7.30+ Lite licenses are allowed | "... doesn't allow image scanning" |
| Drop zone | `--dropzone -p DIR` | `--dropzone DIR` | Thunderstorm license or special `allowdropzone` | "... doesn't allow the drop zone mode" |
| Parallel instances | `--nodoublecheck` | `--no-scan-lock` | special `nodoublecheck` | v10 "License doesn't allow skipping the double check", v11 "license doesn't allow disabling the scan lock" |
| Network and all drives | `--alldrives` | `--all-drives` | Lite license or special `allownetworkscan` | "... doesn't allow the use of --alldrives ... You can use --allhds instead" |
| Action command | `--action_command` | removed | none | v10 only |
| Artifact Collector | `--collector`, `--collector-only` | same | Enterprise license or special `deepforensic` (a Lab license alone is not enough) | "license does not support 'Artifact-Collector' module" |

Not gated (any license): `--threads`, `--norescontrol`/`--no-resource-check`, `--cross-platform`/`--cross-platform-paths`,
`--intense`/`--deep`, `--allfiles`/`--files-all`, `--target-os` (v11), `--allhds`/`--all-hard-drives`.

v11 pitfall: if exactly one `--path` lies on a network file system (SMB, NFS, any FUSE mount such as sshfs on Linux),
v11 switches `--all-drives` on automatically, so a Server/Workstation license then fails the `--alldrives` check.

Mounted images with a non-lab license: both versions detect a mounted OS root and log
"Starting directory looks like a mounted disk image. In the future, we may prohibit scanning mounted images ..."
(v10 Error, v11 Notice), but still scan.

Other license checks: AIX needs the `aix` special. Licenses may also restrict modules or features; THOR then logs
"Disabling module X due to license restrictions" (v10) or the reason "License restrictions" (v11).

## Host binding

- Host-based licenses are bound to the short hostname, case-insensitive: Windows `%COMPUTERNAME%`, Linux `hostname`,
  macOS `sysctl kern.hostname`. Use `master1`, not `master1.internal.net`.
- One folder (USB stick, share) may hold many `.lic` files; THOR uses the first valid one.
- v11 warns when the hostname changed recently ("In future versions of THOR, scans on such systems may be prohibited").

## Interactive challenge (unbound Lab and Trial licenses)

A Lab or Trial license that is not bound to a host asks at start: "Enter the following three digits to continue".
v11 requires an interactive terminal; without one the license is invalid
("license requires challenge / response, which requires an interactive terminal").
Consequence: unattended or scheduled lab scans need a host-bound license. When you propose a lab command,
tell the user they may have to type three digits.

## License file locations

| Source | Behaviour |
|---|---|
| Program folder and all subfolders | Every `*.lic` (case-insensitive) is a candidate; first valid wins. Recommended: `<thor>/licenses/` |
| `-q, --license-path DIR` | Replaces the search root (default: the THOR binary's directory) |
| `THOR_LICENSE` env var | Base64 of the `.lic` content (`export THOR_LICENSE=$(base64 < host.lic)`); read together with the folder |
| Management Center | `--management-center HOST --management-center-token TOKEN` (only if no valid local license); stored as `<hostname>.lic` |
| Customer Portal | `--portal-key KEY` (v11 `--portal-api-key`), optional `--portal-contracts ID,ID`; issues a new license unless `--portal-nonewlic` (v11 `--portal-existing-license`); stored as `<hostname>.lic` |
| THOR Lite | License file from the registration e-mail, placed in the program folder; no MC/Portal retrieval |

Order: env + folder first; if nothing is valid, Management Center, then Portal.
Proxies for Portal: `HTTP_PROXY` / `HTTPS_PROXY`.

## Safe ways to check the license

Never grep `.lic` files (encrypted) and never show the `OWNER` / `LICENSE_OWNER` value or the v11 JSON
`Scan Information` record (it contains `license.owner`). For general output use
`grep -v -e LICENSE_OWNER -e 'License file found' -e 'Scan Information'`; the commands below keep the license lines
but cut the owner out.

1. **v11:** `--list-licenses` lists all candidates and exits 0 without scanning. Add the lab flag you want to test
   (`--list-licenses --lab`) so `VALID`/`REASON` reflect it. Redact the owner:
   ```bash
   ./thor-linux-64 --list-licenses --no-color | sed -E 's/[A-Z_]*OWNER: .* ([A-Z_]*TYPE: )/\1/'
   ```
   ```powershell
   & .\thor64.exe --list-licenses --no-color | ForEach-Object { $_ -replace '[A-Z_]*OWNER: .* ([A-Z_]*TYPE: )','$1' }
   ```
2. **v10:** `--printlicenses` only raises the limit of printed candidates (default 10); THOR still scans.
   Read the license lines of a tiny, isolated run instead:
   ```bash
   mkdir -p /tmp/thor-empty
   ./thor-linux-64 -a Filescan -p /tmp/thor-empty --nothordb --nolog --nohtml --nocsv --nocolor \
     | grep 'License file found' | sed -E 's/[A-Z_]*OWNER: .* ([A-Z_]*TYPE: )/\1/'
   ```
3. **Try and read the refusal (both):** run the gated flag on an empty folder with ThorDB off and outputs disabled,
   then look for "The current license type doesn't allow ..." and exit code 1. An unbound lab license will prompt
   for the 3-digit challenge instead.

## Lite vs full in one table

| | THOR Lite 10.7 | THOR Lite 11 | Full THOR |
|---|---|---|---|
| Modules | Filescan, Autoruns, ProcessCheck, DeepDive (+Eventlog with the `allowsigma` special) | Filescan, Autoruns, ProcessCheck, Eventlog (Windows) | all (about 35) |
| Lab features | none (`--alldrives` allowed; `--image_file` since 10.7.30) | none (`--all-drives` allowed; memory dumps not functional) | with lab-type license |
| Signatures | open-source set + YARA Forge + custom | same | private set (30,000+ rules and IOCs) + custom |

Full matrix: see the `thor-lite` skill.
