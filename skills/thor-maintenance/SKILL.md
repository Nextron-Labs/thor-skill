---
name: thor-maintenance
description: Maintains THOR 10 and THOR 11 installations with thor-util / thor-lite-util. Picks the right verb (update = signatures, upgrade = program + signatures, download = new offline pack, install = apply a pack), pins versions with --version so a THOR 11 folder is not downgraded to the 10.7 stable channel, switches channels (--techpreview, --signatures-preview, formerly --sigdev), migrates THOR 10 to 11 (--reinitialize-config, custom-signatures subfolders), manages YARA Forge (yara-forge download --ruleset core|extended|full), and covers report, logconvert, encrypt/decrypt, verify, diagnostics, proxy settings, config/thor-util.yml, air-gapped updates and exit codes. Use for "thor-util update", "upgrade", "download", "offline update", "air-gapped", "No valid license found", "proxy", "yara-forge", "HTML report from log", "convert JSON to text", "verify signature", "signatures older than 60 days".
compatibility: THOR 10.7.x and THOR 11 (Tech Preview / release candidates); thor-util 2.x. Needs HTTPS to the Nextron update servers (YARA Forge also needs GitHub) or an offline pack.
metadata:
  author: Nextron Systems
  version: "2.0"
---

# THOR maintenance with thor-util

Binary: `thor-util` / `thor-util.exe` (full), `thor-lite-util` / `thor-lite-util.exe` (Lite), in the THOR
program folder. It acts on the folder it lives in unless `--path` is given. Run it as a user that can write
that folder. Detect the THOR version first (`thor64.exe --version`, `./thor-linux-64 --version`): the safe
commands differ.

## 1. Pick the verb

| Goal | Command | Changes | Keeps |
|---|---|---|---|
| New signatures (daily/weekly) | `thor-util update` | replaces `signatures/` completely; refreshes YARA Forge if installed | binaries, `config/`, `custom-signatures/`, licenses |
| New THOR program version | `thor-util upgrade` + **version pin** (section 2) | binaries + signatures (+ YARA Forge), adds new files to `config/` | existing `config/*` (YAML replaced only with `--reinitialize-config`; `*.cfg` always kept), `custom-signatures/`, licenses |
| Offline/air-gapped pack | `thor-util download -t <product> --path <new.zip or dir/>` | writes a NEW package (program + signatures); never touches an install; refuses an existing non-empty target | - |
| Apply a pack to an install (full edition) | `thor-util install --file pack.zip --path <thor-dir>` | binaries + signatures from the pack | existing `config/*`, custom signatures, licenses |
| Refresh a pack in place | `thor-util update --path pack.zip` / `thor-util upgrade --path pack.zip` | the ZIP | - |

Output format for answers: the exact command(s) for the detected version and OS, one line "what it changes",
one line "what it does not change".

## 2. Versions and channels: the downgrade trap

thor-util asks the update server for a channel; the server allows downgrades.

| Flags | Channel requested | Result today |
|---|---|---|
| none | `stable` | THOR 10.7.x. **A plain `thor-util upgrade` in a THOR 11 folder installs 10.7.x (downgrade).** |
| `--techpreview` (short `-v`, not "version"!) | `techpreview` | current Tech Preview build |
| `--version <semver constraint>` | `techpreview` channel filtered by the constraint (overrides `--techpreview` with a warning) | newest build matching the constraint |
| `--version <exact pre-release>` (e.g. `11.0.0-rc.3`) | switches to the development channel automatically | that build, if published |
| `--signatures-preview` (formerly `--sigdev`, hidden/deprecated) | `preview` for signatures | early-access signatures |

Rules:
- THOR 11 installs: always pass a v11 constraint, e.g. `thor-util upgrade --version '^11.0.0-0'` (the `-0`
  lets pre-releases such as release candidates match), or `--techpreview`. Which builds a channel offers is
  decided by the update server; no match ends with `Could not find a matching version for constraint`.
  While THOR 11 is pre-release, a build may be published only on the development channel: then name the
  exact build (`--version 11.0.0-rc.3`), which switches to that channel by itself. Never fall back to a
  plain `upgrade` in a THOR 11 folder.
- Persist the choice for scheduled jobs in `config/thor-util.yml`: `version: "^11.0.0-0"` (or
  `techpreview: true`). A file with `techpreview: false` or no setting means stable = 10.7.x.
- Pin THOR 10: `thor-util upgrade --version '^10.0.0'`. Exact build: `--version 10.7.33`.
- THOR Lite (`thor-lite-util`, server `update-lite.nextron-systems.com`) has no Tech Preview or preview
  signature channel; those flags are ignored. A `--version` constraint is still sent.
- Preview signatures passed the automated pipeline and QA but not full manual testing; use them temporarily
  during fast-moving campaigns, then return with a plain `thor-util update`.
- `update` is not affected by `--version`/`--techpreview`; it only replaces signatures.

## 3. THOR 10 -> 11

1. Read the THOR 11 changelog; back up `config/` and custom templates; review scripts and the config files
   they load (renamed flags, `minmem`/`memory-limit` now bytes, JSONL default output).
2. Recommended: fresh folder. `thor-util download -t thor-linux --version '^11.0.0-0' --path thor11-linux/`
   (or `--techpreview`), copy licenses and custom signatures into it, compare configs.
3. In place: `thor-util upgrade --reinitialize-config --version '^11.0.0-0'`. Without
   `--reinitialize-config` the v10 `config/thor.yml` stays active (thor-util warns `Detected upgrade from THOR 10`).
4. The cross-major upgrade moves files from the `custom-signatures/` root into `yara/` (`.yar .yara .yas`),
   `sigma/` (`.yml .yaml .yms`), `stix/` (`.json .jsos`), `iocs/` (`.txt .dat`); unknown extensions and name
   clashes stay and are reported. THOR 11 loads custom signatures only from those subfolders. 32-bit binaries
   are removed. YARA Forge moves to `custom-signatures/yara/yara-forge/` (the v11 thor-util re-installs it
   there on its next run if needed).
5. Back to 10: `thor-util upgrade --version '^10.0.0'`, then restore the backed-up config.

## 4. Requirements and network

- A time-valid license in the THOR folder (searched recursively, or `--license-path`, or `THOR_LICENSE`).
  Host binding is NOT checked for updates, so a "silent license" (ask Nextron) works on update-only hosts.
  Lite licenses cannot fetch full THOR. Error: `No valid license found`, exit 1.
- HTTPS 443 to `update1.nextron-systems.com` / `update2.nextron-systems.com` (Lite:
  `update-lite.nextron-systems.com`); YARA Forge: GitHub (`api.github.com`, release downloads).
- Proxy: `--proxy http://proxy:8080` (`-a`), `--proxy-user`/`-n`, `--proxy-pass`/`-p`, `--ntlm`; or
  `HTTP_PROXY`/`HTTPS_PROXY`. Put credentials into `config/thor-util.yml` (`proxy-user:`, `proxy-pass:`),
  not on the command line (process list, shell history). YARA Forge downloads ignore the thor-util proxy flags
  and use only the environment proxy variables.
- TLS interception: `--rootca <ca.pem>`; `--http-insecure` only as a last resort. `--insecure` disables
  package signature checks: do not use.
- Short-flag traps: `-v` = `--techpreview`, `-p` = `--proxy-pass`, `-t` = `--product`, `-u` = `--url`.

Details: [update/upgrade/download/install](references/thor-util-update-upgrade.md),
[offline](references/offline-updates.md).

## 5. YARA Forge

```
thor-util yara-forge download --ruleset core      # or extended, full
thor-util yara-forge remove
thor-util upgrade --ruleset core                   # switch/install during upgrade; --ruleset none removes
```
One ruleset at a time, stored encrypted (`.yas`) in v10 `custom-signatures/yara-forge/`, v11
`custom-signatures/yara/yara-forge/`, refreshed by every `update`/`upgrade`/`download`. Larger rulesets cost
scan time and bring more false positives. See [yara-forge.md](references/yara-forge.md).

## 6. Other subcommands (both versions)

| Task | Command |
|---|---|
| HTML report from a log (e.g. after an aborted scan) | `thor-util report --logfile host_thor_2026-11-16_0914.jsonl` -> `<log>.htm` next to the log |
| Convert log formats | `thor-util logconvert --file host.jsonl --to-log --output host.txt`; `--to-csv`, `--to-csv-zip`, `--to-json` |
| Encrypt custom signatures | `thor-util encrypt rules.yar --destdir custom-signatures/yara/` (positional files, no `--file`) |
| Decrypt encrypted THOR logs | `thor-util decrypt --privkey key.pem host_thor.jsonl` (overwrites the input in place: work on a copy) |
| Verify binary signatures | `thor-util verify --file thor64.exe` (exit 2 = missing/invalid signature) |
| Diagnostics pack | `thor-util diagnostics` (see the `thor-troubleshooting` skill) |
| Version | `thor-util version` |

Flags and details: [thor-util-commands.md](references/thor-util-commands.md).

## 7. Exit codes

`0` success or "up to date"; `1` errors (license, network, signature check, missing destination, failed
install); `2` `verify` with missing/invalid signature and `logconvert` usage errors; unknown flags/arguments
end with a non-zero status (255 on Unix). Check the output text, not only the code.

## 8. Signals that maintenance is due

THOR start-up warnings: `Signature file is older than 60 days` (v10 suggests `upgrade`, v11 `update`) and
(v11) `THOR binary is older than 365 days`. `thor-util update` also prints when a newer THOR program is
available (it does not install it).

## References

- [references/thor-util-update-upgrade.md](references/thor-util-update-upgrade.md) - update/upgrade/download/install in depth, products, what is kept, v10->v11.
- [references/offline-updates.md](references/offline-updates.md) - air-gapped and field workflows with exact commands.
- [references/yara-forge.md](references/yara-forge.md) - rulesets, locations, offline use, false positives.
- [references/thor-util-commands.md](references/thor-util-commands.md) - every subcommand and global flag, thor-util.yml, report/logconvert/encrypt/decrypt/verify.

Related skills: `thor` (editions, licenses, flag map), `thor-troubleshooting`, `thor-custom-signatures`,
`thor-deployment` (rolling out updates to many hosts), `thor-lite`.
