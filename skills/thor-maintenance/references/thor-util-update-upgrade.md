# update, upgrade, download, install

Same behaviour in the thor-util shipped with 10.7.x and with THOR 11 unless marked. `thor-lite-util` is
identical except: no `install`, no Tech Preview / preview-signature channels, Lite update server.

## update (signatures only)

```
thor-util update                         # the THOR folder thor-util lives in
thor-util update --path /opt/thor        # another install
thor-util update --path thor-pack.zip    # refresh signatures inside an offline pack
thor-util update --signatures-preview    # early-access signatures (formerly --sigdev)
```
- Accepts only THOR or THOR Lite installs/packs ("Signature update is only available for THOR and THOR Lite").
- Downloads the signature pack for the edition, verifies it, purges and replaces `signatures/`, then
  refreshes YARA Forge if a ruleset is installed.
- Prints a notice when a newer THOR program version exists; it does not install it.
- Never touches binaries, `config/`, `custom-signatures/` (except the YARA Forge subfolder), licenses.
- Back from preview signatures: run `thor-util update` without the flag (no `--force` flag exists).

## upgrade (program + signatures)

```
thor-util upgrade --version '^11.0.0-0'                     # THOR 11 install
thor-util upgrade --version '^10.0.0'                       # THOR 10 install, stay on 10
thor-util upgrade --techpreview                             # current Tech Preview build
thor-util upgrade --reinitialize-config --version '^11.0.0-0'
thor-util upgrade --ruleset core                            # also install/switch YARA Forge (none = remove)
thor-util upgrade --path /opt/thor
```
- Steps: license check -> program package -> signatures -> YARA Forge refresh -> (Windows, in place) a hidden
  cleanup step removes files that were locked.
- Packages are signature-verified before installing; installation is transactional (rolled back on failure).
- Refuses a missing destination ("Use 'download' instead") and a product mismatch (e.g. Lite over full,
  other OS) unless the destination folder is empty.
- Without `--version`/`--techpreview` (and without such keys in `config/thor-util.yml`) it requests the
  **stable** channel, currently 10.7.x, and the server allows downgrades. On a THOR 11 folder that is a
  downgrade. Always pin.

### What is kept

| Item | update | upgrade | install --file |
|---|---|---|---|
| Program binaries | kept | replaced | replaced |
| `signatures/` | purged + replaced | purged + replaced | purged + replaced (if in the pack) |
| Existing `config/*` (`thor.yml`, `*.cfg`, `thor-util.yml`, templates) | kept | kept; YAML files reset only with `--reinitialize-config`; `*.cfg` (excludes, false positive filters) always kept | kept |
| New files in `config/` from the package | - | added | added |
| `custom-signatures/` | kept (YARA Forge subfolder refreshed) | kept; v10 -> v11 moves root files into subfolders | kept |
| Licenses (`*.lic`) | kept | kept | kept |

`--reinitialize-config` is a reset to package defaults, not a conversion: back up `config/` first and
re-apply needed settings with the v11 names and units (`file-size-limit: 64MB`, `memory-limit: 50MB`).

## download (new offline package)

```
thor-util download -t thor-windows --path thor-windows.zip
thor-util download -t thor-linux --version '^11.0.0-0' --path thor11-linux/   # trailing / = directory
thor-util download -t thor-macos --ruleset core --path thor-macos.zip         # incl. YARA Forge core
thor-util download -t thor-lite-linux --path lite.zip                         # with thor-lite-util
```
- Default target: `./{product}-{product_version}-{signatures_version}.zip` in the current directory. A
  trailing path separator in `--path` creates a directory instead of a ZIP.
- Refuses an existing non-empty target ("already exists. Use 'upgrade' instead"). Never modifies an install.
- Product defaults to the OS/architecture thor-util runs on; pass `-t` for other platforms.
- No `-o` option exists; use `--path`.

Product identifiers (`-t`, `--product`):

| Product | Identifier |
|---|---|
| THOR full | `thor-windows`, `thor-windows-arm`, `thor-linux`, `thor-linux-arm`, `thor-macos` (universal), `thor-aix` |
| THOR Lite | `thor-lite-windows`, `thor-lite-windows-arm`, `thor-lite-linux`, `thor-lite-linux-arm`, `thor-lite-macos` |
| THOR Legacy | `thor-legacy-<os>` (with `--legacy`, needs a Legacy license) |
| Signatures only | `signatures`, `signatures-lite` (pass an explicit `--path`) |

ARM packages exist for THOR 11; check availability for 10.7 on the update server. The old names
`thor10-win`, `thor10-linux`, `thor10-macos` still parse but do **not** select THOR 10; the version comes from
`--version`/`--techpreview`.

## install (apply a package, full edition only)

```
thor-util install --file thor-windows-11.0.0-....zip --path C:\thor
```
- `--file` is required ("No installation file specified. Use: thor-util install --file <file.zip>").
- `--path` defaults to the **current directory**, not the thor-util folder: always pass it.
- Refuses a different product type (a signatures-only ZIP cannot be installed over a THOR folder).
- "already up-to-date" (exit 0) if program and signature versions are equal.
- Verifies package signatures; keeps existing `config/*`.
- Not available in `thor-lite-util`: extract Lite packs manually and copy licenses/config back.

## THOR 10 -> 11 specifics

Triggered when the installed THOR is < 11 and the downloaded one >= 11:
- Warning `Detected upgrade from THOR 10; ... use the --reinitialize-config option ...` (unless given).
- `custom-signatures/` root files move into `yara/` (`.yar .yara .yas`), `sigma/` (`.yml .yaml .yms`),
  `stix/` (`.json .jsos`), `iocs/` (`.txt .dat`); unknown extensions or existing targets are left and reported.
- The 32-bit THOR binary is removed (THOR 11 is 64-bit only; ARM64 packages exist).
- YARA Forge rules move to `custom-signatures/yara/yara-forge/`; the THOR 11 thor-util completes the move on
  its next `update`/`upgrade`.
- Old keys in a kept `config/thor.yml` stay active with new meanings (`minmem: 50` = 50 bytes,
  `max_file_size` sets the v11 limit, `cpulimit: 95` overrides the new default 70). THOR 11 warns about tiny
  byte values. Prefer a fresh folder or `--reinitialize-config`.
- v11 output defaults change (JSONL instead of text log): adjust collectors and scripts.

## Typical errors

| Message | Cause | Fix |
|---|---|---|
| `No valid license found` | no time-valid license under `--license-path` (default: thor-util folder) and no `THOR_LICENSE` | copy a license (any valid one; host binding is not checked; silent licenses work) |
| `license not valid for this product` | THOR Lite license used to fetch full THOR | full THOR license, or use `thor-lite-util` for Lite |
| `Download failed: ...`, TLS errors | proxy, firewall, TLS interception | `--proxy`, env proxy vars, `--rootca`; allow update1/update2 on 443 |
| `Could not find a matching version for constraint "..."` | no build in the channel matches | check the constraint; `--techpreview` |
| `Use 'download' instead` / `Use 'upgrade' instead` | wrong verb for the destination | see above |
| `Refusing to install X over the existing Y installation` | product mismatch | correct `-t`/pack |
| Windows: files locked | THOR or AV/EDR holds files | stop running scans; exclude the THOR folder in AV/EDR |
