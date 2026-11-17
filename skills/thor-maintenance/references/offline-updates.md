# Offline and air-gapped updates

Principle: a connected "update host" builds complete THOR packages with `thor-util download` (or keeps a
pack current with `update`/`upgrade --path pack.zip`); the pack is transferred; the offline install applies it
with `thor-util install --file` (full edition) or by extracting it.

## Update host requirements

- thor-util from a THOR package (any OS; it can download packages for other platforms with `-t`).
- A time-valid license next to thor-util (or `--license-path`, or `THOR_LICENSE`). Host binding is not
  checked for updates; ask Nextron for a "silent license" for a dedicated update host.
- HTTPS 443 to `update1.nextron-systems.com` / `update2.nextron-systems.com` (Lite:
  `update-lite.nextron-systems.com`); for YARA Forge also GitHub. Proxy via `--proxy` or `HTTPS_PROXY`.
- Version pin: `download` uses the stable channel (10.7.x) unless `--version`/`--techpreview` is given.

## 1. Build packs (connected host)

```sh
# THOR 10 packs
thor-util download -t thor-windows --version '^10.0.0' --path packs/thor10-windows.zip
thor-util download -t thor-linux   --version '^10.0.0' --path packs/thor10-linux.zip
# THOR 11 packs
thor-util download -t thor-windows --version '^11.0.0-0' --path packs/thor11-windows.zip
thor-util download -t thor-linux   --version '^11.0.0-0' --path packs/thor11-linux.zip
thor-util download -t thor-linux-arm --version '^11.0.0-0' --path packs/thor11-linux-arm.zip
# with YARA Forge rules inside the pack
thor-util download -t thor-windows --version '^11.0.0-0' --ruleset core --path packs/thor11-windows-yf.zip
# THOR Lite (use thor-lite-util and a Lite license)
thor-lite-util download -t thor-lite-windows --path packs/thor-lite-windows.zip
```
`download` refuses an existing non-empty target: use a new name or refresh the existing pack:
```sh
thor-util update  --path packs/thor11-windows.zip                         # newer signatures into the ZIP
thor-util upgrade --path packs/thor11-windows.zip --version '^11.0.0-0'   # newer program + signatures
thor-util yara-forge download --ruleset core --path packs/thor11-windows.zip
```
Record a checksum for the transfer: `sha256sum packs/*.zip` (macOS `shasum -a 256`, Windows
`Get-FileHash`). Packs contain no licenses.

## 2. Apply on the offline host

Existing full-edition install (keeps `config/`, custom signatures, licenses):
```
thor-util install --file D:\transfer\thor11-windows.zip --path C:\thor
./thor-util install --file /media/usb/thor11-linux.zip --path /opt/thor
```
- `--path` defaults to the current directory: always pass it.
- `already up-to-date` (exit 0) if versions are equal. A signatures-only ZIP is refused over a THOR folder;
  use full packs refreshed with `update --path`.
- No running scan may hold the files (Windows).

Fresh install, or THOR Lite (`thor-lite-util` has no `install`): extract the ZIP into a new folder and copy
the license(s), `config/` customisations and `custom-signatures/` from the old folder. For THOR 10 -> 11, do
not copy the old `config/thor.yml` blindly (unit changes; see thor-util-update-upgrade.md).

Signature freshness: THOR warns at start when signatures are older than 60 days; plan the transfer cycle
accordingly.

## 3. Field offices / hand-out packs

Give the pack (with license files for the target hosts, e.g. in a `licenses/` folder) to the local team,
let them run THOR locally with an explicit output directory, and collect the logs. Few hosts: HTML reports;
many hosts: load JSON/JSONL logs into a SIEM, Analysis Cockpit or THOR Lens. Rollout methods: `thor-deployment`
skill.

## 4. Mistakes to avoid

| Mistake | Correct |
|---|---|
| `thor-util download -t thor10-win -o DIR` | no `-o`; `--path DIR/` (trailing separator = directory) |
| expecting `thor10-*` names to select THOR 10 | they are aliases of `thor-windows`/`thor-linux`/`thor-macos`; pin with `--version '^10.0.0'` |
| plain `download`/`upgrade` for a THOR 11 fleet | add `--version '^11.0.0-0'` (or `--techpreview`) |
| running `thor-util update` on the update host and zipping `signatures/` | update the pack ZIP: `thor-util update --path pack.zip` |
| `thor-util yara-forge download` on the update host, then copying folders | add YARA Forge to the pack: `--ruleset` on `download`, or `yara-forge download --path pack.zip` |
| backing up/restoring `config/` around `install` "because install resets it" | `install` keeps existing `config/*`; back up anyway before major upgrades |
