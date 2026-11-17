# thor-util command reference

Applies to the thor-util shipped with THOR 10.7.x and THOR 11 (thor-util 2.x); differences are marked.
`thor-lite-util` has the same commands except `install`. `thor-util <cmd> --help` lists the flags.

## Subcommands

| Command | Purpose | Own flags |
|---|---|---|
| `update` | signatures only | `--path` (folder or pack ZIP) |
| `upgrade` | program + signatures | `--path`, `--ruleset core|extended|full|none`, `--reinitialize-config` |
| `download` | new package | `--path` (default `{product}-{product_version}-{signatures_version}.zip`), `--ruleset` |
| `install` | apply a package (full edition only) | `--file`/`-f` (required), `--path` (default: current dir) |
| `yara-forge download` / `yara-forge remove` | YARA Forge rules | `--ruleset` (download), `--path` |
| `report` | HTML report from logs | `--logfile`, `--logdir`, `--outfile`, `--filter`, `--include-info` |
| `logconvert` | convert log formats | `--from-log/--from-json`, `--to-log/--to-json/--to-kv/--to-csv/--to-csv-zip`, `--file`/`-f`, `--output`/`-o` |
| `encrypt <files...>` | encrypt custom signature files | `--destdir` |
| `decrypt <files...>` | decrypt encrypted THOR logs/CSV | `--privkey` (PEM file or inline key) |
| `verify` | check Nextron signatures of executables | `--file`, `--dir` |
| `diagnostics` | diagnostics pack of a running THOR | `--output`, `--run`; v11 hidden `diagnostics profile -o <file|-> <profile>` |
| `version` | print thor-util and THOR version | - |
| `completion` | shell completion script (bash, zsh, fish, powershell) | - |

## Global flags (valid on every subcommand, settable in `config/thor-util.yml`)

| Flag | Short | Meaning |
|---|---|---|
| `--license-path <dir>` | | where licenses are searched (default: thor-util folder, recursive) |
| `--product <id>` | `-t` | product to download (see thor-util-update-upgrade.md) |
| `--techpreview` | `-v` | Tech Preview channel (not "verbose", not "version") |
| `--version <constraint>` | | semver constraint for THOR, e.g. `10.7.33`, `^10.0.0`, `^11.0.0-0`; overrides `--techpreview` |
| `--signatures-preview` | | preview signature channel (formerly `--sigdev`, hidden and deprecated) |
| `--proxy <url>` | `-a` | proxy; no scheme -> `http://` assumed; `HTTP_PROXY`/`HTTPS_PROXY` used when unset |
| `--proxy-user` | `-n` | proxy user (`DOMAIN\user` for NTLM) |
| `--proxy-pass` | `-p` | proxy password (not "path"!) |
| `--ntlm` | | NTLM proxy authentication |
| `--rootca <file>` | | additional trusted root CA(s), e.g. TLS-inspecting proxy |
| `--url <url>` | `-u` | alternative update URL (internal mirror) |
| `--minimal` | | skip optional files (templates, manuals, extras) |
| `--http-insecure` | | skip TLS certificate verification (last resort) |
| `--insecure` | | skip package signature verification (do not use) |
| `--debug` | | debug output |

`config/thor-util.yml` (YAML keys = long flag names; command-line flags override it):
```yaml
version: "^11.0.0-0"      # keep this folder on THOR 11
proxy: http://proxy.corp.local:8080
proxy-user: CORP\svc-thor
proxy-pass: "..."          # protect the file (ACL / chmod 600) instead of passing -p on the command line
ntlm: true
rootca:
  - config/corp-root-ca.pem
```

## report

```
thor-util report --logfile host_thor_2026-11-16_0914.jsonl
thor-util report --logfile a.txt,b.txt
thor-util report --logdir ./logs                      # recursive; .txt .log .json .jsonl
thor-util report --logfile host.jsonl --outfile /reports/host.html --filter noise.txt
```
- Exactly one of `--logfile`/`--logdir`; `--outfile` only with a single `--logfile`.
- One report per log file (despite the `--logdir` help text), written as `<log without extension>.htm` next to
  the log (mode 0600) unless `--outfile` is given.
- Understands THOR text logs and JSON v1/v2/v3 (JSONL). The report is a self-contained HTML viewer.
- `--filter <file>`: one regular expression per line; matching log lines are left out.
- `--include-info` is accepted but has no effect in current builds.
- Encrypted logs: decrypt a copy first. Use after aborted scans (THOR writes no HTML on a non-zero exit).

## logconvert

```
thor-util logconvert --file host_thor.jsonl --to-log --output host_thor.txt   # JSON -> text
thor-util logconvert --file host_thor.txt --to-csv                            # -> host_thor.csv
thor-util logconvert --file host_thor.jsonl --to-csv-zip                      # one CSV per module in a ZIP
thor-util logconvert --from-log --file thor.log --to-json --output thor.jsonl
```
- Input format from `--from-*` or the extension (`.json/.jsonl` = JSON v1/v2/v3, `.txt/.log` = text).
  `--from-kv` is not implemented (exit 2).
- Output from `--to-*` or the `--output` extension (`.json/.jsonl/.txt/.log/.csv/.zip`); without `--output`
  the input name with the new extension is used, and existing files are not overwritten.
- `--to-json` writes flat JSON lines in the old v1 style, not v3. `--to-csv-zip` skips startup/control modules.

## encrypt / decrypt

```
thor-util encrypt my-rules.yar my-iocs.txt --destdir custom-signatures/yara/
thor-util decrypt --privkey mykey-private.pem host_thor.jsonl
```
- `encrypt` takes positional files/globs (no `--file`). Extension mapping: `.yar/.yara/.yac` -> `.yas`,
  `.yml/.yaml` -> `.yms`, `.txt` -> `.dat`, `.json` -> `.jsos`, `.xml` -> `.xms`, `.go` -> `.gs`, other ->
  `+.enc`; name clash -> `2_<name>`; max 300 MB per file. Output lands next to the source unless
  `--destdir`; THOR 11 only loads custom signatures from `custom-signatures/{yara,sigma,iocs,stix}/`.
- `decrypt` overwrites the input **in place**: copy first. Without `--privkey` it uses the built-in default key
  matching v10 `--encrypt` without `--pubkey`. THOR 11 has no default-key mode; it encrypts with
  `--encryption-key <public key>` and needs the matching private key.

## verify

```
thor-util verify --file thor64.exe       # looks for thor64.exe.sig or docs/thor64.exe.sig
thor-util verify --dir /opt/thor         # every executable with a .sig next to it
```
Exit 2 = missing or invalid signature ("the executable may have been modified"). `--dir` only finds `.sig`
files next to the executable; packages keep them in `docs/`, so prefer `--file`. Alternatives: Windows
Authenticode signer "Nextron Systems GmbH", or OpenSSL with Nextron's public code-signing key
(https://www.nextron-systems.com/resources/keys/):
`openssl dgst -sha256 -verify codesign.pem -signature thor64.exe.sig thor64.exe`.
thor-util verifies downloaded packages automatically unless `--insecure` is used.

## diagnostics

`thor-util diagnostics [--output diag.zip] [--run]` while THOR runs. Contents, `--run` semantics and the
privacy warning: `thor-troubleshooting` skill.

## Exit codes

| Code | When |
|---|---|
| 0 | success, "up to date", "already up-to-date" (install) |
| 1 | license, network, download, signature, destination or install errors |
| 2 | `verify`: missing/invalid signature; `logconvert`: usage error or `--from-kv` |
| 255 (Unix) | unknown command/flag or argument errors from the command parser |
