# YARA Forge

YARA Forge (https://yarahq.github.io) packages public YARA rules from many open-source repositories into
three rule sets. thor-util installs one of them as custom signatures. Source: the latest release of the
GitHub project `YARAHQ/yara-forge` (`yara-forge-rules-<ruleset>.zip`).

## Rule sets

| Ruleset | Content (per the YARA Forge project) | Typical use |
|---|---|---|
| `core` | smallest set, rules with the best accuracy and performance | production sweeps |
| `extended` | `core` plus more rules with somewhat more false positives / cost | threat hunting, analysis hosts |
| `full` | everything that passes the project's quality checks | lab and research |

Every set adds scan time and memory; larger sets add false positives. Start with `core`. THOR's own
signatures already cover much of the public rule space; YARA Forge is a supplement.

## Commands

```sh
thor-util yara-forge download --ruleset core              # install or switch (core|extended|full)
thor-util yara-forge download --ruleset core --path /opt/thor
thor-util yara-forge download --ruleset core --path pack.zip   # into an offline pack
thor-util yara-forge remove [--path ...]
thor-util upgrade  --ruleset extended                     # switch during an upgrade
thor-util upgrade  --ruleset none                         # remove during an upgrade
thor-util download -t thor-linux --ruleset core --path p.zip   # include in a new pack
```
- `--ruleset` is required for `yara-forge download` ("no YARA Forge ruleset specified").
- One ruleset at a time; switching deletes the previous folder first.
- The choice is remembered in `.yara-forge-ruleset` inside the YARA Forge folder; every later `update`,
  `upgrade` and `download` refreshes the rules when a new YARA Forge release exists ("YARA Forge rules are up
  to date" otherwise).
- Downloads go to GitHub directly and use only the `HTTP_PROXY`/`HTTPS_PROXY` environment variables, not
  thor-util's `--proxy` flags. Air-gapped: add the rules to a pack on the connected host.
- Lite: works the same with `thor-lite-util`.

## Location

| | v10 | v11 |
|---|---|---|
| Folder | `custom-signatures/yara-forge/` | `custom-signatures/yara/yara-forge/` |
| Format | encrypted `.yas` files | encrypted `.yas` files |
| v10 -> v11 | the upgrade moves the rules; the THOR 11 thor-util completes the move (re-install at the new place) on its next run | |

THOR loads them as custom YARA rules (check the Init lines `Adding rule set from ...`).

## False positives

Hits show the YARA Forge rule name in the reason. Suppress single noisy rules with a line in
`config/false_positive_filters.cfg`: one regular expression per line, matched against the whole log line,
for example the rule name as shown in the reason (escape regex metacharacters):
```
Example_Noisy_Rule_Name
```
Do not append `;.*` or other separators; that makes the regex fail to match. Alternatively drop to a smaller
ruleset or remove YARA Forge. Rule-level exclusion of signatures in general: v10 `--init-filter`,
v11 `--signature-exclude` (see the `thor-custom-signatures` skill).
