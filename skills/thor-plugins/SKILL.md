---
name: thor-plugins
description: Writes, packages, loads and debugs THOR 11 plugins - Go code in a ZIP in the THOR `plugins/` folder, interpreted by yaegi, using the github.com/NextronSystems/thor-plugin API (Init, RegisterActions, AddYaraRule, AddRuleHook, AddPostProcessingHook, Scanner.ScanFile, ScanStructuredData, AddReason, MatchingObject, AssessedObject, thorlog.Assessment, metadata.yml, --plugin-development-mode, --no-plugins). Use when a user wants to parse a file format THOR does not support, add detection logic beyond YARA/Sigma/IOCs, forward or collect findings and samples, replace the removed THOR 10 action feature (--action_command), or sees errors like "Could not compile plugin", "Plugin has no main.Init function" or "plugin requires THOR version". THOR 11 only.
compatibility: THOR 11.0.x incl. THOR Lite 11, all platforms. Not available in THOR 10. Building needs Go only for `go mod vendor` and local compile checks.
metadata:
  author: Nextron Systems
  version: "2.0"
---

# THOR plugins (THOR 11)

A plugin is Go source in a ZIP that THOR interprets at start-up (yaegi). It registers YARA rules and hooks; THOR
calls the hooks during the scan. Plugins run with THOR's full privileges, file system and network access: only
deploy plugins from trusted sources, review third-party code.

Check the version first: THOR 10 has no plugin support (the closest v10 feature, `--action_command`, is removed
in 11 and replaced by plugins). Plugins work in THOR Lite 11.

## What plugins can and cannot do

| Can | Cannot |
|---|---|
| add YARA rules of any THOR rule type (`AddYaraRule`) | add Sigma rules or IOCs (ship those in `custom-signatures/`) |
| run code when a tagged YARA **or Sigma** rule matches an element (`AddRuleHook`) | log Notice/Warning/Alert directly (only Info/Debug/Error) |
| read the element's content (files, process memory) and hand extracted data back (`ScanFile`, `ScanStructuredData`) | change scan flags or THOR configuration (only `MaxFileSize` is visible) |
| add findings to the element (`AddReason`) | modify elements in post-processing hooks |
| see every assessed element with score and reasons (`AddPostProcessingHook`) | use `unsafe`, `syscall`, `os/exec`, cgo, `embed`, `iter`, `unique` |
| use Go stdlib (Go 1.22 API: `net/http`, `crypto/*`, `archive/*`, `encoding/*` …) and vendored pure-Go modules | print to stdout/stderr (discarded) |

## Structure

```
myplugin.zip              # ZIP root = Go package root (no extra top-level folder!)
├── plugin.go             # any name; package main; func Init(...)
├── more.go               # optional, same package
├── metadata.yml          # optional, strict
└── vendor/               # optional, from `go mod vendor`, minus thor-plugin and jsonlog
```

```go
package main

import (
	"github.com/NextronSystems/jsonlog/thorlog/v3"
	"github.com/NextronSystems/thor-plugin" // package name: thor
)

func Init(config thor.Configuration, logger thor.Logger, actions thor.RegisterActions) { … }
```

`metadata.yml` keys (unknown keys make loading fail): `name` (mandatory if the file exists; module name of all
plugin log lines), `version`, `author`, `description`, `link`, `requires_thor` (semver with `v`), `build_tags`
(list). Without the file the name is the ZIP base name.

**`requires_thor` trap**: THOR compares semver against its own version incl. pre-release suffix. On an
`11.0.0-rc.N` build `requires_thor: v11.0.0` refuses the plugin ("plugin requires THOR version v11.0.0, but THOR
v11.0.0-rc.3 is running"). Use `v11.0.0-0` (accepts all 11.0.0 pre-releases) or omit the key. The upstream
examples use `v11.0.0`.

## Hooks: when they fire

| Registration | Fires | Receives | Use for |
|---|---|---|---|
| `AddRuleHook("TAG", cb)` | after standard scanning of an element, if **any** reason on it carries signature tag `TAG` (exact, case-sensitive). Tag can come from your `AddYaraRule` rule, a custom YARA/Sigma rule or a built-in rule | `thor.Scanner`, `thor.MatchingObject{Object, Content}` | parsers, extra checks, adding reasons |
| `AddPostProcessingHook(cb)` | for **every** scanned element (files, registry values, processes, log lines …), after scoring, whether suspicious or not | `thor.Logger`, `thor.AssessedObject{Assessment, Content}` | export, forwarding, sample collection |

- Trigger rules use `score = 0`; file-format triggers should be `thor.TypeMeta` (meta rules see every file). Do not
  tag them `DEEPSCAN` unless THOR should also run generic YARA on that file.
- Post-processing hooks must filter first (`object.Assessment.Score >= 60`, type switch on
  `object.Assessment.Subject`) and stay cheap: they run once per element per hook.
- `Content` is nil for elements without data (registry, log lines, most objects); process content is sparse
  memory, do not copy it as one stream. `File.Hashes` is nil unless THOR hashed the file. Nil-check both.
- Hooks can run concurrently (THOR 11 scans multi-threaded): guard shared state (`sync.Mutex`, `sync/atomic`).
- `RegisterActions` works only inside `Init`; later calls are ignored with an Error.

## Scanner callbacks (rule hooks only, valid during the callback)

- `ScanFile(name, data, unpackMethod)`: scan bytes as a child file of the element (all file checks incl. your own
  hooks, so recursion works). `unpackMethod` (upper case, e.g. `ZIP`) feeds the `unpack_parent`/`unpack_source`
  YARA externals.
- `ScanStructuredData([]thor.KeyValuePair)`: creates a `structured data from plugin` object, checked with filename
  IOCs, keyword YARA rules and Sigma (`category: structured data from plugin`, fields = your keys verbatim).
- `AddReason(thorlog.NewReason(summary, thorlog.Signature{Score: 70, Type: thorlog.Custom, Class: …, Rulename: …}, nil))`:
  adds a finding to the element; THOR scores and reports it like any signature match.
- `Info/Debug/Error(text, "key", value, …)`: keys must be strings, even count, else the line is dropped
  ("Bad log message from plugin").

API details and object types: [references/plugin-api.md](references/plugin-api.md).

## Workflow

1. Start from [references/getting-started.md](references/getting-started.md) or an example below.
2. `go mod init`, `go get github.com/NextronSystems/thor-plugin@732bd59e9da7` (the API THOR 11.0 links) and
   `go vet ./...` for a type check; native Go compiling is not proof that yaegi accepts it.
3. Develop unpacked: `<thor>/plugins/<name>/` + `--plugin-development-mode` (CLI only).
4. Package: [references/packaging.md](references/packaging.md). Deploy the `.zip` to `<thor>/plugins/`.

## Load and debug safely

Never test on a full system scan. Restrict to a sample folder, no ThorDB, own output directory:

```bash
./thor-linux-64 --module Filescan --path /tmp/plugintest --plugin-development-mode --debug \
  --no-thordb -e /tmp/thor-out | grep -v -e LICENSE_OWNER -e 'License file found' -e 'Scan Information' \
  | grep -i -e plugin -e '<your plugin name>'
```

| Message (module `Plugin` unless noted) | Meaning |
|---|---|
| `Loaded plugin` with PATH and plugin metadata | loaded and `Init` ran |
| `No plugin directory found` (Debug) | no `plugins/` folder next to the binary |
| `unpacked plugins are only supported in plugin development mode` | folder found without `--plugin-development-mode` |
| `unsupported plugin extension` | only `.zip` (and Nextron-encrypted `.zips`) load; `README.md` is ignored |
| `could not parse metadata file` / `metadata file must contain a name` | unknown key or missing name in `metadata.yml` |
| `plugin requires THOR version …` / `bad THOR version requirement` | `requires_thor` too high or not `vX.Y.Z` |
| `Could not compile plugin` | yaegi error: wrong ZIP layout, missing vendor package, unsupported stdlib package, old API |
| `Plugin has no main.Init function` / `Plugin's Init symbol has type …` | wrong package or signature |
| `Plugin's Init function panicked` / `Plugin's YARA hook panicked` / `Plugin's post-processing hook panicked` | runtime panic, recovered; check nil pointers |
| `Plugin added YARA rule with invalid type` | bad `YaraRuleType` |
| `Could not add rules to <type> yara ruleset` with PATH `Plugin:<name>` (module `Init`) | plugin YARA rule does not compile; rule dropped |
| `Invoking plugin hook` with NAME/TAGS (Debug) | hook fired |

Plugin log lines appear with the plugin `name` as module. `--no-plugins` disables all plugins.

## Versioning and compatibility

- The API changed during THOR 11 pre-releases. Current: `AssessedObject{Assessment *thorlog.Assessment}`,
  no `Scanner.ScanString`, no `Logger.Log`. Code using `thor.MatchedObject`, `object.Finding`, `ScanString` or
  `thorlog.Reason{Score:…, Message:…}` is outdated and does not compile.
- THOR provides `thor-plugin` and `jsonlog` itself: never ship them in `vendor/`.
- Public sources: API and docs https://github.com/NextronSystems/thor-plugin, object types
  https://github.com/NextronSystems/jsonlog, template and examples https://github.com/thor-plugins
  (`template`, `example-zipparser`, `example-httpcollector`, `example-list-registry-autoruns`, `defender-quarantine`,
  `finding-webhook`).

## Examples (compile-checked with yaegi against the THOR 11.0 API)

- [examples/zipparser.md](examples/zipparser.md) - meta-rule trigger, read content, `ScanFile` recursion, size limits.
- [examples/defender-quarantine.md](examples/defender-quarantine.md) - decrypt Defender quarantine blobs and rescan.
- [examples/httpcollector.md](examples/httpcollector.md) - post-processing hook that uploads only scored files, nil-safe.
- [examples/registry-autoruns.md](examples/registry-autoruns.md) - registry rule trigger and `AddReason` finding.
