# Getting started: first THOR 11 plugin

Read this to build a plugin from scratch. Needs THOR 11 and Go (only for dependency handling and a local type
check; THOR interprets the source, it does not need compiled code).

## 1. Project

```bash
mkdir hello-plugin && cd hello-plugin
go mod init example.com/hello-plugin
go get github.com/NextronSystems/thor-plugin@732bd59e9da7     # API linked by THOR 11.0
go get github.com/NextronSystems/jsonlog@16aa1af352dc         # object types (thorlog/v3) of current THOR 11 builds
```
Newer THOR builds may link newer versions; the API used here is stable since THOR 11.0.0-rc.1. Alternatively start
from the template repository https://github.com/thor-plugins/template (update its `go.mod` pins as above).

## 2. Code: `plugin.go`

A rule hook that inspects batch files and adds a finding, plus a post-processing hook that reports high-score
elements. This exact code compiles and runs in THOR's interpreter.

```go
package main

import (
	"strings"
	"sync/atomic"

	"github.com/NextronSystems/jsonlog/thorlog/v3"
	"github.com/NextronSystems/thor-plugin"
)

// Hooks can run concurrently (THOR 11 scans multi-threaded): use atomics or a mutex for shared state.
var assessed atomic.Int64

func Init(config thor.Configuration, logger thor.Logger, actions thor.RegisterActions) {
	// 1. A trigger rule. Meta rules see every file (first 64 KB + external variables).
	actions.AddYaraRule(thor.TypeMeta, `
rule Hello_BatchFile : HELLO_BAT {
    meta:
        description = "Batch file (trigger for hello plugin)"
        score = 0
    condition:
        extension == ".bat" or extension == ".cmd"
}`)
	// 2. Rule hook: runs for every element that a signature tagged HELLO_BAT matched.
	actions.AddRuleHook("HELLO_BAT", func(scanner thor.Scanner, object thor.MatchingObject) {
		file, ok := object.Object.(*thorlog.File)
		if !ok || object.Content == nil {
			return
		}
		buf := make([]byte, 4096)
		n, _ := object.Content.ReadAt(buf, 0)
		text := strings.ToLower(string(buf[:n]))
		scanner.Debug("Inspecting batch file", "path", file.Path, "bytes", n)
		if strings.Contains(text, "vssadmin delete shadows") {
			scanner.AddReason(thorlog.NewReason(
				"Batch file deletes volume shadow copies",
				thorlog.Signature{Score: 75, Type: thorlog.Custom, Class: thorlog.ClassInternalHeuristic, Rulename: "Hello_ShadowDelete"},
				nil,
			))
		}
		// Hand derived data back to THOR (filename IOCs, keyword YARA, Sigma).
		scanner.ScanStructuredData([]thor.KeyValuePair{{Key: "first_line", Value: strings.SplitN(text, "\n", 2)[0]}})
	})
	// 3. Post-processing hook: runs for EVERY scanned element, after scoring.
	actions.AddPostProcessingHook(func(logger thor.Logger, object thor.AssessedObject) {
		assessed.Add(1)
		if object.Assessment == nil || object.Assessment.Score < 80 {
			return
		}
		logger.Info("High score element", "module", object.Assessment.Meta.Mod, "score", object.Assessment.Score,
			"type", object.Assessment.Subject.EmbeddedHeader().Type)
	})
	logger.Info("hello plugin initialized", "max_file_size", config.MaxFileSize)
}
```

## 3. `metadata.yml` (optional, strict)

```yaml
name: hello
version: v0.1.0
author: Your Name
description: Minimal example with a rule hook and a post-processing hook
requires_thor: v11.0.0-0
```
Only `name`, `version`, `author`, `description`, `link`, `requires_thor`, `build_tags` are allowed. Keep
`requires_thor: v11.0.0-0` while you run release candidates; `v11.0.0` refuses `11.0.0-rc.N` builds.

## 4. Check, then run unpacked

```bash
go vet ./...                       # type check against the real API
mkdir -p /opt/thor/plugins/hello && cp plugin.go metadata.yml /opt/thor/plugins/hello/
mkdir -p /tmp/plugintest && printf '@echo off\r\nvssadmin delete shadows /all /quiet\r\n' > /tmp/plugintest/x.bat
cd /opt/thor
./thor-linux-64 --module Filescan --path /tmp/plugintest --plugin-development-mode --debug --no-thordb \
  -e /tmp/thor-out | grep -v -e LICENSE_OWNER -e 'License file found' -e 'Scan Information' \
  | grep -i -e plugin -e hello
```
Expected: `Loaded plugin` (module `Plugin`), `hello plugin initialized` (module `hello`), Debug `Invoking plugin
hook` with `TAGS: HELLO_BAT`, then a finding for `x.bat` whose reasons include `Batch file deletes volume shadow
copies` (score 75: Warning). `go vet` passing does not prove yaegi accepts the code; the THOR run does.

## 5. Package and deploy

```bash
zip -r hello.zip plugin.go metadata.yml          # files at ZIP root
cp hello.zip /opt/thor/plugins/ && rm -rf /opt/thor/plugins/hello
```
See `packaging.md` for vendoring and release automation.

## 6. Design rules

- One unique tag per trigger rule (`MYPLUGIN_FORMAT`), `score = 0`, `thor.TypeMeta` for file formats.
- Check types with a type switch/assertion; nil-check `object.Content`, `object.Assessment`, `File.Hashes`.
- Respect `config.MaxFileSize` (`0` means unlimited, so `size > config.MaxFileSize` alone would reject everything).
- No output via `fmt.Print*`; use the logger with string keys: `scanner.Info("msg", "path", p)`.
- Configuration: plugins get no command-line options. Read environment variables (`os.Getenv`, THOR passes its
  environment) or constants compiled into the plugin.
- Keep hooks fast and goroutine-safe; any goroutine you start must finish before the hook returns.
