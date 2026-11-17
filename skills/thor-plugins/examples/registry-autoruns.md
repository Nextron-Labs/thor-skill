# Example: registry Run key checker (registry rule + AddReason)

Logs every Run/RunOnce value THOR sees and raises a finding (score 60, Warning) when the command line points to a
user-writable folder or a script host. Based on https://github.com/thor-plugins/example-list-registry-autoruns,
extended with `AddReason`. Compiled and run in THOR 11's interpreter.

## plugin.go

```go
package main

import (
	"strings"

	"github.com/NextronSystems/jsonlog/thorlog/v3"
	"github.com/NextronSystems/thor-plugin"
)

// Registry YARA rules see one line per value: KEYPATH;VALUENAME;VALUE
// (no HKLM/HKCU prefix). This rule tags every value under a Run/RunOnce key.
const runKeyRule = `
rule PluginExample_RunKey : PLUGIN_RUNKEY {
    meta:
        description = "Run/RunOnce value (trigger for plugin)"
        score = 0
    strings:
        $run = "\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
    condition:
        $run
}`

var suspicious = []string{
	`\appdata\local\temp\`, `\users\public\`, `\programdata\`,
	"powershell", "mshta", "rundll32", "regsvr32", "wscript", "cscript",
}

func Init(config thor.Configuration, logger thor.Logger, actions thor.RegisterActions) {
	actions.AddYaraRule(thor.TypeRegistry, runKeyRule)
	actions.AddRuleHook("PLUGIN_RUNKEY", checkRunValue)
	logger.Info("registry-autoruns example plugin initialized")
}

func checkRunValue(scanner thor.Scanner, object thor.MatchingObject) {
	value, ok := object.Object.(*thorlog.RegistryValue)
	if !ok {
		return
	}
	// Key holds the key path plus value name, separated by backslashes on every
	// OS (also when THOR scans hives from an image on Linux), so don't use filepath.Base.
	name := value.Key
	if i := strings.LastIndex(name, `\`); i >= 0 {
		name = name[i+1:]
	}
	scanner.Debug("Autorun entry", "key", value.Key, "name", name, "command", value.ParsedValue)

	cmd := strings.ToLower(value.ParsedValue)
	for _, s := range suspicious {
		if strings.Contains(cmd, s) {
			// AddReason raises the score of THIS registry value; THOR then
			// reports it as Notice/Warning/Alert like any other finding.
			scanner.AddReason(thorlog.NewReason(
				"Run key entry with suspicious command line",
				thorlog.Signature{
					Score:           60,
					Type:            thorlog.Custom,
					Class:           thorlog.ClassInternalHeuristic,
					Rulename:        "PluginExample_SuspiciousRunKey",
					LongDescription: "Run key value contains " + s,
					Tags:            thorlog.StringList{"PERSISTENCE"},
				},
				nil,
			))
			return
		}
	}
}
```

## metadata.yml

```yaml
name: registry-autoruns
version: v1.0.0
author: Your Name
description: Flags Run key values with suspicious command lines
link: https://github.com/thor-plugins/example-list-registry-autoruns
requires_thor: v11.0.0-0
```

## Key points

- `thor.TypeRegistry` rules see registry data, per key as `KEYPATH;VALUENAME;VALUE` lines (no `HKLM`/`HKCU`
  prefix) and per value as text. The rule matches both; the hook acts only on `*thorlog.RegistryValue`.
- `RegistryValue` has `Key` (key path + `\` + value name), `ParsedValue` (data as string; REG_BINARY upper hex,
  numbers decimal), `Modified`, `Size`. There is no registry type field.
- `thorlog.NewReason(summary, thorlog.Signature{…}, nil)` is the only way to build a reason; the reason is added to
  this registry value and reported with THOR's normal levels (60 = Warning; THOR 11 needs total >= 81 and one
  subscore >= 76 for an Alert).
- Registry data comes from the live registry on Windows and from hive files found by Filescan (also on images).
  Registry scanning is not part of THOR Lite.
- `Debug` lines appear only with `--debug`; use `Info` sparingly, it is written for every Run value.

## Package and test

```bash
zip -j registry-autoruns.zip plugin.go metadata.yml
```

```powershell
# Windows (PowerShell), registry module only; filter license lines, keep only plugin lines
thor64.exe --module RegistryChecks --debug --no-thordb -e C:\thor-test `
  | Select-String -NotMatch 'LICENSE_OWNER|License file found|Scan Information' `
  | Select-String 'plugin|registry-autoruns'
```

This is not a narrow test: RegistryChecks walks the whole live registry, so the run takes minutes and
`--debug` writes a very large log. Read only the filtered lines, never the full console output.
