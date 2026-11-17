# THOR plugin API reference (THOR 11)

Read this when writing hook code. Source of truth: `thorplugin.go` in https://github.com/NextronSystems/thor-plugin
(THOR 11.0 links commit `732bd59e9da7`) and the object types in https://github.com/NextronSystems/jsonlog
(`thorlog/v3`). Import paths:

```go
import (
	"github.com/NextronSystems/jsonlog/thorlog/v3" // package thorlog
	"github.com/NextronSystems/thor-plugin"        // package thor
)
```
Importable non-stdlib packages are only these two module trees (`jsonlog`, `jsonlog/thorlog/common`, `/v1`, `/v2`,
`/v3`, `/parser`, `thor-plugin`) plus what you vendor.

## Entry point

```go
type PluginInitializeFunction func(Configuration, Logger, RegisterActions)

func Init(config thor.Configuration, logger thor.Logger, actions thor.RegisterActions)
```
- Called once at THOR start-up. A panic is recovered ("Plugin's Init function panicked") and the plugin is not
  loaded.
- `thor.Configuration{MaxFileSize uint64}`: the file size limit (`--file-size-limit`, default 64 MB; `0` = no limit).
- A `func main()` is allowed but never called.

## RegisterActions (only effective during Init)

```go
AddYaraRule(ruletype YaraRuleType, rule string)
AddRuleHook(tag string, callback RuleMatchedCallback)
AddPostProcessingHook(callback PostProcessingCallback)
```

| `YaraRuleType` | THOR rule type | Applied to |
|---|---|---|
| `thor.TypeMeta` | meta | every file: first 64 KB (THOR 11; the API comment still says 2048) + externals |
| `thor.TypeDefault` | generic | files selected for deep scan |
| `thor.TypeKeyword` | keyword | all non-file elements as text |
| `thor.TypeRegistry` | registry | registry keys/values (`KEYPATH;VALUENAME;VALUE` lines per key) |
| `thor.TypeLog` | log | log lines, event log, journald, audit log entries |
| `thor.TypeProcess` | process | process memory, memory dumps, DeepDive chunks |

- Plugin rules are compiled into THOR's rule set as custom rules with source `Plugin:<name>`; all THOR externals
  (`filetype`, `extension`, `filename`, `filepath` = directory, `unpack_parent` …) are available.
- `--custom-signatures-only` keeps plugin rules (they are custom).
- Several rules can be passed in one string.

## Rule hooks

```go
type RuleMatchedCallback func(scanner Scanner, object MatchingObject)

type MatchingObject struct {
	Object  jsonlog.Object // *thorlog.File, *thorlog.RegistryValue, *thorlog.Process, ...
	Content ObjectReader   // nil/empty except for files and processes
}

type ObjectReader interface {
	io.ReaderAt
	io.ReadSeeker
	Size() int64
}
```
- Fires when any reason on the element has the tag (exact string). Rules from any source count: your
  `AddYaraRule` rule, a custom YARA or Sigma rule with that tag (Sigma `tags:` entry), or a built-in rule.
- Runs after the standard scanners (YARA, Sigma, IOCs) for that element, before it is scored and logged.
- Prefer `ReadAt` / `io.NewSectionReader(object.Content, 0, object.Content.Size())`: independent of the reader's
  current position. For processes `Content` is sparse virtual memory: read only regions you know.

### Scanner (valid only during the callback)

```go
type Scanner interface {
	ScanFile(name string, data []byte, unpackMethod string)
	ScanStructuredData(data []KeyValuePair)
	AddReason(reason thorlog.Reason)
	Logger
}
type KeyValuePair struct{ Key, Value string }
```
- `ScanFile`: queued as a child file of the current element (path `<parent>/<name>`), scanned with all file
  features incl. plugin hooks (recursion). `unpackMethod` by convention upper case (`ZIP`, `DEFENDER_QUARANTINE`);
  becomes `unpack_parent` and part of `unpack_source`.
- `ScanStructuredData`: object type `structured data from plugin` (`{"plugin": "<name>", "data": {...}}`), checked
  with filename IOCs, keyword YARA and Sigma. Sigma fields are the keys as given. For free text use one key.
- `AddReason`: appends a reason to the current element. There is no `ScanString` (removed); use
  `ScanStructuredData([]thor.KeyValuePair{{Key: "data", Value: s}})`.

### Building a reason

```go
r := thorlog.NewReason(
	"Run key entry with suspicious command line",   // Summary, shown as REASON
	thorlog.Signature{
		Score:           60,                          // -100..100; negative lowers the element score
		Type:            thorlog.Custom,              // Internal, Custom, External
		Class:           thorlog.ClassInternalHeuristic, // free Sigclass string; constants: ClassYaraRule, ClassSigmaRule, ClassFilenameIOC, ...
		Rulename:        "MyPlugin_SuspiciousRunKey",
		LongDescription: "Details for analysts",
		Tags:            thorlog.StringList{"PERSISTENCE"},
		Ref:             thorlog.StringList{"https://example.org/ref"},
		Author:          "Your Name",
	},
	nil, // thorlog.MatchStrings (optional)
)
scanner.AddReason(r)
```
`thorlog.Reason{Score: 50, Message: "…"}` does not compile: there is no `Message` field, and `Score` belongs to the
embedded `Signature`. On a `Reason` value, `r.Type` is ambiguous (object header vs signature): use `r.Signature.Type`.
Scoring: element total from all reasons (positive ones weighted 1, 1/2, 1/4 …); Notice from 40, Warning 60, Alert
81 with at least one subscore >= 76.

## Post-processing hooks

```go
type PostProcessingCallback func(logger Logger, object AssessedObject)

type AssessedObject struct {
	Assessment *thorlog.Assessment
	Content    ObjectReader // nil for elements without data
}
```
- Called for **every** element after scoring, also for score 0. Filter immediately.
- Treat `Assessment` as read-only; changes are not reflected in THOR's output.

| `thorlog.Assessment` field | Content |
|---|---|
| `Score int64` | 0..100 total score |
| `Subject thorlog.ObservedObject` | the element (`*thorlog.File`, `*thorlog.Process`, …); `Subject.EmbeddedHeader().Type` gives the type name |
| `Reasons []thorlog.Reason`, `ReasonCount int` | reasons (may be truncated) and total count |
| `Meta.Mod`, `Meta.Lvl`, `Meta.Time`, `Meta.ScanID`, `Meta.Source` | module, level (`Alert`, `Warning`, `Notice`, `Info`, `Debug`), time, scan ID, hostname |
| `Text` | message THOR prints |
| `Ancestors`, `Derivatives` | containing archives etc., referenced objects |

The whole assessment marshals to THOR's JSON v3 format: `json.Marshal(object.Assessment)`.

## Logger

```go
Info(text string, kv ...any)
Debug(text string, kv ...any)   // visible with --debug
Error(text string, kv ...any)
```
Keys must be strings and pairs complete, otherwise the line is replaced by Error `Bad log message from plugin`.
Module = plugin `name`. There is no Notice/Warning/Alert method: findings come from `AddReason` or tagged
signatures. Stdout/stderr of the plugin are discarded.

## Common object types (`thorlog/v3`)

| Go type | `type` name | Key fields (Go / JSON) |
|---|---|---|
| `*thorlog.File` | `file` | `Path`/`path`, `Extension`, `MagicHeader`/`magic_header` (= YARA `filetype`), `Size`, `Hashes *FileHashes{Md5, Sha1, Sha256}` (**may be nil**), `Filetimes *Filetimes`, `UnpackSource`, `Permissions`, `PeInfo` |
| `*thorlog.Process` | `process` | `Pid`, embedded `ProcessInfo{Name, Cmdline (json command), User (json owner), Image *File, ParentInfo{Pid, Exe, CommandLine}, Created, Session}`, `Handles`, `Connections` |
| `*thorlog.RegistryValue` | `registry value` | `Key` (key path + `\` + value name, always backslashes), `ParsedValue` (json `value`), `Modified`, `Size` |
| `*thorlog.RegistryKey` | `registry key` | `Key`, `Modified`, `FormattedValues` (`path;name;value` lines) |
| `*thorlog.LogLine` | `log line` | `LineIndex`, `Line` |
| `*thorlog.WindowsEventlogEntry` | `eventlog entry` | event fields |
| `*thorlog.AutorunEntry` | `autorun entry` | `Type` (json `autorun_type`), `Location`, `Image *File`, `Arguments`, `Entry`, `LaunchString` |
| `*thorlog.WindowsService` | `Windows service` | `ServiceName`, `Command`, `Image *File`, `StartType`, `User` |
| `*thorlog.CronJob` | `cron job` | `User`, `Schedule`, `Command` |
| `*thorlog.PluginStructuredData` | `structured data from plugin` | `Plugin`, `Data` |

All types: `--describe-object-type all` on a THOR 11 binary (JSON schemas).

## Interpreter limits (yaegi in THOR 11)

- Go 1.22 standard library API (generics work; very new language features may not). Missing packages: `os/exec`,
  `syscall`, `unsafe`, `plugin`, `embed`, `iter`, `unique`; no cgo.
- Third-party pure-Go packages must be vendored (`vendor/` in the ZIP); packages using `unsafe`, `syscall`,
  assembly or cgo fail to compile.
- No sandbox: the plugin can read files, open network connections and sees THOR's environment variables.
- CPU limiting (`--cpu-limit`) also pauses plugin code.
