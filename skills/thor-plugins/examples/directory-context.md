# Example: directory context (burst of JVM crash logs)

Pattern for **detections that depend on other files**, which YARA rules and filename IOCs cannot express: counts,
time windows, related files next to the matched one. A meta rule tags the file, the hook lists its directory once,
caches the result, and adds a reason to every file that is part of the pattern.

Use case: memory corruption exploits against Java services (e.g. CVE-2026-114938) often crash the JVM on failed
attempts and get retried. Each crash writes a HotSpot fatal error log (`hs_err_pid<pid>.log`). One crash log is
normal; three or more in one folder within an hour are worth a look. Native out-of-memory crash loops are excluded,
they are the main false positive source. Run in THOR 11.0.0-rc.3 against test folders: bursts flagged with score
60 (Warning), single and spread-out crash logs and OOM loops not flagged.

Full plugin with GC-crash and CVE-2026-114938 exposure checks, test fixtures and release builds:
https://github.com/Nextron-Labs/thor-plugin-jvm-crash-cluster

## plugin.go

```go
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/NextronSystems/jsonlog/thorlog/v3"
	"github.com/NextronSystems/thor-plugin"
)

const (
	window   = 60 * time.Minute
	minCount = 3
	header   = "A fatal error has been detected by the Java Runtime Environment"
	oom      = "There is insufficient memory for the Java Runtime Environment to continue"
)

type dirResult struct {
	members map[string]bool // crash logs that are part of a burst
	summary string
}

var (
	mu    sync.Mutex // hooks run concurrently
	cache = map[string]*dirResult{}
)

func Init(config thor.Configuration, logger thor.Logger, actions thor.RegisterActions) {
	actions.AddYaraRule(thor.TypeMeta, `
rule JVM_Fatal_Error_Log : JVMCRASHLOG {
	meta:
		description = "HotSpot fatal error log (trigger for the crash burst plugin)"
		score = 0
	strings:
		$h = "# A fatal error has been detected by the Java Runtime Environment" ascii
	condition:
		$h in (0..256)
}`)
	actions.AddRuleHook("JVMCRASHLOG", func(scanner thor.Scanner, object thor.MatchingObject) {
		file, ok := object.Object.(*thorlog.File)
		if !ok {
			return
		}
		r := analyzeDir(filepath.Dir(file.Path), scanner)
		if r.members[filepath.Base(file.Path)] {
			scanner.AddReason(thorlog.NewReason(r.summary, thorlog.Signature{
				Score:           60,
				Type:            thorlog.Custom,
				Class:           thorlog.ClassInternalHeuristic,
				Rulename:        "JVM_Crash_Log_Burst",
				LongDescription: "Several JVM fatal error logs in a short time span, e.g. retried memory corruption exploits",
			}, nil))
		}
	})
	logger.Info("crash burst plugin loaded", "window", window.String(), "min_count", minCount)
}

// analyzeDir lists a directory once per scan and caches the result.
func analyzeDir(dir string, logger thor.Logger) *dirResult {
	mu.Lock()
	defer mu.Unlock()
	if r, ok := cache[dir]; ok {
		return r
	}
	r := &dirResult{members: map[string]bool{}}
	cache[dir] = r

	entries, err := os.ReadDir(dir) // fails e.g. for files inside archives
	if err != nil {
		logger.Debug("cannot list directory", "dir", dir, "error", err.Error())
		return r
	}
	type crash struct {
		name  string
		mtime time.Time
	}
	var crashes []crash
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasSuffix(strings.ToLower(e.Name()), ".log") {
			continue
		}
		head := readHead(filepath.Join(dir, e.Name()), 4096)
		if !bytes.Contains(head, []byte(header)) || bytes.Contains(head, []byte(oom)) {
			continue // not a crash log, or a native OOM crash loop (false positive source)
		}
		if info, err := e.Info(); err == nil {
			crashes = append(crashes, crash{e.Name(), info.ModTime()})
		}
	}
	sort.Slice(crashes, func(i, j int) bool { return crashes[i].mtime.Before(crashes[j].mtime) })

	// Sliding window over the modification times; every file in a dense window is a member.
	best, start := 0, 0
	for end := range crashes {
		for crashes[end].mtime.Sub(crashes[start].mtime) > window {
			start++
		}
		if n := end - start + 1; n >= minCount {
			for k := start; k <= end; k++ {
				r.members[crashes[k].name] = true
			}
			if n > best {
				best = n
				r.summary = fmt.Sprintf("JVM crash burst: %d fatal error logs within %s in %s (first %s)",
					n, crashes[end].mtime.Sub(crashes[start].mtime), dir, crashes[start].mtime.UTC().Format(time.RFC3339))
			}
		}
	}
	return r
}

func readHead(path string, limit int) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, limit)
	n, _ := io.ReadFull(f, buf)
	return buf[:n]
}
```

## metadata.yml

```yaml
name: jvm-crash-burst
version: v0.1.0
description: Flags bursts of JVM fatal error logs in the same directory
requires_thor: v11.0.0-0
```

## How it works

- Trigger on content, not name: the HotSpot header in the first 256 bytes also catches logs renamed with
  `-XX:ErrorFile`. `score = 0`, `thor.TypeMeta`, so the trigger itself adds nothing.
- The hook fires once per crash log. `analyzeDir` lists the directory on the first call and caches the result per
  directory; the mutex makes concurrent hooks wait for the first one instead of listing the folder in parallel.
- Siblings are checked by reading their first 4 KB with `os.Open`, timestamps come from `DirEntry.Info().ModTime()`.
- Every file inside a window of `minCount` crashes within `window` gets the reason, not only the last one.
- `os.ReadDir` errors are expected (members of archives have virtual paths) and only logged at Debug level.

## Limits of the pattern

- Modification times: files copied without preserved timestamps (collector ZIPs, some copy tools) all get the copy
  time and look like a burst. Scan the original file system or a mounted image.
- The hook sees only what it can list itself: correlation across directories (e.g. one service crashing into
  several working directories) needs its own logic, e.g. a global map keyed by service or command line.
- There is no end-of-scan hook. Decide inside the hook call; a result that only becomes clear later in the scan
  cannot be attached to elements that were already reported.

## Package and test

```bash
zip -j jvm-crash-burst.zip plugin.go metadata.yml
cp jvm-crash-burst.zip /opt/thor/plugins/
./thor-linux-64 --module Filescan --path /tmp/plugintest --no-thordb -e /tmp/thor-out \
  | grep -v -e LICENSE_OWNER -e 'License file found' -e 'Scan Information' | grep -i -e plugin -e 'crash burst'
```
Test data: copy a few files that start with `#\n# A fatal error has been detected by the Java Runtime Environment:`
into `/tmp/plugintest` and set their times with `touch -t` (e.g. 10:00, 10:07, 10:15).
