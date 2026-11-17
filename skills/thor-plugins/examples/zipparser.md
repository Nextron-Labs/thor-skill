# Example: ZIP parser (rule hook + ScanFile)

Pattern for **any file format THOR does not unpack itself**: a meta rule tags the format, the hook reads the
content and hands each extracted member back to THOR with `ScanFile`. THOR 11 already unpacks ZIP natively, so in
production adapt this to your format (deploying it as-is scans ZIP members twice). Based on
https://github.com/thor-plugins/example-zipparser, updated: nil content check, `MaxFileSize == 0` (unlimited)
handled, member count and real size bounded. Compiled and run in THOR 11's interpreter.

## plugin.go

```go
package main

import (
	"archive/zip"
	"io"

	"github.com/NextronSystems/jsonlog/thorlog/v3"
	"github.com/NextronSystems/thor-plugin"
)

// maxEntries caps the number of archive members we extract (ZIP bomb guard).
const maxEntries = 10000

func Init(config thor.Configuration, logger thor.Logger, actions thor.RegisterActions) {
	// Meta rules run on every file (first 64 KB in THOR 11 + external variables).
	actions.AddYaraRule(thor.TypeMeta, `
rule PluginExample_ZipFile : PLUGIN_ZIPFILE {
    meta:
        description = "Trigger for the zipparser example plugin"
        score = 0
    condition:
        filetype == "ZIP"
}`)
	actions.AddRuleHook("PLUGIN_ZIPFILE", func(scanner thor.Scanner, object thor.MatchingObject) {
		file, isFile := object.Object.(*thorlog.File)
		if !isFile || object.Content == nil {
			return
		}
		zipReader, err := zip.NewReader(object.Content, object.Content.Size())
		if err != nil {
			scanner.Debug("Could not parse ZIP file", "path", file.Path, "error", err.Error())
			return
		}
		for i, entry := range zipReader.File {
			if i >= maxEntries {
				scanner.Info("Too many ZIP entries, stopping", "path", file.Path, "entries", len(zipReader.File))
				return
			}
			scanEntry(config, scanner, entry)
		}
	})
	logger.Info("zipparser example plugin initialized")
}

func scanEntry(config thor.Configuration, scanner thor.Scanner, entry *zip.File) {
	if entry.FileInfo().IsDir() {
		return
	}
	// MaxFileSize == 0 means "no limit" (--file-size-limit 0).
	if config.MaxFileSize != 0 && entry.UncompressedSize64 > config.MaxFileSize {
		scanner.Debug("ZIP entry exceeds file size limit, skipped", "entry", entry.Name, "size", entry.UncompressedSize64)
		return
	}
	rc, err := entry.Open()
	if err != nil {
		scanner.Debug("Could not open ZIP entry", "entry", entry.Name, "error", err.Error())
		return
	}
	defer rc.Close()
	var limit int64 = 1 << 30
	if config.MaxFileSize != 0 {
		limit = int64(config.MaxFileSize)
	}
	// Read at most limit+1 bytes: the header size can lie.
	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		scanner.Debug("Could not read ZIP entry", "entry", entry.Name, "error", err.Error())
		return
	}
	if int64(len(data)) > limit {
		scanner.Debug("ZIP entry larger than declared, skipped", "entry", entry.Name)
		return
	}
	// Hand the content back to THOR. It is scanned like a file found on disk;
	// if it is a ZIP again, this hook fires again for it.
	scanner.ScanFile(entry.Name, data, "ZIP")
}
```

## metadata.yml

```yaml
name: zipparser-example
version: v1.0.0
author: Your Name
description: Example plugin that extracts ZIP members and hands them back to THOR
link: https://github.com/thor-plugins/example-zipparser
requires_thor: v11.0.0-0
```

## How it works

- `thor.TypeMeta` + `filetype == "ZIP"`: meta rules run on every file and see the magic-header type through the
  `filetype` external (other externals: `filename`, `extension`, `filepath` = directory, `filesize` is YARA's own).
- `score = 0`: the trigger adds nothing to the score; findings come from scanning the members.
- `zip.NewReader(object.Content, object.Content.Size())`: `ObjectReader` implements `io.ReaderAt`.
- `ScanFile(entry.Name, data, "ZIP")`: each member is scanned as `<archive path>/<member>` with all file checks;
  YARA sees `unpack_parent == "ZIP"`. A nested ZIP triggers the hook again: bound recursion and sizes yourself
  (entry count, declared vs. real size, total bytes).
- `config.MaxFileSize` is 0 with `--file-size-limit 0`: treat 0 as "no limit", keep an own hard cap.

## Package and test

```bash
zip -j zipparser.zip plugin.go metadata.yml
cp zipparser.zip /opt/thor/plugins/
./thor-linux-64 --module Filescan --path /tmp/plugintest --debug --no-thordb -e /tmp/thor-out \
  | grep -v -e LICENSE_OWNER -e 'License file found' -e 'Scan Information' | grep -i -e plugin -e zipparser
```
