# Example: HTTP sample collector (post-processing hook)

Uploads files that THOR scored 60 or higher (Warnings and Alerts) to a collection server. Based on
https://github.com/thor-plugins/example-httpcollector, rewritten: the upstream version filters only on `MagicHeader
== "EXE"` and would upload **every** EXE THOR touches, because post-processing hooks fire for every element; it also
dereferences `file.Hashes` without a nil check. Compiled and run in THOR 11's interpreter (score 0 and 80, with and
without content/hashes, against a local test server).

## plugin.go

```go
package main

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"time"

	"github.com/NextronSystems/jsonlog/thorlog/v3"
	"github.com/NextronSystems/thor-plugin"
)

const (
	sampleServerURL = "http://localhost:8084/upload" // change to your collector
	minScore        = 60                             // upload Warnings (60+) and Alerts (81+) only
	maxUploadSize   = 50 << 20                       // never buffer more than 50 MB
)

// One shared client with a timeout; hooks can run concurrently and
// http.Client is safe for concurrent use.
var client = &http.Client{Timeout: 30 * time.Second}

func Init(config thor.Configuration, logger thor.Logger, actions thor.RegisterActions) {
	actions.AddPostProcessingHook(uploadSample)
	logger.Info("httpcollector example plugin initialized", "server", sampleServerURL, "min_score", minScore)
}

// uploadSample runs for EVERY scanned element (files, registry values,
// processes, log lines, ...), not only for findings. Filter early and cheaply.
func uploadSample(logger thor.Logger, object thor.AssessedObject) {
	if object.Assessment == nil || object.Assessment.Score < minScore {
		return
	}
	file, isFile := object.Assessment.Subject.(*thorlog.File)
	if !isFile || object.Content == nil {
		return
	}
	size := object.Content.Size()
	if size <= 0 || size > maxUploadSize {
		logger.Debug("Sample not uploaded (size)", "path", file.Path, "size", size)
		return
	}
	sha256 := ""
	if file.Hashes != nil { // nil unless THOR hashed the file (deep-scanned regular files)
		sha256 = file.Hashes.Sha256
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	_ = writer.WriteField("sha256", sha256)
	_ = writer.WriteField("score", strconv.FormatInt(object.Assessment.Score, 10))
	_ = writer.WriteField("module", object.Assessment.Meta.Mod)
	part, err := writer.CreateFormFile("file", file.Path)
	if err != nil {
		logger.Error("Could not create multipart section", "error", err.Error())
		return
	}
	// SectionReader reads via ReadAt: independent of the reader's current offset.
	if _, err := io.Copy(part, io.NewSectionReader(object.Content, 0, size)); err != nil {
		logger.Error("Could not read sample", "path", file.Path, "error", err.Error())
		return
	}
	if err := writer.Close(); err != nil {
		logger.Error("Could not finish multipart body", "error", err.Error())
		return
	}
	req, err := http.NewRequest(http.MethodPost, sampleServerURL, body)
	if err != nil {
		logger.Error("Could not create request", "error", err.Error())
		return
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := client.Do(req)
	if err != nil {
		logger.Error("Upload failed", "path", file.Path, "error", err.Error())
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		logger.Error("Upload rejected", "path", file.Path, "status", resp.Status)
		return
	}
	logger.Info("Uploaded sample", "path", file.Path, "sha256", sha256, "score", object.Assessment.Score)
}
```

## metadata.yml

```yaml
name: httpcollector
version: v1.1.0
author: Your Name
description: Uploads files with a score of 60 or more to a sample server
link: https://github.com/thor-plugins/example-httpcollector
requires_thor: v11.0.0-0
```

## Key points

- Filter first: `object.Assessment.Score < minScore` returns before any work. The hook runs for files, registry
  values, processes, log lines … of the whole scan.
- `object.Assessment.Subject` is the scanned object; type-assert to `*thorlog.File`.
- `object.Content` is nil for elements without data; `file.Hashes` is nil when THOR did not hash the file
  (not deep-scanned, not a regular file).
- `io.NewSectionReader(object.Content, 0, size)` reads from offset 0 regardless of earlier reads.
- One shared `http.Client` with timeout; hooks may run in parallel.
- The server URL is a constant here. For deployments, read it from an environment variable
  (`os.Getenv("MYCOLLECTOR_URL")`) as the public `finding-webhook` plugin does; THOR passes its environment to
  plugins.
- Data protection: uploading samples moves potentially sensitive files off the host. Use TLS (`https://`), restrict
  the score threshold and get approval before deploying.

## Minimal receiving server for tests

```python
# test-server.py: prints what it receives (test use only)
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        print(self.path, len(body), "bytes")
        self.send_response(200); self.end_headers()
http.server.HTTPServer(("127.0.0.1", 8084), H).serve_forever()
```

## Package

```bash
zip -j httpcollector.zip plugin.go metadata.yml
```
