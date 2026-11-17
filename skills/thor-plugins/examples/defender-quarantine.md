# Example: Windows Defender quarantine extractor

Decrypts Defender quarantine blobs (`C:\ProgramData\Microsoft\Windows Defender\Quarantine\ResourceData\…`) and lets
THOR scan the original payload, so quarantined malware shows up with its real detections. Based on
https://github.com/thor-plugins/defender-quarantine, updated for the current API and `requires_thor`; all read and
cipher errors are checked. Compiled and run in THOR 11's interpreter against a synthetic quarantine blob.

## plugin.go

```go
package main

import (
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/NextronSystems/jsonlog/thorlog/v3"
	"github.com/NextronSystems/thor-plugin"
)

func Init(config thor.Configuration, logger thor.Logger, actions thor.RegisterActions) {
	// Meta rule: sees every file. No DEEPSCAN tag needed; the hook reads the
	// content itself, and a generic YARA pass over the encrypted blob is useless.
	actions.AddYaraRule(thor.TypeMeta, `
rule PluginExample_DefenderQuarantine : PLUGIN_DEFENDER_QUARANTINE {
    meta:
        description = "Windows Defender quarantine blob (trigger for plugin)"
        score = 0
    condition:
        uint16(0) == 0xAD0B and uint8(2) == 0x00
}`)
	actions.AddRuleHook("PLUGIN_DEFENDER_QUARANTINE", func(scanner thor.Scanner, object thor.MatchingObject) {
		extractAndRescan(config, scanner, object)
	})
	logger.Info("defender-quarantine example plugin initialized")
}

func extractAndRescan(config thor.Configuration, scanner thor.Scanner, object thor.MatchingObject) {
	file, ok := object.Object.(*thorlog.File)
	if !ok || object.Content == nil {
		return
	}
	// Only real quarantine files (normalize separators and case).
	p := strings.ToLower(strings.ReplaceAll(file.Path, "\\", "/"))
	if !strings.Contains(p, "programdata/microsoft/windows defender/quarantine/") {
		return
	}
	limit := int64(config.MaxFileSize)
	if limit == 0 || limit > 1<<30 {
		limit = 1 << 30 // MaxFileSize 0 = unlimited; keep a hard cap anyway
	}
	size := object.Content.Size()
	if size < 12 || size > limit {
		scanner.Debug("Quarantine blob has unexpected size, skipped", "path", file.Path, "size", size)
		return
	}
	data := make([]byte, size)
	if _, err := object.Content.ReadAt(data, 0); err != nil && err != io.EOF {
		scanner.Error("Could not read quarantine blob", "path", file.Path, "error", err.Error())
		return
	}
	payload, err := decodePayload(data)
	if err != nil {
		scanner.Debug("Could not decode quarantine blob", "path", file.Path, "error", err.Error())
		return
	}
	// Scanned as a child of the quarantine file; unpack_parent = DEFENDER_QUARANTINE.
	scanner.ScanFile("payload.bin", payload, "DEFENDER_QUARANTINE")
}

// decodePayload RC4-decrypts the blob in place and strips the 0x28-byte header
// plus the metadata block whose length is stored at offset 8.
func decodePayload(enc []byte) ([]byte, error) {
	if len(enc) < 12 || enc[0] != 0x0B || enc[1] != 0xAD || enc[2] != 0x00 {
		return nil, fmt.Errorf("invalid quarantine header")
	}
	c, err := rc4.NewCipher(mseKey)
	if err != nil {
		return nil, err
	}
	c.XORKeyStream(enc, enc)
	headerLen := 0x28 + int(binary.LittleEndian.Uint32(enc[8:12]))
	if headerLen < 0x28 || headerLen > len(enc) {
		return nil, fmt.Errorf("corrupt header length %d", headerLen)
	}
	return enc[headerLen:], nil
}

// mseKey is the public 256-byte RC4 key used by Defender (from mpengine.dll),
// identical to the upstream plugin github.com/thor-plugins/defender-quarantine.
var mseKey = []byte{
	0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69,
	0x70, 0x2C, 0x0C, 0x78, 0xB7, 0x86, 0xA3, 0xF6, 0x23, 0xB7,
	0x38, 0xF5, 0xED, 0xF9, 0xAF, 0x83, 0x53, 0x0F, 0xB3, 0xFC,
	0x54, 0xFA, 0xA2, 0x1E, 0xB9, 0xCF, 0x13, 0x31, 0xFD, 0x0F,
	0x0D, 0xA9, 0x54, 0xF6, 0x87, 0xCB, 0x9E, 0x18, 0x27, 0x96,
	0x97, 0x90, 0x0E, 0x53, 0xFB, 0x31, 0x7C, 0x9C, 0xBC, 0xE4,
	0x8E, 0x23, 0xD0, 0x53, 0x71, 0xEC, 0xC1, 0x59, 0x51, 0xB8,
	0xF3, 0x64, 0x9D, 0x7C, 0xA3, 0x3E, 0xD6, 0x8D, 0xC9, 0x04,
	0x7E, 0x82, 0xC9, 0xBA, 0xAD, 0x97, 0x99, 0xD0, 0xD4, 0x58,
	0xCB, 0x84, 0x7C, 0xA9, 0xFF, 0xBE, 0x3C, 0x8A, 0x77, 0x52,
	0x33, 0x55, 0x7D, 0xDE, 0x13, 0xA8, 0xB1, 0x40, 0x87, 0xCC,
	0x1B, 0xC8, 0xF1, 0x0F, 0x6E, 0xCD, 0xD0, 0x83, 0xA9, 0x59,
	0xCF, 0xF8, 0x4A, 0x9D, 0x1D, 0x50, 0x75, 0x5E, 0x3E, 0x19,
	0x18, 0x18, 0xAF, 0x23, 0xE2, 0x29, 0x35, 0x58, 0x76, 0x6D,
	0x2C, 0x07, 0xE2, 0x57, 0x12, 0xB2, 0xCA, 0x0B, 0x53, 0x5E,
	0xD8, 0xF6, 0xC5, 0x6C, 0xE7, 0x3D, 0x24, 0xBD, 0xD0, 0x29,
	0x17, 0x71, 0x86, 0x1A, 0x54, 0xB4, 0xC2, 0x85, 0xA9, 0xA3,
	0xDB, 0x7A, 0xCA, 0x6D, 0x22, 0x4A, 0xEA, 0xCD, 0x62, 0x1D,
	0xB9, 0xF2, 0xA2, 0x2E, 0xD1, 0xE9, 0xE1, 0x1D, 0x75, 0xBE,
	0xD7, 0xDC, 0x0E, 0xCB, 0x0A, 0x8E, 0x68, 0xA2, 0xFF, 0x12,
	0x63, 0x40, 0x8D, 0xC8, 0x08, 0xDF, 0xFD, 0x16, 0x4B, 0x11,
	0x67, 0x74, 0xCD, 0x0B, 0x9B, 0x8D, 0x05, 0x41, 0x1E, 0xD6,
	0x26, 0x2E, 0x42, 0x9B, 0xA4, 0x95, 0x67, 0x6B, 0x83, 0x98,
	0xDB, 0x2F, 0x35, 0xD3, 0xC1, 0xB9, 0xCE, 0xD5, 0x26, 0x36,
	0xF2, 0x76, 0x5E, 0x1A, 0x95, 0xCB, 0x7C, 0xA4, 0xC3, 0xDD,
	0xAB, 0xDD, 0xBF, 0xF3, 0x82, 0x53,
}
```

## metadata.yml

```yaml
name: defender-quarantine
version: v0.2.0
author: Your Name
description: Decrypts Windows Defender quarantine files and scans the original payload
link: https://github.com/thor-plugins/defender-quarantine
requires_thor: v11.0.0-0
```

## Notes

- The meta rule checks the first bytes (`0B AD 00`) of every file; the hook additionally checks the path so random
  files with that header are ignored. Path comparison is lower-cased with `/` separators, so it also works on
  mounted images scanned from Linux.
- The upstream rule carries the `DEEPSCAN` tag; it is not needed and only makes THOR run generic YARA over the
  encrypted blob.
- `ReadAt` reads the whole blob without depending on the reader position; the size is capped by `MaxFileSize`
  (or 1 GiB when unlimited).
- The payload is scanned as `<quarantine file>/payload.bin` with `unpack_parent == "DEFENDER_QUARANTINE"`; YARA rules
  can use that to raise or lower scores for quarantined content.
- Quarantined files are already neutralized on disk: findings here mean "this was on the system", not "this is
  active". Triage accordingly.

## Package

```bash
zip -j defender-quarantine.zip plugin.go metadata.yml
```
Run on Windows (live) or on a mounted image (`--path` to the mounted volume, read-only).
