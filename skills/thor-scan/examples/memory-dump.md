# Memory dump examples

Two approaches:

| Approach | What THOR does | When |
|---|---|---|
| DeepDive on the raw dump (`-m`) | Reads the whole file in overlapping 12 MB chunks, applies YARA (built-in + custom), extracts executables; reports offsets, no file or process names | Quick YARA sweep of a dump, unknown or unsupported formats |
| Volatility extraction + Filescan | Volatility writes per-process or per-file dumps; THOR scans the folder with all file features | You need process context; reports name the dump files |

License for `-m`: lab-type (Forensic Lab, Incident Response, Trial) or the `allowdeepdive` special. THOR Lite 10.7.30+
also accepts `-m`; THOR Lite 11 cannot scan dumps. `-j` needs a lab-type license (drop it otherwise).

## DeepDive on a raw memory image

```bash
# v10
./thor-linux-64 -m /cases/WKS001/memory.raw -j WKS001 -e /cases/WKS001/thor
# v11 (do NOT add --lab: it deactivates the DeepDive module)
./thor-linux-64 --memory-dump-file /cases/WKS001/memory.raw -j WKS001 -e /cases/WKS001/thor
```

```bat
v10: thor64.exe -m C:\cases\WKS001\memory.raw -j WKS001 -e C:\cases\WKS001\thor
v11: thor64.exe --memory-dump-file C:\cases\WKS001\memory.raw -j WKS001 -e C:\cases\WKS001\thor
```

- One file per run. All other modules and features are off: no Sigma, no audit trail, no filename IOCs.
- Findings carry `CHUNK_OFFSET`/`CHUNK_END` and match offsets for follow-up in a hex editor or Volatility.
- Smaller chunks reduce false positives across chunk borders but may miss larger patterns:
  v10 `--image-chunk-size 8MB`, v11 `--memory-dump-chunk-size 8MB`.

## Restore matching executables

```bash
# v10
./thor-linux-64 -m /cases/WKS001/memory.raw -r /cases/WKS001/restored --restore_score 60 -e /cases/WKS001/thor
# v11
./thor-linux-64 --memory-dump-file /cases/WKS001/memory.raw -r /cases/WKS001/restored --memory-dump-extraction-score 60 -e /cases/WKS001/thor
```

Writes executables/chunks whose findings reach the score (default 50). Treat restored files as live malware.

## Linux dumps (LiME, AVML)

```bash
./thor-linux-64 --memory-dump-file /cases/srv01/srv01.lime -j SRV01 -e /cases/srv01/thor   # v11 (v10: -m)
```

DeepDive is format-agnostic; it scans raw bytes. AVML snapshots may be compressed (`--compress`): decompress first
(`avml-convert`). The same applies to `hiberfil.sys` and compressed crash dumps: convert to raw before scanning.

## Volatility 3 extraction, then Filescan

```bash
vol -f /cases/WKS001/memory.raw windows.pslist > /cases/WKS001/pslist.txt      # keep for PID -> name mapping
vol -f /cases/WKS001/memory.raw -o /cases/WKS001/procs windows.memmap --dump --pid 748
vol -f /cases/WKS001/memory.raw -o /cases/WKS001/dlls windows.dlllist --dump
vol -f /cases/WKS001/memory.raw -o /cases/WKS001/files windows.dumpfiles

# lab
./thor-linux-64 --lab -p /cases/WKS001/procs -p /cases/WKS001/dlls -p /cases/WKS001/files -j WKS001 -e /cases/WKS001/thor
# no lab license
./thor-linux-64 -a Filescan --intense --nothordb -p /cases/WKS001/procs -e /cases/WKS001/thor        # v10
./thor-linux-64 --module Filescan --deep --no-thordb -p /cases/WKS001/procs -e /cases/WKS001/thor   # v11
```

Volatility 2 (end of life) equivalent: `vol.py -f memory.raw --profile=Win10x64_19041 memdump -D procs/`.
Findings name the dump files (`pid.748.dmp`); map PIDs with the saved process list.

## Dumps found during a normal scan

Memory and crash dumps on disk are analysed by the DumpScan feature during Filescan: on by default in
`--intense`/`--deep` and lab mode, otherwise v10 `--dumpscan`, v11 `--memory-dumps`.

## If it fails

- "doesn't allow image scanning": no lab-type license or `allowdeepdive` special.
- v11 scan ends immediately with no module running: `--lab` was combined with `--memory-dump-file`.
- No findings on a compressed dump: convert to raw first.
