# Forensic lab scanning: images, remapping, memory dumps, drop zone, collector

## License

Lab features need a lab-type license: **Forensic Lab**, **Incident Response** (Enterprise) or **Trial**; never THOR Lite.
Check it safely (redacting the owner) with the commands in the `thor` skill: v11 `--list-licenses --lab`;
v10 a tiny run, or try the flag on an empty folder and read "The current license type doesn't allow ...".
Never grep `.lic` files. An unbound Lab/Trial license asks for 3 digits at start (v11 refuses without a terminal).

## What `--lab` does

- Runs **only the Filescan module** (registry, eventlog, process, autoruns and other modules do not run as modules;
  hives, EVTX, logs and other artifacts found as files are still parsed by Filescan's features).
- Intense/deep intensity: every file deep-scanned, 200 MB file size limit unless set, built-in excludes off.
- All drives when no `-p` is given -> always pass `-p`.
- No ThorDB (no resume, no delta, no timing statistics), no resource control, no scan lock, all CPU cores
  (unless `--threads`), cross-platform filename IOC paths, unlimited match limit.
- v11 only: file references (symlink targets, paths found in artifacts) are followed only through `--path-remap`.
  Without a remap on a foreign file system THOR warns "Scanning a foreign file system, but no path remaps are configured".
- `--quick`/`--fast` and `-a` are ignored or narrowed; `--soft` is fatal in v11 and silently wins in v10.

## Path remapping

Syntax in both versions: `CURRENT:ORIGINAL` (split at the last colon; the original side must not contain a colon;
a single letter means a drive, `C` = `C:\`). Repeat the flag for several mounts.

| Situation | v10 | v11 |
|---|---|---|
| Image mounted as `S:` on Windows, was `C:` | `--virtual-map S:C` | `--path-remap S:C --target-os Windows` |
| Windows mount point folder | `--virtual-map D:\root:C` | `--path-remap D:\root:C --target-os Windows` |
| Windows image on Linux/macOS | `--virtual-map /mnt/img:C` | `--path-remap /mnt/img:C --target-os Windows` (**required**, else exit 1) |
| Linux image on Linux | `--virtual-map /mnt/img:/` | `--path-remap /mnt/img:/` (`--target-os Linux` optional on a Linux host) |
| dissect `target-mount` of a Windows image | n/a | `--path-remap /mnt/image/fs/sysvol/:C --target-os Windows -p /mnt/image/fs/sysvol/` |

`--target-os Windows|Linux|MacOS|AIX` (v11, any license) switches path separators for filename IOCs and YARA,
loads that OS's built-in heuristics and excludes, and confines references to remapped paths. Use it only with
`-p` and Filescan (lab mode); on a live host it can destabilise the system because only the target OS's excludes apply.
v10 has no target-OS concept: excludes and heuristics are those of the host OS; `--lab` adds cross-platform IOC paths.

Excludes (`--exclude-path` in v11, `directory-excludes.cfg` in v10) match the **local** mounted path (`/mnt/img/...`,
`S:\...`), not the remapped original path.

Hostname: `-j HOST` (`--overwrite-hostname`) puts the original host name into every line and into output file names.

## Canonical lab commands

```text
v10  thor64.exe --lab -p S:\ --virtual-map S:C -j WKS001 -e C:\cases\WKS001
v11  thor64.exe --lab -p S:\ --path-remap S:C --target-os Windows -j WKS001 -e C:\cases\WKS001

v10  ./thor-linux-64 --lab -p /mnt/wks001 --virtual-map /mnt/wks001:C -j WKS001 -e /cases/WKS001
v11  ./thor-linux-64 --lab -p /mnt/wks001 --path-remap /mnt/wks001:C --target-os Windows -j WKS001 -e /cases/WKS001

v10  ./thor-linux-64 --lab -p /mnt/srv01 --virtual-map /mnt/srv01:/ -j SRV01 -e /cases/SRV01
v11  ./thor-linux-64 --lab -p /mnt/srv01 --path-remap /mnt/srv01:/ --target-os Linux -j SRV01 -e /cases/SRV01
```

Add for forensic timelines: v11 `--audit-trail` (THOR Lens input; written to `-e`), v10 `--audit-trail /cases/WKS001/WKS001_audit.json.gz`
(absolute path; experimental format). Add `--utc`/`--timestamp-utc` when cases span time zones.

## Mounting (THOR does not mount images)

- Mount **read-only**. Windows: Arsenal Image Mounter (`aim_cli.exe` for automation), FTK Imager. Linux: `ewfmount` + loop mount with
  `mount -o ro,noload` (ext4) / `-o ro` (ntfs3) or `ntfs-3g -o ro`, `dissect` (`target-mount`). Use a write blocker for physical media.
- Mount each partition separately; scan each with its own remap and the same `-i SCANID` to group the results.
- v11 on Linux classifies FUSE mounts (ntfs-3g `fuseblk`, dissect `target-mount`, sshfs) as network file
  systems: with `--lab` that is fine (all drives); without lab, a single FUSE `-p` auto-enables `--all-drives`, which a
  Server/Workstation license refuses. v10 scans FUSE mounts on Linux without extra flags.
- v10 on macOS skips everything under `/Volumes/` unless `--alldrives` (lab sets it). v11 scans `/Volumes`.

## Without a lab license (lab-like scan)

Allowed with any license including Lite:

```text
v10  thor-linux-64 -a Filescan --intense --norescontrol --cross-platform --threads 0 --nothordb -p /mnt/img -e /cases/out
v11  thor-linux-64 --module Filescan --deep --cross-platform-paths --no-thordb -p /mnt/img -e /cases/out
```

v11 `--deep` already implies `--no-resource-check` and all cores; add `--target-os Windows` for a Windows image on
Linux (not license-gated). What you do not get: path remapping (findings show `/mnt/img/...` paths), hostname
override, all-drives, unlimited match limit, parallel instances. Both versions log
"Starting directory looks like a mounted disk image ..." for an OS root but still scan it.

## Memory dumps (DeepDive)

- v10 `-m FILE` (`--image_file`), v11 `--memory-dump-file FILE` (alias `-m`). One file per run. Lab-type license or
  `allowdeepdive` special; THOR Lite 10.7.30+ accepts it; THOR Lite 11 has no working DeepDive.
- Format-agnostic: raw memory, crash dumps (`.dmp`), LiME/AVML, pagefile. The file is read in overlapping chunks
  (default 12 MB, half overlap: 0-12, 6-18, ...; v10 `--image-chunk-size`, v11 `--memory-dump-chunk-size`), YARA only
  (built-in and custom YARA). All other modules and features are off: **no Sigma, no audit trail, no file names**.
  Findings carry chunk offsets (`CHUNK_OFFSET`, `CHUNK_END`, match offsets) for hex-editor follow-up.
- Restore matching executables/chunks: `-r DIR` (v11 `--memory-dump-extraction-directory`) with minimum score
  `--restore_score` / `--memory-dump-extraction-score` (default 50).
- Compressed formats (`hiberfil.sys`, compressed crash dumps) yield little: convert to raw first (Volatility 3 or similar).
- v11: do **not** add `--lab` (both modes deactivate each other's module). v10: `--lab` is unnecessary.

```text
v10  ./thor-linux-64 -m /cases/WKS001.mem -r /cases/WKS001/restored -j WKS001 -e /cases/WKS001
v11  ./thor-linux-64 --memory-dump-file /cases/WKS001.mem -r /cases/WKS001/restored -j WKS001 -e /cases/WKS001
```

Volatility route (file names and full Filescan instead of chunks): extract process memory, then scan the folder.
Volatility 3: `vol -f WKS001.mem -o /cases/procs windows.memmap --dump --pid <PID>` per process, or
`windows.dumpfiles`/`windows.dlllist --dump`; Volatility 2: `vol.py -f img --profile=<profile> memdump -D procs/`.
Then `--lab -p /cases/procs` (no lab: `-a Filescan --intense -p ...` / `--module Filescan --deep -p ...`).
Findings name the dump file (`pid.748.dmp`); keep the Volatility process list to map PIDs to process names.

Memory dump files found during a normal Filescan are analysed by the DumpScan feature (v10 `--dumpscan`,
v11 `--memory-dumps`; on by default in intense/deep).

## Drop zone

Scans every file dropped into a folder. Lab-type or Thunderstorm license (or `allowdropzone`).

| | v10 | v11 |
|---|---|---|
| Start | `--dropzone -p /srv/dropzone` | `--dropzone /srv/dropzone` |
| Delete after scan | `--dropdelete` | `--dropzone-purge` |
| Wait for writes | `--dropzone-delay 1` (seconds) | same |

Deletion flags remove the dropped files: never point a drop zone with deletion at evidence or a user folder.
Only Notice/Warning/Alert are printed after start; test with an EICAR file. Move files in (atomic) instead of
writing them slowly into the folder. No ThorDB, no HTML, no CSV.

## Artifact Collector

`--collector` (after the scan) or `--collector-only` collects artifacts into a ZIP: `--collector-output FILE.zip`
(a file path; default `:hostname:_collector.zip` / `<hostname>_collector.zip`). Preview with `--collector-dry-run`
(v11 `--collector-preview`); edit the config from `--collector-print-config` (v11 `--collector-config-preview`) and pass
`--collector-config FILE`. License: Incident Response (Enterprise) or the `deepforensic` special; a Forensic Lab
license alone is refused.

## Parallel lab scans

Several lab scans on one workstation: give each `--threads N` (e.g. 4 scans x `--threads 4` on 16 cores), its own
`-e` folder and `-j`. Memory grows with threads x file size limit. Lab mode already skips the scan lock.
