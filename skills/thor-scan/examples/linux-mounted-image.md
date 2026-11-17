# Disk images on a Linux forensic workstation

Prerequisites: image mounted **read-only**, output on a separate disk, lab-type license (Forensic Lab, Incident Response
or Trial) for `--lab`, `-j` and remapping. An unbound Lab/Trial license asks for 3 digits at start.

## Mount read-only (examples)

```bash
# E01 -> raw via ewfmount, then the NTFS partition
sudo ewfmount /cases/WKS001.E01 /mnt/ewf
sudo mount -o ro,offset=$((2048*512)) /mnt/ewf/ewf1 /mnt/wks001        # ntfs3 or ntfs-3g
# Linux ext4 partition from a raw image (noload: don't replay the journal)
sudo mount -o ro,noload,offset=$((2048*512)) /cases/srv01.dd /mnt/srv01
```

Find partition offsets with `mmls` or `fdisk -l`.

## Windows image on Linux

```bash
# v10
sudo ./thor-linux-64 --lab -p /mnt/wks001 --virtual-map /mnt/wks001:C -j WKS001 -e /cases/WKS001/thor
# v11
sudo ./thor-linux-64 --lab -p /mnt/wks001 --path-remap /mnt/wks001:C --target-os Windows -j WKS001 -e /cases/WKS001/thor
```

- `--lab`: Filescan only, every file deep-scanned, all cores, no resource control, no ThorDB.
- Remap: findings show `C:\Windows\...` instead of `/mnt/wks001/Windows/...`.
- v11 requires `--target-os Windows` for a Windows-style original path on Linux (else exit 1); it also loads Windows
  heuristics and excludes.
- `-j`: original host name in every line and in file names.
- Do not add `--intense`, `--quick`, `--alldrives` or `-a`: lab already sets or overrides them.

## Linux image on Linux

```bash
# v10
sudo ./thor-linux-64 --lab -p /mnt/srv01 --virtual-map /mnt/srv01:/ -j SRV01 -e /cases/SRV01/thor
# v11
sudo ./thor-linux-64 --lab -p /mnt/srv01 --path-remap /mnt/srv01:/ --target-os Linux -j SRV01 -e /cases/SRV01/thor
```

## Several partitions of one image

```bash
# v11 (v10: --virtual-map instead of --path-remap --target-os Windows)
sudo ./thor-linux-64 --lab -p /mnt/p1 --path-remap /mnt/p1:C --target-os Windows -j WKS001 -i WKS001-IMG -e /cases/WKS001/p1
sudo ./thor-linux-64 --lab -p /mnt/p2 --path-remap /mnt/p2:D --target-os Windows -j WKS001 -i WKS001-IMG -e /cases/WKS001/p2
```

Same `-i` scan ID groups the results; separate output folders keep files apart.

## With forensic timeline output

```bash
# v10: text log by default, JSON and the experimental audit trail on request
sudo ./thor-linux-64 --lab -p /mnt/wks001 --virtual-map /mnt/wks001:C -j WKS001 -e /cases/WKS001/thor \
  --jsonfile=WKS001_thor.json --audit-trail /cases/WKS001/thor/WKS001_audit.json.gz --utc
# v11: JSONL by default; audit trail for THOR Lens
sudo ./thor-linux-64 --lab -p /mnt/wks001 --path-remap /mnt/wks001:C --target-os Windows -j WKS001 \
  -e /cases/WKS001/thor --audit-trail --timestamp-utc
```

## One subdirectory of the image

```bash
# v11 (remap the mount root, scan only a subfolder)
sudo ./thor-linux-64 --lab -p /mnt/wks001/Users/alice --path-remap /mnt/wks001:C --target-os Windows -j WKS001 -e /cases/WKS001/alice
```

## Parallel scans of several images (16 cores)

```bash
sudo ./thor-linux-64 --lab --threads 4 -p /mnt/img1 --path-remap /mnt/img1:C --target-os Windows -j HOST1 -e /cases/HOST1 &
sudo ./thor-linux-64 --lab --threads 4 -p /mnt/img2 --path-remap /mnt/img2:C --target-os Windows -j HOST2 -e /cases/HOST2 &
```

Lab mode skips the scan lock, so parallel instances are allowed. Unbound lab licenses need the 3-digit
challenge per instance: start them in separate terminals instead of `&`.

## Without a lab license (or THOR Lite)

```bash
# v10
sudo ./thor-linux-64 -a Filescan --intense --norescontrol --cross-platform --threads 0 --nothordb -p /mnt/wks001 -e /cases/WKS001/thor
# v11
sudo ./thor-linux-64 --module Filescan --deep --cross-platform-paths --target-os Windows --no-thordb -p /mnt/wks001 -e /cases/WKS001/thor
```

Paths stay as `/mnt/wks001/...` (no remap), the host name is the workstation's, and THOR logs
"Starting directory looks like a mounted disk image" but scans. v11: if the image is mounted through FUSE
(ntfs-3g, dissect), a single FUSE `-p` triggers the all-drives check, which a Server license refuses; mount with the
kernel `ntfs3` driver instead, or use a lab-type or Lite license.

## If it fails

- Finishes in seconds: v11 skipped a FUSE mount (see above); wrong `-p`; image not mounted.
- Exit 1 "doesn't allow lab mode scans / virtual mapping / setting the hostname": no lab-type license.
- v11 exit 1 about remapping style: add `--target-os Windows`.
- Many findings under unexpected paths: check the remap direction (`CURRENT:ORIGINAL`).
