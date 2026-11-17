# Scanning appliances and unsupported systems over SSHFS

Use when THOR cannot run on the target (firewall, VPN gateway, NAS, ESXi-like or embedded systems, unusual
architecture) but SSH access exists. Alternatives first:

- Vendor-recommended for unsupported systems: THOR Thunderstorm with a collector that uploads files (see `thor-deployment`).
- Copy the relevant directories (`rsync -a`/`scp`) to the analysis host and scan the copy locally: faster and no
  network file system pitfalls.

## Rules

- Mount **read-only** and only the data directories you need (web roots, `/etc`, `/var/log`, `/tmp`, home and
  application folders). Never mount the remote `/` and scan it: `/proc`, `/sys` and `/dev` arrive as ordinary FUSE
  directories (pseudo-FS detection cannot see through FUSE), and lab/deep mode disables built-in excludes, so THOR reads
  endless or huge pseudo files such as `/proc/kcore`.
- If you must mount `/`, exclude pseudo file systems (v11): `--exclude-path "^/mnt/fw01/(proc|sys|dev|run)/"`.
  v10 has no CLI exclude: add the regex to `config/directory-excludes.cfg`.
- No process, registry, memory or live checks happen: only files are scanned.

## File system handling and licenses

| Host OS | THOR 10.7 | THOR 11 |
|---|---|---|
| Linux | FUSE mounts are scanned with any license | `fuse.sshfs` counts as a network FS: skipped unless all-drives. A single `-p` on it auto-enables `--all-drives`, which needs a lab-type or THOR Lite license (Server/Workstation licenses are refused) |
| macOS | sshfs skipped unless `--alldrives` (lab-type or Lite license) | same as Linux |

`--lab` sets all-drives in both versions.

## Mount

```bash
mkdir -p /mnt/fw01/www /mnt/fw01/etc
sshfs -o ro,reconnect,ServerAliveInterval=15 admin@fw01:/var/www /mnt/fw01/www
sshfs -o ro,reconnect,ServerAliveInterval=15 admin@fw01:/etc /mnt/fw01/etc
# via jump host: sshfs -o ro,ProxyJump=bastion admin@fw01:/var/www /mnt/fw01/www
```

## Scan with a lab-type license

```bash
# v10
./thor-linux-64 --lab -p /mnt/fw01/www -p /mnt/fw01/etc --virtual-map /mnt/fw01/www:/var/www --virtual-map /mnt/fw01/etc:/etc -j fw01 -e /cases/fw01
# v11
./thor-linux-64 --lab -p /mnt/fw01/www -p /mnt/fw01/etc --path-remap /mnt/fw01/www:/var/www --path-remap /mnt/fw01/etc:/etc --target-os Linux -j fw01 -e /cases/fw01
```

The remaps make findings show the appliance's real paths; `-j` sets its host name. Do not add `--quick`/`--fast`
(lab ignores it).

## Scan without a lab license

```bash
# v10 on Linux: works with any license (FUSE is scanned)
./thor-linux-64 -a Filescan -p /mnt/fw01/www -p /mnt/fw01/etc --nothordb -e /cases/fw01
# THOR Lite on Linux (v10 or v11)
./thor-lite-linux-64 -a Filescan -p /mnt/fw01/www -e /cases/fw01
```

With a Server/Workstation license on v11, copy the files locally and scan the copy instead.

## Unmount

```bash
fusermount -u /mnt/fw01/www   # Linux
umount /mnt/fw01/www          # macOS
```

## Performance

- SSHFS is slow for many small files: scan targeted directories, consider `-o cache=yes,kernel_cache,compression=no`
  on fast links, and prefer copying for large trees.
- Connection drops abort file reads: use `reconnect` and `ServerAliveInterval`.
- Archives (backups, WAR/JAR) on the appliance are read over the network in full: exclude large backup folders.
