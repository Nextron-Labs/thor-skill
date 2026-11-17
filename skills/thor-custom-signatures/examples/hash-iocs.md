# Hash IOC examples

Folder: THOR 11 `custom-signatures/iocs/`; THOR 10 anywhere below `custom-signatures/` (use `iocs/` anyway, it
survives an upgrade). The file name must contain `hash`, `hashes` or `md5s` as a whole word.

## Basic file: `case2611-hashes.txt`

```text
# HASH;DESCRIPTION  (score 100)
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855;Dropper stage 1 (SHA256)
d41d8cd98f00b204e9800998ecf8427e;Main RAT payload (MD5)
da39a3ee5e6b4b0d3255bfef95601890afd80709;PsExec variant (SHA1)
```
(The values above are hashes of an empty file; replace them with real ones. An empty file is never reported.)

## Custom scores: `case2611-tiered-hashes.txt`

```text
# HASH;SCORE;DESCRIPTION
aabbccdd11223344556677889900aabb;100;Confirmed backdoor
11223344556677889900aabbccddeeff;80;Packer seen only in this campaign
ffeeddccbbaa99887766554433221100;50;Dual-use tool, review
```
Score 50 alone gives a Notice, 60-80 a Warning, 81+ an Alert (an Alert also needs one subscore >= 76, in both versions).

## Imphash: `cobaltstrike-imp-hash-iocs.txt`

```text
# Imphashes are 32 hex chars and share the hash table with MD5
d0583e7f5e56a9621b4fe9e4d65ab347;Loader imphash (case 2611)
```
Do **not** name it `imphash-iocs.txt`: `imphash` is not the word `hash`, the file would be ignored. THOR 10 checks
imphashes of EXE files (not with `--noimphash`); THOR 11 also checks RichHeaderHash.

## Trusted hashes: `our-trusted-hashes.txt`

```text
# Known-good internal tools
5d41402abc4b2a76b9719d911017c592;Internal deployment script
7d793037a0760186574b0282f2f435e7;Approved remote support tool
```
- Needs the hash tag **and** `trusted` or `falsepositive` (`falsepositive-hashes.txt` also works;
  `false-positive-hashes.txt` and `whitelist-hashes.txt` would load as malicious hashes).
- THOR 10 removes the whole file finding; THOR 11 adds -100, which forces the file's total score to 0.
- Only full 32/40/64-character hashes; shortened values (`abc123...`) are rejected.

## THOR 11 YAML alternative: `case2611.yml`

```yaml
title: Case 2611 hashes
iocs:
  hashes:
    - value:
        - e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        - d41d8cd98f00b204e9800998ecf8427e
      score: 100
    - value: 5d41402abc4b2a76b9719d911017c592
      score: -100
```
Always set `score` in YAML IOCs (omitted = 0 = no effect).

## Test

Hash IOCs only run on deep-scanned files. Copy a sample into a test folder and scan only that folder:
```bash
cp case2611-hashes.txt /opt/thor/custom-signatures/iocs/
# THOR 11
./thor-linux-64 --custom-signatures-only --module Filescan --path /tmp/sigtest --deep --no-thordb -e /tmp/thor-out \
  | grep -v -e LICENSE_OWNER -e 'License file found' -e 'Scan Information'
# THOR 10
./thor-linux-64 --customonly -a Filescan -p /tmp/sigtest --intense --nothordb -e /tmp/thor-out \
  | grep -v -e LICENSE_OWNER -e 'License file found' -e 'Scan Information'
```
Expect `Reading iocs from …case2611-hashes.txt as 'hash' type` (trusted file: `as false positive 'hash' type`) and
`Successfully compiled N malware and M false positive hashes`.
