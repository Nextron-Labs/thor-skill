# YARA examples for THOR

All rules below compile with `yara` 4.5.x (externals defined with `-d`) and were checked against sample data.
The **file name decides the rule type**: keep the tags in the names shown. Place files in
`custom-signatures/yara/` (THOR 11 requires it; THOR 10 accepts any subfolder).

## 1. Generic rules: `case2611.yar`

Run on deep-scanned files (and custom ones also on process memory). Default mode deep-scans only files picked by
DEEPSCAN rules; test with `--deep` (11) / `--intense` (10).

```yara
rule Case2611_Loader_Strings {
    meta:
        description = "Loader from case 2026-11 (strings in PE)"
        author = "Your Name"
        date = "2026-11-16"
        score = 80
    strings:
        $s1 = "malicious_export" ascii
        $s2 = "PAYLOAD_KEY" ascii wide
        $pdb = "\\Release\\implant.pdb" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2MB and (all of ($s*) or $pdb)
}

rule Case2611_Backdoor_Outside_Windows {
    meta:
        description = "Backdoor strings in an EXE outside the Windows folder"
        score = 90
    strings:
        $s1 = "beacon" ascii fullword
        $s2 = "PAYLOAD_KEY" ascii
    condition:
        filetype == "EXE" and filesize < 500KB and all of them
        and not filepath icontains "\\windows\\"
}
```
`filepath` is the directory without trailing backslash, so `icontains "\\windows\\"` also covers subfolders but not
files directly in `C:\Windows` (use `filepath icontains "\\windows"` if that matters).

## 2. Meta rules: `case2611-meta.yar`

Meta rules run on **every** file but see only the first 2048 bytes (v10) / 64 KB (v11) plus externals. Rules that
use only externals belong here; in a generic file they would only see deep-scanned files.

```yara
rule Case2611_DLL_In_User_Temp {
    meta:
        description = "DLL directly in a user's Temp folder"
        score = 60
    condition:
        extension == ".dll" and filepath matches /\\AppData\\Local\\Temp$/i
}

rule Case2611_EXE_Masquerading_As_Document {
    meta:
        description = "Executable with a document extension"
        score = 75
    condition:
        filetype == "EXE" and extension matches /^\.(doc|docx|pdf|txt|xlsx|jpg)$/
}

rule Case2611_Recent_EXE_In_ProgramData : DEEPSCAN {
    meta:
        description = "EXE created in the last 14 days directly below ProgramData (also selects it for deep scan)"
        score = 40
    condition:
        filetype == "EXE" and age < 14 and filepath matches /^[a-z]:\\programdata(\\[^\\]+)?$/i
}

rule Case2611_Select_Large_Archives : DEEPSCAN FORCE {
    meta:
        description = "Deep scan ISO/VHD containers even above the file size limit"
        score = 0
    condition:
        extension == ".iso" or extension == ".vhd" or extension == ".vhdx"
}

rule Case2611_EXE_From_Email_Archive {
    meta:
        description = "EXE extracted from an archive attached to an e-mail"
        score = 70
    condition:
        filetype == "EXE" and unpack_source matches /^EMAIL>(ZIP|RAR|7ZIP)/
}
```
- `DEEPSCAN` on a matching meta rule also sends the file through generic YARA, hash IOCs and STIX.
- `FORCE` lifts the file size limit (v10 30 MB, v11 64 MB) for that file: slow on large containers.
- `age` = days since creation (NaN when unknown, comparisons are then false).
- `unpack_source` chains look like `EMAIL>ZIP`; `unpack_parent` is the last step (`ZIP`).

## 3. False-positive rule: `fp-meta.yar`

```yara
rule FP_Vendor_Tool_Folder {
    meta:
        description = "Known-good admin tool folder"
        score = -60
    condition:
        filepath icontains "\\Program Files\\KnownGoodTool"
}
```
A negative score multiplies the remaining uncertainty: it pulls a single 60 down to 36 (below Notice), but cannot
lower an element that already has a 100 subscore. Do not combine `falsepositive = 1` with a negative score (they
cancel to a positive score). For noisy files prefer an exclude or `config/false_positive_filters.cfg`.

## 4. Registry rules: `case2611-registry.yar`

Data per key: one line per value, `KEYPATH;VALUENAME;VALUE`, no `HKLM`/`HKCU` prefix (REG_BINARY uppercase hex,
DWORD decimal). Keep regexes bounded and on one line (`[^\n]`), because registry data is bulk-scanned.

```yara
rule Case2611_RunKey_ScriptHost {
    meta:
        description = "Run key value starting a script host"
        score = 70
    strings:
        $run = "\\CurrentVersion\\Run" nocase
        $h1 = "powershell" nocase
        $h2 = "mshta" nocase
        $h3 = "wscript" nocase
    condition:
        $run and any of ($h*)
}

rule Case2611_Service_ImagePath_UserFolder {
    meta:
        description = "Service ImagePath in a user-writable folder"
        score = 70
    strings:
        $a = /\\Services\\[^;\n]{1,80};ImagePath;[^\n]{0,40}\\(Users\\Public|AppData|ProgramData)\\/ nocase
    condition:
        $a
}
```
Test locally against a text file containing such lines:
`SYSTEM\CurrentControlSet\Services\upd;ImagePath;C:\Users\Public\upd.exe`.

## 5. Log rules: `case2611-log.yar`

Text logs are scanned per line, event log entries as `Key1: Value1  Key2: Value2 …`.

```yara
rule Case2611_Log_PowerShell_Download {
    meta:
        description = "PowerShell download cradle in a log line or event"
        score = 70
    strings:
        $ps = "powershell" nocase
        $d1 = "downloadstring" nocase
        $d2 = "downloadfile" nocase
        $d3 = "invoke-webrequest" nocase
    condition:
        $ps and any of ($d*)
}
```

## 6. Keyword rule limited to one module: `case2611-keyword.yar`

Keyword rules see every non-file element as text. `limit` restricts reporting to one module (exact module name;
an unknown name silences the rule). A mutex IOC file (`case2611-mutexes.txt`) is the simpler alternative.

```yara
rule Case2611_Mutex_Name {
    meta:
        description = "Mutex of the case 2026-11 loader"
        score = 85
        limit = "Mutex"
    strings:
        $m1 = "LoaderMtx2026" ascii
    condition:
        $m1
}
```

## 7. Process memory rule: `case2611-process.yar`

`process`/`memory` in the file name restricts the rule to process memory, memory dumps and DeepDive chunks. Do not
use `type = "memory"` in the meta section: THOR ignores it. `nodeepdive = 1` excludes DeepDive/dump chunks.

```yara
rule Case2611_Beacon_In_Memory {
    meta:
        description = "Loader config marker in process memory"
        score = 85
        nodeepdive = 1
    strings:
        $c1 = "%s as %s\\%s: %d" ascii
        $c2 = "LoaderMtx2026" ascii wide
    condition:
        all of them
}
```

## 8. Check before deploying

```bash
yara -d filename=a.dll -d 'filepath=C:\Users\bob\AppData\Local\Temp' -d extension=.dll -d filetype=EXE \
     -d age=1.0 -d 'unpack_source=EMAIL>ZIP' case2611-meta.yar sample.bin
cp case2611*.yar fp-meta.yar /opt/thor/custom-signatures/yara/
./thor-linux-64 --list-signatures | grep -i case2611      # THOR 11 (THOR 10: --print-signatures)
```
Startup lines: `Adding rule set from case2611-meta.yar as 'meta' type`, `… case2611.yar as 'default' and 'custom'
type`, `… case2611-registry.yar as 'registry' type`. A compile error shows `Could not load yara signature file` and
the file is skipped.
