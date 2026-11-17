# Example: THOR hunts with Velociraptor

Nextron publishes three client artifacts: https://github.com/NextronSystems/velociraptor-artifacts-thor
(background: Nextron blog "Integration of THOR in Velociraptor", Nov 2023).

| Artifact | For | How THOR gets to the client |
|---|---|---|
| `Generic.Scanner.Thor` | full THOR | downloads the THOR package for the client OS from the Nextron Portal with `PortalKey`; THOR fetches the host license with `--portal-key` (+ optional `PortalContractID`) |
| `Generic.Scanner.ThorZIP` | THOR Lite (or any prepared ZIP) | Velociraptor tool `ThorZIP`: your ZIP with binaries, license and signatures |
| `Generic.Scanner.ThorCloud` | THOR Cloud / Cloud Lite | downloads the campaign launcher with the campaign `Token`; results go to the Cloud console |

All support Windows, Linux and macOS clients and take a `CMDLine` parameter with extra THOR
flags. The Thor/ThorZIP artifacts upload `.txt`, `.html`, `.csv` and `.json` results to the
server and parse the alert/warning/notice/error counts from THOR's console output.

## Run a hunt

1. Import the artifact YAML (Server Artifacts → Add/Import, or `artifact_set()` in a notebook).
2. ThorZIP: upload your prepared, updated ZIP as tool `ThorZIP` (Server → Tools) instead of
   the placeholder URL.
3. Create a hunt on a label/OS-filtered set of clients; set **Max Execution Time** high
   (artifact authors suggest 30000 s ≈ 8.5 h); no extra resource limits (THOR throttles itself).
4. `CMDLine` examples: `--soft` (servers), `-c 50`, `--timestamp-utc` (v11) / `--utc` (v10),
   `--timeout 8` (v11) / `--max_runtime 8` (v10) so THOR ends before Velociraptor kills it.
5. Results: hunt notebook / flow *Results* (counts), uploaded files per client.

## Cautions

- `Generic.Scanner.Thor` sends the Portal API key to every client, including compromised
  ones. Use a contract download token rather than a personal API key and rotate it after the
  hunt.
- The published artifacts were written for THOR 10. Check them before using THOR 11
  packages: they pass `--json` without a value (in THOR 11 `--json` takes a file name and would
  consume the next argument), they upload only files ending in `json` (THOR 11 writes
  `.jsonl`), and on non-amd64 clients they pick the 32-bit names `thor.exe`/`thor-linux`, which
  THOR 11 no longer ships (ARM64 uses `thor64.exe`/`thor-linux-64`). Adapt the VQL (drop
  `--json`, upload `jsonl`) and test on one client first.
- `Generic.Scanner.ThorCloud` needs outbound HTTPS from clients to the THOR Cloud service.
- Uploaded results contain host data and license info; restrict access to the hunt.

## After the hunt

Download the uploaded logs (hunt → Download results) into one folder and triage as in
`references/collecting-results.md`, or import the JSON logs into THOR Lens
(`thorlens import --log-dir <dir> --case <hunt>`).
