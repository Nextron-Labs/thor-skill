# Build and prerequisites (THOR Lens 0.7)

## Getting Lens

- The repository is private. Ask Nextron for a release archive or repository access; do not
  guess a public URL.
- Release archives (`thorlens_<version>_<os>_<arch>.tar.gz`, `.zip` on Windows) contain
  `thorlens`, `thorlens-agents`, `LICENSE`, `README.md`, `scenarios/`, `THIRD_PARTY_NOTICES.txt`,
  plus an SBOM and `SHA256SUMS`. Platforms: Linux amd64, Windows amd64, macOS arm64 (macOS 12+).
- Linux arm64 and Intel macOS: no archive; `make build` works there.

## Toolchain for source builds

| Requirement | Version | Why |
|---|---|---|
| Go | 1.26+ (`go.mod` pins toolchain go1.26.x; an older 1.26 downloads it) | backend |
| C compiler | gcc or clang; MinGW-w64 gcc on Windows | DuckDB and SQLite via cgo |
| Node.js | `^20.19.0` or `>=22.12.0` | Vite 8 frontend build |
| npm | bundled with that Node.js | frontend dependencies |
| Make | any recent | build targets (optional but used everywhere) |

Install hints: macOS `brew install go node` + `xcode-select --install`; Debian/Ubuntu
`apt install golang-go nodejs npm build-essential` (distribution Go/Node are often too old:
check `go version`, `node --version`, use upstream packages if needed); Windows: Go, Node.js
and MinGW-w64 gcc on `PATH`.

## Build

```bash
make build          # npm install + Vite build into internal/server/static/dist/ + go build -o thorlens
./thorlens --version
```

`internal/server/static/dist/` is git-ignored and embedded into the binary. A plain
`go build ./cmd/thorlens` or `go install` needs no Node.js, but that binary serves a page
saying it was built without its web interface (API and MCP work).

| Target | Effect |
|---|---|
| `make` / `make build` | frontend + `./thorlens` |
| `make build-frontend` | `npm install` + Vite build only |
| `make build-backend` | `./thorlens` with the last UI build (reports if the UI build is stale or missing) |
| `make build-agents` | `./thorlens-agents` (standalone scenario CLI) |
| `make build-release` | release archive for this platform into `dist/` (needs curl, jq) |
| `make rebuild` | frontend + backend again |
| `make serve [CASE=./cases/x] [PORT=…]` | run the server |
| `make import LOG_FILE=… CASE_NAME=…` | import one file |
| `make dev` / `make dev-frontend` | backend on :8080 for `./cases/demo` / Vite dev server on :5173 |
| `make test` / `make lint` | Go tests / frontend ESLint |
| `make clean` / `make clean-all` | remove build output / also `web/node_modules` |

## After rebuilding

The UI is embedded: a running `thorlens serve` keeps serving the old UI. Stop it, start the
new binary, hard-refresh the browser tab.

## CLI basics

- `thorlens [--debug] import|serve …`; `--version`; logs go to stderr.
- Exit codes: `0` success, `1` failure (one `Error: …` line on stderr), `2` usage error
  (unknown flag, missing value, bad combination).

## Build problems

| Error | Fix |
|---|---|
| `cgo: C compiler "gcc" not found` / DuckDB link errors | install gcc/clang (Windows: MinGW-w64 on PATH) |
| `go: go.mod requires go >= 1.26` | install Go 1.26+ or allow toolchain download (`GOTOOLCHAIN=auto`) |
| Vite/npm refuses the Node.js version | Node.js `^20.19.0` or `>=22.12.0` |
| npm `EACCES` | don't build with sudo; fix npm prefix permissions |
| frontend build broken after update | `make clean-all && make build` |
