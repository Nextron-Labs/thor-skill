# Packaging, deployment and release of THOR plugins

Read this when building the plugin ZIP, adding dependencies, deploying to many systems or automating releases.

## 1. ZIP layout

The ZIP root is the Go package root. THOR mounts it as package `main` and compiles every `.go` file at the root.

```
myplugin.zip
├── plugin.go          # package main, func Init(...)  (any file name)
├── helpers.go         # optional
├── metadata.yml       # optional
└── vendor/            # only if you use third-party modules
    └── modules.txt
```
- Wrong: `zip -r myplugin.zip myplugin/` (files end up in `myplugin/…` → "Could not compile plugin"). Zip from
  inside the folder or with `-j` for flat projects.
- Files with `//go:build` constraints are included only if the tags match; `build_tags` in `metadata.yml` adds tags.
  Sub-packages inside the ZIP are untested territory: keep everything in one package.

## 2. metadata.yml

```yaml
name: my-plugin                  # mandatory if the file exists; module name in THOR's log
version: v1.0.0
author: Your Name
description: What the plugin does
link: https://github.com/you/my-plugin
requires_thor: v11.0.0-0         # semver with v; -0 accepts 11.0.0 release candidates
build_tags:
  - myfeature
```
Decoded strictly: any other key (`license:`, `tags:`, `min_version:` …) fails with "could not parse metadata file".
Without `metadata.yml` the plugin loads with name = ZIP base name, version `<unversioned>`.

## 3. Dependencies

```bash
go mod tidy
go mod vendor
rm -rf vendor/github.com/NextronSystems/thor-plugin vendor/github.com/NextronSystems/jsonlog   # provided by THOR
```
- Only pure-Go packages work (no cgo, `unsafe`, `syscall`, assembly). Check with a test load (section 5).
- Standard-library-only plugins need no `vendor/` and no `go.mod` in the ZIP.

## 4. Build the ZIP

```bash
# flat project, stdlib only
zip -j my-plugin.zip *.go metadata.yml
# with vendor directory (run inside the project root)
zip -r my-plugin.zip . -i '*.go' -i 'metadata.yml' -i 'vendor/*'
unzip -l my-plugin.zip            # files must be at the root
```

Release automation as in the public template (https://github.com/thor-plugins/template): on a `vX.Y.Z` tag run
`go mod download && go mod vendor`, delete the two NextronSystems vendor folders, `zip -r plugin.zip .` with
`--include metadata.yml --include "*.go"` (add `vendor/*` if needed), attach `plugin.zip` to the GitHub release.
Lint with golangci-lint and `go vet` in CI.

## 5. Test load before deployment

```bash
cp my-plugin.zip /opt/thor/plugins/
cd /opt/thor && ./thor-linux-64 --module Filescan --path /tmp/plugintest --debug --no-thordb -e /tmp/thor-out \
  | grep -v -e LICENSE_OWNER -e 'License file found' -e 'Scan Information' | grep -i -e plugin -e my-plugin
```
Look for `Loaded plugin` (module `Plugin`) and your own Init message; errors are listed in the SKILL.md table.
During development use an unpacked folder `plugins/my-plugin/` and `--plugin-development-mode` (CLI flag only, not
settable in a config file).

## 6. Deployment

- Location: `<THOR program folder>/plugins/` (next to the binary, not the working directory). Each `.zip` (or
  Nextron-encrypted `.zips`) is one plugin; `README.md` there is ignored; other files cause an error line.
- Distribute the ZIP together with the THOR package (shares, software deployment, THOR Remote, ASGARD/Management
  Center packages: see the `thor-deployment` skill). Plugins need no license change and work in THOR Lite 11.
- Disable all plugins for a run with `--no-plugins` (e.g. to compare results or rule out a plugin problem).
- `thor-util upgrade/install` packages: plugin ZIPs shipped inside official packages are signature-checked by
  thor-util; your own ZIPs placed later are not checked by THOR at scan time. Protect the THOR folder against
  tampering: a planted plugin runs with THOR's privileges.
- THOR updates can change the plugin API in pre-releases. Re-test plugins after each THOR upgrade; pin
  `requires_thor` to the lowest version you tested.

## 7. Versioning

- Use semantic versions in `version:`; it is printed in the `Loaded plugin` line, which makes scan logs traceable.
- Keep `go.mod` pinned to the `thor-plugin`/`jsonlog` versions of the THOR build you target
  (`thor-plugin@732bd59e9da7` for THOR 11.0).
