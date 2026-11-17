# THOR Agent Skills

Agent skills for [THOR](https://www.nextron-systems.com/thor/), the compromise assessment scanner by Nextron Systems.
They help an AI agent build correct THOR command lines, triage findings, troubleshoot scans, maintain installations
with `thor-util`, write custom signatures and plugins, roll THOR out to many systems, and work with THOR Lens.

- Covers **THOR 10** (10.7.x) and **THOR 11**. Where flags or behaviour differ, both are given.
- Covers **full THOR** and **THOR Lite** (including THOR Cloud Lite).
- Follows the open [Agent Skills](https://agentskills.io) format, so the skills work in Claude Code, Hermes Agent and
  other agents that read `SKILL.md` folders. The repository is also a Claude Code plugin marketplace.

## Skills

| Skill | Use it when you want to … |
|-------|---------------------------|
| `thor` | Start here: identify the installation (version, edition, license) and route to the right skill; v10/v11 flag map |
| `thor-scan` | Get the right command for a live system, a folder, a mounted image, a memory dump or an SSHFS-mounted appliance |
| `thor-lite` | Use the free THOR Lite or THOR Cloud Lite, and know what it does and doesn't include |
| `thor-log-analysis` | Read and triage THOR output (text log, JSON, JSONL, HTML) from one or many systems |
| `thor-troubleshooting` | Fix scans that hang, crawl, stop early, produce nothing, or miss expected alerts |
| `thor-db` | Understand ThorDB (`thor10.db` / `thor.db`): location, resume, timing data |
| `thor-maintenance` | Update signatures, upgrade THOR, use YARA Forge, work offline, generate reports with `thor-util` |
| `thor-custom-signatures` | Write IOCs, YARA, Sigma (log and THOR 11 object rules), STIX and false-positive filters |
| `thor-plugins` | Write and package THOR 11 plugins |
| `thor-deployment` | Roll THOR out to many systems (shares, Ansible, GPO, Velociraptor, Management Center, THOR Cloud, Thunderstorm, SIEM) |
| `thor-lens` | Explore THOR 11 audit trails and JSON logs in THOR Lens, including its MCP server |

The Claude Code plugin also ships a `thor-log-analyst` subagent for bulk triage of log files.

## Installation

### Claude Code (plugin)

```
/plugin marketplace add NextronSystems/thor-skill
/plugin install thor-skills@nextron
```

Skills are then available as `/thor-skills:thor-scan` and so on, and load automatically when a request matches.
Update later with `/plugin marketplace update nextron`.

### Claude Code (without plugins)

Copy the skill folders into your personal skills directory. Each skill must be a direct child of it:

```bash
git clone https://github.com/NextronSystems/thor-skill.git
mkdir -p ~/.claude/skills
cp -R thor-skill/skills/* ~/.claude/skills/
```

If you installed an older version of this repository, remove its folders first (`~/.claude/skills/thor-skill/` and
older top-level `thor-*` folders): the old layout nested skills one level too deep, so most of them were never loaded.

### Hermes Agent

Clone the repository and add its `skills/` folder as an external skills directory in `~/.hermes/config.yaml`:

```yaml
skills:
  external_dirs:
    - ~/src/thor-skill/skills
```

### Other agents

Any agent that supports the Agent Skills format can use the folders under `skills/` as they are. Copy or link them
into that agent's skills directory. Each skill is self-contained; skills refer to each other by name only.

## What to expect

- The skills detect the THOR version and edition before suggesting commands, and ask if they can't tell.
- They never suggest full-system test scans, never print license owner lines from THOR output, and treat evidence as
  read-only.
- Helper scripts (`scripts/` in some skills) need Python 3.8+ or a POSIX shell and no extra packages.

## Requirements

- THOR 10.7 or THOR 11, full or Lite. Some features need THOR 11 (plugins, object-based Sigma rules, the audit trail
  for THOR Lens) or a lab-type license (Forensic Lab, Incident Response or Trial: `--lab`, path remapping,
  hostname override).
- The [THOR manual](https://thor-manual.nextron-systems.com) is the reference for everything the skills summarize.
