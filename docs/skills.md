# Skills

A skill is a ready-made scan recipe. It is a folder with a `SKILL.md` file:

- the **front matter** (YAML at the top) says what the skill is, what inputs it takes, and a `workflow`
  of steps the scanner can run,
- the **body** is plain instructions that any agent or person can follow.

```text
src/skills/
  quick-scan/SKILL.md
  deep-audit/SKILL.md
  audit-client-configs/SKILL.md
  ci-gate/SKILL.md
```

## Using skills

```bash
mcp-scanner skills list
mcp-scanner skills show deep-audit
mcp-scanner skills run quick-scan --input target="python server.py"
mcp-scanner skills run deep-audit --input target="python server.py" --input source=./src --allow-host
mcp-scanner skills validate
```

Skills are found in the bundled skills, the repository `src/skills/` folder, `~/.aevrin-mcp-scanner/skills`,
`./skills`, and folders given with `--skills-dir`.

## Writing a skill

```markdown
---
name: my-check
description: Static scan with only the poisoning rules, as Markdown.
version: 1.0.0
inputs:
  target:
    description: What to scan.
    required: true
workflow:
  - name: Poisoning only
    action: scan
    with:
      target: "${inputs.target}"
      rules: [MCP-POISON, MCP-SHADOW, MCP-INJ]
      formats: [console, markdown]
      output: reports
---

# My check

Plain instructions for an agent or a person...
```

Actions and the options each one accepts:

| Action | Options |
|---|---|
| `scan` | `target`, `discover`, `server`, `dynamic`, `ai`, `ai_provider`, `ai_model`, `min_severity`, `fail_on`, `formats`, `output`, `rules`, `disable_rules`, `source`, `transport` |
| `inspect` | `target`, `server`, `transport` |
| `discover` | (none) |
| `report` | `formats`, `output` (renders the reports of earlier scan steps) |

`${inputs.NAME}` is replaced with an input value. A value that is only a placeholder keeps the input's type.

## Safety

Skills are data only:

- They cannot run their own code or shell commands.
- They can only use the four actions above, with the options listed. Anything else makes the skill invalid.
- They cannot turn on host execution (`--allow-host`) or dangerous tool calls. Only the person running the
  scanner can do that, on the command line.

`skills validate` checks: name format, folder name, front matter schema, known actions and options, declared
inputs, a `report` step only after a `scan` step, and that the instructions are not empty.
