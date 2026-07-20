
# `.agent/` — Agent Configuration

This directory governs agent behaviour for the `canary-scan` project. It contains four subdirectories:

| Path | Purpose |
|---|---|
| [`rules/`](./rules) | Hard constraints — always in effect. Violations are critical failures. |
| [`context/`](./context) | Project overview, architecture, and decision records. Read before making design changes. |
| [`workflows/`](./workflows) | Step-by-step procedures for setup, uv commands, and common tasks. |
| [`skills/`](./skills) | Optional skill modules — loaded on demand via the skill system. |

---

## Rules (always active)

Rules are non-negotiable. Read and obey at all times.

| Rule                    | File | Summary |
|-------------------------|---|---|
| `_dev/` off-limits      | [`dev-directory.md`](./rules/dev-directory.md) | Never read, write, or reference `_dev/`. Treat as invisible. |
| No local `.venv`        | [`environment.md`](./rules/environment.md) | venv at `${HOME}/.local/venvs/canary-scan`, cache at `/tmp/.uv-cache-canary-scan`, `UV_LINK_MODE=copy`. Use `make` targets (Makefile `UV` prefix). |
| Package age ≥ 14 days   | [`package-age.md`](./rules/package-age.md) | Never install packages <14 days old. `[tool.uv] exclude-newer = "14 days ago"` enforced in `pyproject.toml`. |

---

## Context (read before design changes)

Context files explain what the project is, how it is built, and why.

| File | Contains |
|---|---|
| [`context/architecture.md`](./context/architecture.md) | Stack, repo structure, data-flow phasing, core principles. |
| [`context/architecture-decisions.md`](./context/architecture-decisions.md) | Lightweight ADRs: Python 3.12+ (not 3.13), Typer CLI, JSONL output, read-only mount enforcement, bundled scripts, flock+audit trail, uv/hatchling/ruff, 12 file-type buckets, SARIF output. |
| [`context/development-phase.md`](./context/development-phase.md) | Pre-alpha constraints: breaking changes allowed, no backward compatibility, refactor aggressively, keep docs current. |

---

## Workflows (procedures)

| File | Use for |
|---|---|
| [`workflows/dev-setup.md`](./workflows/dev-setup.md) | First-time setup, re-syncing deps, common dev commands (test, lint, format, run). |
| [`workflows/uv-commands.md`](./workflows/uv-commands.md) | Correct uv invocation patterns and how the Makefile `UV` prefix enforces isolation. |

---

## Skills (load on demand)

Skills are invoked via the skill system. Load when task matches description.

| Skill | Trigger | Use for |
|---|---|---|
| [`caveman`](./skills/caveman/SKILL.md) | "caveman mode", "/caveman", "be brief", token efficiency | Ultra-compressed communication (lite / full / ultra / wenyan-* levels). Code/commits stay normal. |
| [`python-pro`](./skills/python-pro/SKILL.md) | Python dev, optimization, advanced patterns | Python 3.12+ modern features, uv, ruff, pydantic, Typer best practices. |
| [`python-patterns`](./skills/python-patterns/SKILL.md) | Framework selection, async, type hints, structure | Teaches Python decision-making thinking, not rote patterns. |
| [`architect-review`](./skills/architect-review/SKILL.md) | Architectural decisions, design review | Clean architecture, microservices, DDD, scalability, maintainability. |
| [`code-reviewer`](./skills/code-reviewer/SKILL.md) | Code quality assurance | AI-powered review, security, performance, production reliability. |
| [`docker-expert`](./skills/docker-expert/SKILL.md) | Dockerfile optimization, container issues | Multi-stage builds, image size, security hardening, Compose orchestration. |
| [`vulnerability-scanner`](./skills/vulnerability-scanner/SKILL.md) | Security analysis | OWASP 2025, supply chain, attack surface mapping, risk prioritization. Includes `checklists.md` + `scripts/security_scan.py`. |
| [`karpathy-guidelines`](./skills/karpathy-guidelines/SKILL.md) | Writing, reviewing, refactoring code | Behavioural guardrails: surgical changes, surface assumptions, verifiable success criteria. Reduces LLM coding mistakes. |

