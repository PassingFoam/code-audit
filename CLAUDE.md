# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a **Claude Code skill** for professional white-box code security audits. When invoked, it performs systematic vulnerability discovery across 55+ vulnerability types in 9 languages with 143 mandatory detection items.

## Key Architecture: Dual-Track Audit Model

The skill uses three fundamentally different detection strategies depending on vulnerability type:

| Track | Dimensions | Method |
|-------|-----------|--------|
| **Sink-driven** | D1, D4, D5, D6 | Grep dangerous patterns → trace data flow → verify no defense |
| **Control-driven** | D3, D9 | Enumerate endpoints → verify security controls exist → **missing = vuln** |
| **Config-driven** | D2, D7, D8, D10 | Search configs → compare against security baseline |

**Critical insight**: D3/D9 vulnerabilities are "missing code", not "dangerous code" — Grep cannot find what doesn't exist. Control-driven audits must enumerate endpoints first.

## 10 Security Dimensions (D1-D10)

- **D1**: Injection (SQL/Cmd/LDAP/SSTI/SpEL/JNDI)
- **D2**: Authentication (Token/Session/JWT/Filter chain)
- **D3**: Authorization (CRUD permission consistency, IDOR)
- **D4**: Deserialization (Java/Python/PHP gadget chains)
- **D5**: File Operations (Upload/download/path traversal)
- **D6**: SSRF (URL injection, protocol restriction)
- **D7**: Cryptography (Key management, cipher modes, KDF)
- **D8**: Configuration (Actuator, CORS, error exposure)
- **D9**: Business Logic (Race conditions, mass assignment, state machine)
- **D10**: Supply Chain (Dependency CVEs, version checks)

## Execution Flow (from SKILL.md)

```
Step 1: 模式判定 → Determine mode (quick/standard/deep)
Step 2: 文档加载 → Load required documentation based on mode
Step 3: 侦察 → Tech stack identification, attack surface mapping
Step 4: 执行计划 → STOP and wait for user confirmation
Step 5: 执行 → Execute according to mode
Step 6: 报告门控 → Verify coverage before generating report
Step 7: 报告保存 → Save report to `.audit-reports/` directory (mandatory)
```

**Important**: Step 4 requires user confirmation before proceeding. Never skip this gate.

## Critical Files

| File | Purpose |
|------|---------|
| `SKILL.md` | Entry point with frontmatter + execution controller |
| `agent.md` | Agent workflow, state machine, dual-track methodology |
| `references/checklists/coverage_matrix.md` | D1-D10 coverage verification matrix |
| `references/core/phase2_deep_methodology.md` | Sink-driven/Control-driven/Config-driven execution details |
| `references/core/taint_analysis.md` | Data flow tracking with LSP support, Slot type classification |
| `references/core/anti_hallucination.md` | False positive prevention rules |
| `references/languages/*.md` | Language-specific vulnerability patterns |
| `references/frameworks/*.md` | Framework-specific detection patterns |

## Anti-Hallucination Rules (Mandatory)

```
1. Never guess file paths based on "typical project structure"
2. Never fabricate code snippets from memory
3. Always use Read/Glob to verify file exists before reporting
4. Code snippets must come from actual Read tool output
5. Better to miss a vulnerability than report a false positive
```

## Multi-Agent Workflow (Deep Mode)

For large projects, the skill spawns parallel agents:

```
Agent 1: Injection (D1) [sink-driven]
Agent 2: Auth + AuthZ + Business Logic (D2+D3+D9) [control-driven]
Agent 3: File + SSRF (D5+D6) [sink-driven]
Agent 4: Deserialization (D4) [sink-driven]
Agent 5: Config + Crypto + Supply Chain (D7+D8+D10) [config-driven]
```

Agent count scales with project size:
- Small (<10K lines): 2-3 agents
- Medium (10K-100K lines): 3-5 agents
- Large (>100K lines): 5-9 agents

## Slot Type Classification

Different sink positions require different protections. Key insight: **parameter binding only protects value positions, not identifiers**.

| Slot Type | Example | Correct Protection |
|-----------|---------|-------------------|
| SQL-val | `WHERE col = ?` | Parameter binding |
| SQL-ident | `ORDER BY ${col}` | **Whitelist only** (binding doesn't work) |
| CMD-argument | `cmd [arg]` | shell=False + array params |
| FILE-path | `new File(base + name)` | canonicalize + boundary check |

## WooYun Case Integration

The `references/wooyun/` directory contains real-world vulnerability patterns from 88,636 cases (2010-2016). These provide:
- Statistical-driven parameter priority
- Bypass techniques library
- Logic vulnerability patterns
- Real-case references for similar issues

## Coverage Verification

Before generating final report, verify:
- D1-D6 (Critical dimensions): Must all be covered
- D7-D8 (High dimensions): Strongly recommended
- D9 (Business Logic): Required if project has admin/multi-tenant/payment logic
- D10 (Supply Chain): Required if project has external dependencies

Coverage criteria:
- Sink-driven: Core sink categories searched + data flow traced + sink fanout rate ≥ 30%
- Control-driven: Endpoint audit rate ≥ 50% (deep) / ≥ 30% (standard)
- Config-driven: Core config items checked + versions compared to security baseline