# 🛡 Automated Threat Modeler

> AI-powered threat modeling for engineering teams — STRIDE, DREAD, LINDDUN, PASTA, and OWASP Top 10 in one tool.

![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green?style=flat-square)
![Claude AI](https://img.shields.io/badge/Claude-Sonnet%204.6-purple?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-gray?style=flat-square)

---

## What it does

Automated Threat Modeler (ATM) takes a system description, components, data flows, and trust boundaries and runs them through one or more threat modeling frameworks to produce a prioritised list of threats, mitigations, CVSS 3.1 + 4.0 scores, MITRE ATT&CK mappings, and compliance control IDs — in seconds.

**Input methods**
- 📝 Plain-English text description — Claude extracts components for you
- 🖼️ Architecture diagram upload — Claude Vision reads PNG/JPG/WebP diagrams
- 🔧 Manual component builder with interactive, draggable DFD canvas
- 📐 Built-in system templates (SaaS, Mobile + API, Microservices, Data Pipeline, IoT)
- ⚙️ Custom threat rules — define your own threats that run alongside built-in analysis

**Output**
- Deduplicated, prioritised threat list (across all selected frameworks)
- CVSS 3.1 + CVSS 4.0 scores, CWE IDs, MITRE ATT&CK technique + tactic
- SOC2 / ISO 27001 / PCI-DSS compliance control mapping per threat
- Interactive 5×5 risk matrix (Likelihood × Impact)
- Attack path visualiser — top multi-hop chains across trust boundaries
- Risk register CSV export
- Claude-narrated executive HTML/PDF report
- Per-threat remediation tracking (status, owner, due date, version history)
- AI-generated before/after code fix per threat
- Shareable read-only report URLs

---

## Quick start

```bash
# 1. Clone
git clone https://github.com/rootabhi1/Automated-Threat-Modelling
cd Automated-Threat-Modelling/threat-modeler

# 2. Configure
cp .env.example .env
# Set ANTHROPIC_API_KEY for AI-enhanced analysis (optional but recommended)

# 3. Run
docker compose up
# or: pip install -r requirements.txt && python app.py

# 4. Open
open http://localhost:8000
```

---

## Methodologies

| Framework | Categories | Description |
|-----------|-----------|-------------|
| **STRIDE** | 6 | Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation of Privilege |
| **DREAD** | 5 dimensions | Damage, Reproducibility, Exploitability, Affected users, Discoverability |
| **LINDDUN** | 7 | Privacy: Linkability, Identifiability, Non-repudiation, Detectability, Disclosure, Unawareness, Non-compliance |
| **PASTA** | 7 stages | Process for Attack Simulation and Threat Analysis |
| **OWASP Top 10** | 10 (A01–A10) | Web application risks: Broken Access Control, Injection, Crypto Failures, SSRF, and more |

---

## Features

### Analysis engine
- **Threat deduplication** — running multiple frameworks no longer produces duplicate cards; highest severity is kept and mitigations are merged
- **MITRE ATT&CK mapping** — every threat includes `attack.id` (e.g. T1190), `attack.tactic`, and a link to attack.mitre.org
- **CVSS 3.1 + CVSS 4.0** — both scores computed and displayed per threat
- **SOC2 / ISO 27001 / PCI-DSS** — compliance control IDs mapped from CWE per threat
- **Custom threat rules** — define domain-specific threats in the UI; they persist to DB and run alongside built-in analysis
- **Claude Vision diagram upload** — drop an architecture diagram; Claude extracts components, flows, and trust boundaries
- **Interactive DFD canvas** — zoom, mini-map, node tooltips, flow hover popups
- **5 built-in system templates** — load in one click, edit before analyzing

### Results & reporting
- **Risk matrix** — 5×5 Likelihood × Impact grid, click cells to drill in
- **Attack path visualiser** — top 5 multi-hop attack chains, ordered by Critical count
- **ATT&CK badges** — clickable on every threat card, link to MITRE ATT&CK
- **Compliance section** — SOC2/ISO/PCI control IDs shown per expanded threat
- **AI code fix** — 🔧 Fix button generates a before/after code snippet in your stack using Claude
- **Risk register CSV** — compliance-ready export with CVSS, DREAD, ATT&CK, compliance controls
- **Executive report** — Claude writes the narrative (Executive Summary, Top Risks, Actions); download as HTML or PDF

### Remediation & collaboration
- **Per-threat tracking** — status (Open/In progress/Mitigated/Accepted/False positive), owner, due date
- **Bulk status update** — select all Low/Info and mark as accepted in one click
- **Version history** — full audit trail of status changes with time-to-closure
- **Share link** — generate a 7-day read-only URL for stakeholders (no login required)
- **Release comparison diff** — compare two saved models: new, resolved, changed-severity threats + surface delta
- **GitHub Issues / Jira export** — push individual threats as tickets
- **Slack / email notifications** — alert when new Critical/High threats appear after re-analysis

### Developer experience
- **Keyboard shortcuts** — `n` add component · `f` add flow · `b` add boundary · `a` auto-layout · `Ctrl+S` save · `?` help
- **Dark / light mode** — toggle in the header, preference saved to localStorage
- **Mobile-responsive** — stacked layout, touch-friendly DFD nodes, responsive filters
- **GitHub Actions CI/CD** — fail the build when threats exceed a severity threshold
- **Structured JSON logging** — all requests logged with correlation IDs (`X-Request-ID`)
- **Health / readiness endpoints** — `/healthz` and `/readyz` for load balancers and Kubernetes
- **PostgreSQL support** — set `DATABASE_URL` to switch from SQLite (falls back gracefully)

---

## Architecture

```
Browser
  ├── app.js                 (DFD builder, analysis UI — core, unchanged)
  ├── enhancements.js        (templates, remediation, risk matrix, attack paths,
  │                           exec report, tickets, dark mode, keyboard shortcuts,
  │                           bulk status, share link, ATT&CK badges, compliance,
  │                           AI fix button, custom rules UI)
  ├── mobile.css             (responsive overrides + dark mode variables)
  └── templates.json         (5 built-in system templates)

FastAPI (app.py — 1285 lines)
  ├── /api/analyze                   → run threat model (dedup + custom rules + notify)
  ├── /api/extract-from-text         → parse description → components
  ├── /api/extract-from-diagram      → Claude Vision → components
  ├── /api/infer-trust-boundaries    → auto-detect trust zones
  ├── /api/templates                 → built-in system templates
  ├── /api/custom-rules              → CRUD for user-defined threat rules
  ├── /api/threat-status             → per-threat remediation tracking
  ├── /api/threat-status/bulk        → bulk status update
  ├── /api/share/:id                 → generate read-only share link
  ├── /share/:token                  → serve shared report (no auth)
  ├── /api/releases/:a/diff/:b       → compare two saved threat models
  ├── /api/threat/fix                → AI before/after code fix (Claude)
  ├── /api/report/csv                → risk register CSV export
  ├── /api/report/executive          → Claude-narrated PDF/HTML
  ├── /api/create-ticket             → GitHub Issues / Jira
  ├── /healthz                       → liveness probe
  └── /readyz                        → readiness probe (DB ping)

Middleware (app.py)
  ├── SecurityHeadersMiddleware      → X-Content-Type-Options, X-Frame-Options, HSTS …
  ├── RateLimitMiddleware            → 10 req/min on /auth/login, 5/min on /auth/register
  └── RequestIDMiddleware            → X-Request-ID correlation, JSON structured logging

Threat Engine
  ├── methodologies.py    (STRIDE / DREAD / LINDDUN / PASTA / OWASP Top 10)
  ├── analyzer.py         (core analysis + E1 deduplication)
  ├── scoring.py          (CVSS 3.1 + 4.0 + E2 ATT&CK map + P3 compliance map)
  ├── dfd.py
  ├── diagram_extractor.py
  ├── ticket_export.py
  ├── notifications.py
  └── executive_report.py

Database (SQLite / PostgreSQL via DATABASE_URL)
  ├── threat_models, components, data_flows, trust_boundaries
  ├── threat_status   (+owner, +due_date columns)
  ├── custom_threat_rules
  ├── share_tokens
  └── teams, team_members, team_projects, team_invites  (multi-tenancy schema)

CLI / DevOps
  ├── cli/atm_cli.py
  ├── .github/workflows/threat-model.yml  (CI + pip-audit CVE scan)
  ├── .github/dependabot.yml              (weekly pip + Actions updates)
  └── system.json                          (example system definition)
```

---

## CI/CD Integration

```bash
# Analyze and fail if any High+ threats exist
python threat-modeler/cli/atm_cli.py analyze \
  --system-file system.json \
  --frameworks stride,dread,owasp \
  --threshold high \
  --output-md summary.md
# Exit 0 = pass · 1 = violations · 2 = error
```

| Repo variable | Default | Description |
|---------------|---------|-------------|
| `ATM_THRESHOLD` | `high` | `info` / `low` / `medium` / `high` / `critical` |
| `ATM_FRAMEWORKS` | `stride` | `stride,dread,linddun,pasta,owasp` |

---

## Integrations setup

### Slack notifications
```bash
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
NOTIFY_THRESHOLD=high   # critical | high | all
```

### Email alerts
```bash
SMTP_HOST=smtp.sendgrid.net  SMTP_PORT=587
SMTP_USER=apikey             SMTP_PASS=SG.xxx
NOTIFY_EMAIL_FROM=atm@yourcompany.com
NOTIFY_EMAIL_TO=security@yourcompany.com
```

### GitHub Issues
```bash
GITHUB_TOKEN=ghp_xxx   GITHUB_REPO=owner/repo
```

### Jira
```bash
JIRA_BASE_URL=https://yourcompany.atlassian.net
JIRA_EMAIL=you@yourcompany.com
JIRA_API_TOKEN=xxx   JIRA_PROJECT_KEY=SEC
```

### PostgreSQL (production)
```bash
DATABASE_URL=postgresql://user:pass@localhost:5432/atm
# Add psycopg2-binary to requirements.txt
```

---

## Complete API reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/login` | — | Get JWT token |
| POST | `/api/analyze` | ✓ | Run threat model |
| POST | `/api/extract-from-text` | ✓ | Text → components |
| POST | `/api/extract-from-diagram` | ✓ | Claude Vision → components |
| POST | `/api/infer-trust-boundaries` | ✓ | Auto-detect trust zones |
| GET  | `/api/templates` | ✓ | List built-in templates |
| POST | `/api/custom-rules` | ✓ | Create custom threat rule |
| GET  | `/api/custom-rules` | ✓ | List user's custom rules |
| PUT  | `/api/custom-rules/:id` | ✓ | Update custom rule |
| DELETE | `/api/custom-rules/:id` | ✓ | Delete custom rule |
| POST | `/api/threat-status` | ✓ | Set remediation status |
| GET  | `/api/threat-status/:id` | ✓ | List all statuses for a model |
| POST | `/api/threat-status/bulk` | ✓ | Bulk update multiple statuses |
| GET  | `/api/threat-status/:id/:tid/history` | ✓ | Status change history |
| POST | `/api/share/:id` | ✓ | Generate 7-day share link |
| GET  | `/share/:token` | — | View shared report (no auth) |
| GET  | `/api/releases/:a/diff/:b` | ✓ | Compare two saved models |
| POST | `/api/threat/fix` | ✓ | AI before/after code fix |
| POST | `/api/report/csv` | ✓ | Risk register CSV |
| POST | `/api/report/executive` | ✓ | Executive HTML/PDF report |
| POST | `/api/create-ticket` | ✓ | Create GitHub Issue or Jira ticket |
| GET  | `/healthz` | — | Liveness probe |
| GET  | `/readyz` | — | Readiness probe (DB ping) |

---

## Running tests

```bash
cd threat-modeler
pytest tests/ -v

# Test classes:
# TestTemplates            · TestDiagramExtraction  · TestThreatStatus
# TestCSVExport            · TestSecurityHeaders    · TestRateLimiting
```

---

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | **Yes** | JWT signing secret |
| `ANTHROPIC_API_KEY` | Optional | Claude Vision, LLM threats, exec report, AI fix |
| `DATABASE_URL` | Optional | PostgreSQL connection string; SQLite used if absent |
| `SLACK_WEBHOOK_URL` | Optional | Slack alerts for new threats |
| `SMTP_HOST/PORT/USER/PASS` | Optional | Email alert credentials |
| `NOTIFY_EMAIL_FROM/TO` | Optional | Sender/recipient for email alerts |
| `NOTIFY_THRESHOLD` | Optional | `critical` / `high` (default) / `all` |
| `GITHUB_TOKEN` | Optional | GitHub Issues ticket export |
| `GITHUB_REPO` | Optional | `owner/repo` for Issues |
| `JIRA_BASE_URL/EMAIL/API_TOKEN/PROJECT_KEY` | Optional | Jira integration |

---

## Project structure

```
threat-modeler/
├── app.py                          # FastAPI app + all 22 API routes (1285 lines)
├── requirements.txt
├── Dockerfile                      # with HEALTHCHECK directive
├── docker-compose.yml
├── system.json                     # Example system for CLI
│
├── threat_engine/
│   ├── methodologies.py            # STRIDE · DREAD · LINDDUN · PASTA · OWASP Top 10
│   ├── analyzer.py                 # Core engine + E1 deduplication
│   ├── scoring.py                  # CVSS 3.1+4.0 · ATT&CK map · compliance map
│   ├── dfd.py
│   ├── diagram_extractor.py        # Claude Vision
│   ├── ticket_export.py            # GitHub Issues + Jira
│   ├── notifications.py            # Slack + SMTP
│   └── executive_report.py        # Claude-narrated PDF/HTML
│
├── db/
│   ├── __init__.py                 # Schema (incl. teams + custom_rules + share_tokens + PG support)
│   └── domain.py                   # All DB query functions + custom rule CRUD
│
├── cli/
│   └── atm_cli.py                  # CI/CD command-line tool
│
├── static/
│   ├── js/
│   │   ├── app.js                  # Core DFD builder (unchanged)
│   │   └── enhancements.js        # All additive features (~750 lines)
│   ├── css/
│   │   ├── app.css
│   │   └── mobile.css             # Mobile responsive + dark mode
│   └── templates.json             # 5 built-in system templates
│
├── templates/
│   └── index.html                  # 4-tab UI (text/diagram/builder/custom rules)
│
├── tests/
│   └── test_new_endpoints.py
│
└── .github/
    ├── dependabot.yml              # Weekly pip + Actions updates
    └── workflows/
        └── threat-model.yml       # CI: analyze + pip-audit + PR comment
```

---

## Keyboard shortcuts

| Key | Action |
|-----|--------|
| `n` | Add component |
| `f` | Add data flow |
| `b` | Add trust boundary |
| `a` | Auto-layout DFD |
| `Ctrl+S` | Save project |
| `?` | Show shortcuts overlay |
| `Esc` | Close modal |

---

## Screenshots

| Dashboard | New Model | Threat Analysis |
|-----------|-----------|-----------------|
| ![Dashboard](docs/screenshots/atm_dashboard.png) | ![New Model](docs/screenshots/atm_newmodel.png) | ![Threats](docs/screenshots/atm_threats.png) |

---

## Roadmap

- [ ] Multi-tenancy UI — team creation, member invites, shared projects
- [ ] MITRE ATT&CK filter in results (group by tactic)
- [ ] SOC2 "compliance view" — group threats by control instead of severity
- [ ] Webhook outbox for Zapier/n8n integrations
- [ ] VS Code extension
- [ ] OWASP SAMM maturity scoring

---

## License

MIT © rootabhi1
