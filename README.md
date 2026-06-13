# 🛡 Automated Threat Modeler

> AI-powered threat modeling for engineering teams — STRIDE, DREAD, LINDDUN, and PASTA in one tool.

![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green?style=flat-square)
![Claude AI](https://img.shields.io/badge/Claude-Sonnet%204.6-purple?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-gray?style=flat-square)

---

## What it does

Automated Threat Modeler (ATM) takes a system description, a set of components, data flows, and trust boundaries and runs them through one or more threat modeling frameworks to produce a prioritized list of threats, mitigations, and a risk score — in seconds.

**Input methods**
- 📝 Plain-English text description — Claude extracts the components for you
- 🖼️ Architecture diagram upload — Claude Vision reads your PNG/JPG/WebP diagram
- 🔧 Manual component builder with an interactive, draggable DFD canvas
- 📐 Built-in system templates (SaaS, Mobile + API, Microservices, Data Pipeline, IoT)

**Output**
- Prioritized threat list with severity, CVSS 3.1, DREAD, CWE, and mitigations
- Interactive 5×5 risk matrix (Likelihood × Impact)
- Attack path visualizer — top multi-hop chains across trust boundaries
- Risk register CSV export
- Claude-narrated executive HTML/PDF report
- Per-threat remediation tracking (status, owner, due date)
- Version history / audit trail

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

## Features

### Core threat modeling
| Framework | Categories | Description |
|-----------|-----------|-------------|
| **STRIDE** | 6 | Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation of Privilege |
| **DREAD** | 5 dimensions | Damage, Reproducibility, Exploitability, Affected users, Discoverability |
| **LINDDUN** | 7 | Privacy-focused: Linkability, Identifiability, Non-repudiation, Detectability, Disclosure, Unawareness, Non-compliance |
| **PASTA** | 7 stages | Process for Attack Simulation and Threat Analysis |

### Analysis features
- **Claude Vision diagram upload** — drop an architecture diagram; Claude extracts components, flows, and trust boundaries automatically
- **Interactive DFD canvas** — drag nodes, zoom (+ / − / scroll wheel), mini-map, node tooltips showing threat counts
- **Risk matrix** — 5×5 Likelihood × Impact grid, click cells to drill into threats
- **Attack path visualizer** — top 5 multi-hop attack chains, ordered by Critical count
- **System templates** — 5 ready-to-analyze templates loaded in one click

### Remediation & reporting
- **Per-threat tracking** — status, owner, due date, persisted to DB
- **Version history** — full audit trail of status changes with time-to-closure
- **Risk register CSV** — compliance-ready export with CVSS, DREAD, all metadata
- **Executive report** — Claude writes the narrative (Executive Summary, Top Risks, Recommended Actions); download as HTML or PDF
- **GitHub Issues / Jira export** — push individual threats as tickets with severity-mapped priority

### Integrations
- **Slack notifications** — POST to a webhook when new Critical/High threats appear after re-analysis
- **Email alerts** — HTML digest via SMTP / SendGrid
- **GitHub Actions CI/CD** — fail the build when threats exceed a severity threshold

### Security
- Security headers on every response (X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, HSTS, Referrer-Policy)
- Rate limiting on auth endpoints (10 req/min on login, 5/min on register)
- JWT authentication on all API endpoints

---

## Architecture

```
Browser
  ├── app.js              (DFD builder, analysis UI — unchanged core)
  ├── enhancements.js     (templates, remediation, risk matrix, attack paths, exec report, tickets)
  ├── mobile.css          (responsive overrides for small screens)
  └── templates.json      (5 built-in system templates)

FastAPI (app.py)
  ├── /api/analyze                 → run threat model
  ├── /api/extract-from-text       → parse description → components
  ├── /api/extract-from-diagram    → Claude Vision → components  [NEW]
  ├── /api/infer-trust-boundaries  → auto-detect trust zones
  ├── /api/threat-status           → per-threat remediation tracking [NEW]
  ├── /api/report/csv              → risk register CSV export [NEW]
  ├── /api/report/executive        → Claude-narrated PDF/HTML [NEW]
  ├── /api/templates               → built-in system templates [NEW]
  └── /api/create-ticket           → GitHub Issues / Jira [NEW]

Threat Engine
  ├── methodologies.py     (STRIDE / DREAD / LINDDUN / PASTA)
  ├── analyzer.py
  ├── dfd.py
  ├── diagram_extractor.py (Claude Vision — NEW)
  ├── ticket_export.py     (GitHub + Jira — NEW)
  ├── notifications.py     (Slack + SMTP — NEW)
  └── executive_report.py  (Claude narrative + WeasyPrint PDF — NEW)

CLI / DevOps
  ├── cli/atm_cli.py                        (CI/CD wrapper — NEW)
  ├── .github/workflows/threat-model.yml    (GitHub Actions — NEW)
  └── system.json                            (example system definition)

Database (SQLite)
  ├── threat_models, components, data_flows, trust_boundaries
  ├── threat_status (+owner, +due_date columns)
  └── teams, team_members, team_projects, team_invites  [NEW — multi-tenancy]
```

---

## CI/CD Integration

ATM ships with a CLI and a GitHub Actions workflow for running threat analysis on every PR.

**Setup**
1. Add `ANTHROPIC_API_KEY` to repository secrets (optional — rules-based analysis works without it)
2. Commit a `system.json` to your repo root (see `system.json` for an example)
3. The workflow runs automatically on PRs and posts a Markdown summary as a PR comment

**Manual CLI usage**
```bash
# Analyze and fail if any High+ threats exist
python threat-modeler/cli/atm_cli.py analyze \
  --system-file system.json \
  --frameworks stride,dread \
  --threshold high \
  --output-md summary.md

# Exit codes: 0 = pass, 1 = threshold violations, 2 = error
```

**Configure via repo variables**
| Variable | Default | Description |
|----------|---------|-------------|
| `ATM_THRESHOLD` | `high` | Severity threshold: `info`, `low`, `medium`, `high`, `critical` |
| `ATM_FRAMEWORKS` | `stride` | Comma-separated: `stride,dread,linddun,pasta` |

---

## Integrations setup

### Slack notifications
```bash
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
NOTIFY_THRESHOLD=high   # critical | high | all
```

### Email alerts
```bash
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASS=SG.xxx
NOTIFY_EMAIL_FROM=atm@yourcompany.com
NOTIFY_EMAIL_TO=security@yourcompany.com,eng-lead@yourcompany.com
```

### GitHub Issues
```bash
GITHUB_TOKEN=ghp_xxx
GITHUB_REPO=owner/repo
```

### Jira
```bash
JIRA_BASE_URL=https://yourcompany.atlassian.net
JIRA_EMAIL=you@yourcompany.com
JIRA_API_TOKEN=xxx
JIRA_PROJECT_KEY=SEC
```

---

## API reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/login` | — | Get JWT token |
| POST | `/api/analyze` | ✓ | Run threat model |
| POST | `/api/extract-from-text` | ✓ | Text → components |
| POST | `/api/extract-from-diagram` | ✓ | Image → components (Claude Vision) |
| POST | `/api/infer-trust-boundaries` | ✓ | Auto-detect trust zones |
| GET  | `/api/templates` | ✓ | List built-in templates |
| POST | `/api/threat-status` | ✓ | Set threat remediation status |
| GET  | `/api/threat-status/{id}` | ✓ | List all statuses for a model |
| POST | `/api/report/csv` | ✓ | Download risk register CSV |
| POST | `/api/report/executive` | ✓ | Download executive HTML/PDF |
| POST | `/api/create-ticket` | ✓ | Create GitHub Issue or Jira ticket |
| POST | `/api/projects` | ✓ | Save threat model project |

---

## Running tests

```bash
cd threat-modeler
pytest tests/test_new_endpoints.py -v

# Coverage areas:
#   TestTemplates            — schema validation, flow reference integrity
#   TestDiagramExtraction    — upload, type validation, size limit, stub response
#   TestThreatStatus         — CRUD, invalid status handling
#   TestCSVExport            — content-type, header row, data integrity
#   TestSecurityHeaders      — X-Content-Type-Options, X-Frame-Options
#   TestRateLimiting         — 429 after 10 rapid login attempts
```

---

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Optional | Enables Claude Vision diagram analysis, LLM-enhanced threats, executive report narrative |
| `SECRET_KEY` | **Yes** | JWT signing secret — change this before deploying |
| `SLACK_WEBHOOK_URL` | Optional | Slack channel for new-threat alerts |
| `SMTP_HOST` / `SMTP_PORT` | Optional | SMTP server for email alerts |
| `SMTP_USER` / `SMTP_PASS` | Optional | SMTP credentials |
| `NOTIFY_EMAIL_FROM` / `TO` | Optional | Sender/recipient for email alerts |
| `NOTIFY_THRESHOLD` | Optional | Notification threshold: `critical`, `high` (default), `all` |
| `GITHUB_TOKEN` | Optional | For GitHub Issues ticket export |
| `GITHUB_REPO` | Optional | `owner/repo` for GitHub Issues |
| `JIRA_BASE_URL` | Optional | e.g. `https://yourcompany.atlassian.net` |
| `JIRA_EMAIL` / `JIRA_API_TOKEN` | Optional | Jira credentials |
| `JIRA_PROJECT_KEY` | Optional | Jira project key e.g. `SEC` |

---

## Project structure

```
threat-modeler/
├── app.py                          # FastAPI application + all API routes
├── requirements.txt
├── Dockerfile / docker-compose.yml
├── system.json                     # Example system definition for CLI
│
├── threat_engine/
│   ├── methodologies.py            # STRIDE, DREAD, LINDDUN, PASTA rules
│   ├── analyzer.py                 # Core threat analysis engine
│   ├── dfd.py                      # DFD construction helpers
│   ├── diagram_extractor.py        # Claude Vision → system model
│   ├── ticket_export.py            # GitHub Issues + Jira
│   ├── notifications.py            # Slack + SMTP alerts
│   └── executive_report.py        # Claude-narrated report + WeasyPrint PDF
│
├── db/
│   ├── __init__.py                 # Schema + migrations (incl. teams)
│   └── domain.py                   # All DB query functions
│
├── cli/
│   └── atm_cli.py                  # CI/CD command-line tool
│
├── static/
│   ├── js/
│   │   ├── app.js                  # Core DFD builder + analysis UI
│   │   └── enhancements.js        # Additive features (templates, risk matrix, etc.)
│   ├── css/
│   │   ├── app.css
│   │   └── mobile.css             # Mobile-responsive overrides
│   └── templates.json             # 5 built-in system templates
│
├── templates/
│   └── index.html                  # Main UI (3-tab: text / diagram / builder)
│
├── tests/
│   └── test_new_endpoints.py      # Pytest test suite
│
└── .github/
    └── workflows/
        └── threat-model.yml       # GitHub Actions CI workflow
```

---

## Screenshots

| Dashboard | New Model | Threat Analysis |
|-----------|-----------|-----------------|
| ![Dashboard](docs/screenshots/atm_dashboard.png) | ![New Model](docs/screenshots/atm_newmodel.png) | ![Threats](docs/screenshots/atm_threats.png) |

---

## Roadmap

- [ ] Multi-tenancy UI — team creation, member invites, shared projects
- [ ] OWASP Top 10 methodology
- [ ] MITRE ATT&CK mapping for each threat
- [ ] Bulk status update across threats
- [ ] Webhook for completed analyses (Zapier/n8n compatible)
- [ ] VS Code extension

---

## License

MIT © rootabhi1
