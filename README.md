# 🛡 Automated Threat Modeler

> AI-powered threat modeling for engineering teams — STRIDE, DREAD, LINDDUN, PASTA and OWASP Top 10.

[![Live Demo](https://img.shields.io/badge/🌐_Live_Site-GitHub_Pages-22c55e?style=flat-square)](https://rootabhi1.github.io/Automated-Threat-Modelling/)
[![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green?style=flat-square)](https://fastapi.tiangolo.com)
[![Claude AI](https://img.shields.io/badge/Claude-Opus%204.8-purple?style=flat-square)](https://anthropic.com)
[![License](https://img.shields.io/badge/License-MIT-gray?style=flat-square)](LICENSE)

---

## 🌐 Live project site

**[https://rootabhi1.github.io/Automated-Threat-Modelling/](https://rootabhi1.github.io/Automated-Threat-Modelling/)**

The project site (GitHub Pages) includes:
- Interactive quick-start guide with copy-paste commands
- Full feature overview
- Complete API reference (22 endpoints)
- Common troubleshooting steps

---

## Branches

Everything now lives on `main` — the former `feature/enhancements` branch has been
merged in, so there is a single source of truth. STRIDE, DREAD, LINDDUN, PASTA,
OWASP Top 10, ATT&CK mapping, compliance controls, custom rules, dark mode, AI fix,
CI/CD and the rest are all on `main`.

---

## Run locally

```bash
# 1. Clone
git clone https://github.com/rootabhi1/Automated-Threat-Modelling
cd Automated-Threat-Modelling/threat-modeler

# 2. Create virtual environment and install
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 3. Set required environment variables
export INITIAL_ADMIN_EMAIL=admin@example.com
export INITIAL_ADMIN_PASSWORD=changeme123
export JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
export ANTHROPIC_API_KEY=sk-ant-...    # Optional — enables Claude AI features

# 4. Start the server
python app.py
# or with auto-reload:  uvicorn app:app --reload --port 8000
# or with Docker:       docker compose up --build

# 5. Open in browser
open http://localhost:8000
# API docs: http://localhost:8000/docs
```

**Verify it's working:**
```bash
curl http://localhost:8000/healthz
# → {"status":"ok","version":"2.1"}

curl http://localhost:8000/readyz
# → {"status":"ready","db":"ok"}
```

---

## Deploy with Docker

The compose file requires three secrets — it fails fast if they are missing, so
you can't accidentally boot with a throwaway JWT secret (which would log everyone
out on every restart).

```bash
cd threat-modeler
cp .env.example .env          # then edit .env

# Generate a persistent JWT secret:
python -c "import secrets; print(secrets.token_urlsafe(48))"

docker compose up --build
```

Minimum `.env`:

```bash
JWT_SECRET=<paste the generated value>
INITIAL_ADMIN_EMAIL=admin@example.com
INITIAL_ADMIN_PASSWORD=change-me-now
# ANTHROPIC_API_KEY=sk-ant-...   # optional — omit to run rules-only, fully offline
```

> **Single-instance note.** Sessions, rate limiting and the SQLite store are
> per-process. Run one container instance. For horizontal scaling, move to
> PostgreSQL (`DATABASE_URL`) and a shared `JWT_SECRET` first.

---

## What's included

### Analysis engine
| Feature | Description |
|---------|-------------|
| **OWASP Top 10 2021** | 5th methodology — 10 categories, 22 threats (A01–A10) |
| **Threat deduplication** | Cross-methodology duplicates merged, highest severity kept |
| **MITRE ATT&CK mapping** | Every threat gets technique ID + tactic from CWE |
| **CVSS 3.1 + 4.0** | Both scores displayed per threat |
| **Compliance controls** | SOC2 / ISO 27001 / PCI-DSS IDs mapped per threat |
| **Custom threat rules** | Define domain-specific threats via UI, persisted to DB |

### Results & reporting
| Feature | Description |
|---------|-------------|
| **AI code fix** | 🔧 Fix button — Claude generates before/after code in your stack |
| **Share link** | 7-day read-only URL, no login required |
| **Release diff** | Compare two saved models: new, resolved, severity changes |
| **Risk matrix** | 5×5 Likelihood × Impact, click cells to drill in |
| **Attack paths** | Top 5 multi-hop chains across trust boundaries |
| **Executive PDF** | Claude-narrated summary — HTML or PDF via WeasyPrint |
| **Risk register CSV** | With CVSS, ATT&CK, compliance controls |

### UX & DX
| Feature | Description |
|---------|-------------|
| **Dark mode** | 🌙/☀️ toggle in header, saved to localStorage |
| **Keyboard shortcuts** | `n` `f` `b` `a` `Ctrl+S` `?` |
| **Bulk status update** | Select all Low/Info and mark accepted in one click |
| **5 system templates** | SaaS, Mobile, Microservices, Data Pipeline, IoT |
| **Diagram upload** | Claude Vision extracts components from PNG/JPG/WebP |
| **Mobile responsive** | Stacked layout, touch-friendly, hidden minimap |

### DevOps
| Feature | Description |
|---------|-------------|
| **PostgreSQL** | Set `DATABASE_URL` to switch from SQLite |
| **Health checks** | `/healthz` (liveness) + `/readyz` (DB ping) |
| **JSON logging** | Structured with `X-Request-ID` correlation |
| **Security headers** | X-Content-Type-Options, X-Frame-Options, HSTS, rate limiting |
| **GitHub Actions CI** | Threat model on every PR, pip-audit CVE scan |
| **Dependabot** | Weekly dep updates for pip and GitHub Actions |
| **Test suite** | pytest covering all new endpoints |

---

## API reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/login` | — | Get JWT token |
| POST | `/api/analyze` | ✓ | Run threat model |
| POST | `/api/extract-from-text` | ✓ | Text → components |
| POST | `/api/extract-from-diagram` | ✓ | Claude Vision → components |
| GET  | `/api/templates` | ✓ | Built-in system templates |
| POST | `/api/custom-rules` | ✓ | Create custom threat rule |
| GET  | `/api/custom-rules` | ✓ | List custom rules |
| POST | `/api/threat-status` | ✓ | Set remediation status |
| POST | `/api/threat-status/bulk` | ✓ | Bulk update statuses |
| POST | `/api/share/:id` | ✓ | Generate share link |
| GET  | `/share/:token` | — | View shared report |
| GET  | `/api/releases/:a/diff/:b` | ✓ | Compare two models |
| POST | `/api/threat/fix` | ✓ | AI code fix (Claude) |
| POST | `/api/report/csv` | ✓ | Risk register CSV |
| POST | `/api/report/executive` | ✓ | Executive HTML/PDF |
| POST | `/api/create-ticket` | ✓ | GitHub Issues / Jira |
| GET  | `/healthz` | — | Liveness probe |
| GET  | `/readyz` | — | Readiness probe |

Full interactive docs at `http://localhost:8000/docs` once running.

---

## Running tests

```bash
cd threat-modeler
export INITIAL_ADMIN_EMAIL=admin@example.com
export INITIAL_ADMIN_PASSWORD=changeme123
export JWT_SECRET=test-secret
pytest tests/test_new_endpoints.py -v
```

---

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `INITIAL_ADMIN_EMAIL` | **Yes** | Admin account email on first run |
| `INITIAL_ADMIN_PASSWORD` | **Yes** | Admin account password on first run |
| `JWT_SECRET` | **Yes** | JWT signing secret — set a persistent value |
| `ANTHROPIC_API_KEY` | Optional | Claude Vision, AI fix, executive report narration |
| `DATABASE_URL` | Optional | PostgreSQL: `postgresql://user:pass@host:5432/atm` |
| `SLACK_WEBHOOK_URL` | Optional | Slack alerts for new Critical/High threats |
| `SMTP_HOST/PORT/USER/PASS` | Optional | Email alert credentials |
| `NOTIFY_EMAIL_FROM/TO` | Optional | Email alert sender/recipient |
| `NOTIFY_THRESHOLD` | Optional | `critical` / `high` (default) / `all` |
| `GITHUB_TOKEN` + `GITHUB_REPO` | Optional | GitHub Issues ticket export |
| `JIRA_BASE_URL/EMAIL/API_TOKEN/PROJECT_KEY` | Optional | Jira integration |

---

## Screenshots

| Dashboard | New Model | Threat Analysis |
|-----------|-----------|-----------------|
| ![Dashboard](docs/screenshots/atm_dashboard.png) | ![New Model](docs/screenshots/atm_newmodel.png) | ![Threats](docs/screenshots/atm_threats.png) |

---

## License

MIT © rootabhi1
