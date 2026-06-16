"""Threat Modeler — FastAPI app with RBAC.

Architecture (POC):
  - SQLite via db/__init__.py
  - JWT access tokens + opaque refresh tokens (auth/auth.py)
  - Role-based permission checks via @require_permission decorators
  - Resource-access checks via ensure_can_access_threat_model
  - Hierarchy: Release → Feature → ThreatModel → Threats (with per-threat status)

Run locally:
  export INITIAL_ADMIN_EMAIL=admin@example.com
  export INITIAL_ADMIN_PASSWORD=changeme123
  export JWT_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
  python app.py
  # Open http://127.0.0.1:8000
"""
from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field

import json
import re
import secrets as _secrets
import logging as _logging
import uuid as _uuid
from contextvars import ContextVar as _ContextVar
from datetime import timedelta as _td

