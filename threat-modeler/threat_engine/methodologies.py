"""Threat modeling methodology catalogs.

Each methodology defines categories and the rule patterns that map
component types / data flow attributes to applicable threats.
"""

# ---------- STRIDE ----------
STRIDE = {
    "name": "STRIDE",
    "description": "Microsoft's threat model: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege",
    "categories": {
        "Spoofing": {
            "description": "Impersonating someone or something",
            "applies_to": ["user", "external_entity", "api", "auth_service", "webapp", "mobile_app"],
            "threats": [
                {
                    "title": "Authentication bypass via credential stuffing",
                    "description": "Attackers reuse leaked credentials to impersonate legitimate users.",
                    "severity": "High",
                    "mitigations": ["Implement MFA", "Rate-limit login attempts", "Monitor for credential stuffing patterns", "Use passkeys / WebAuthn where possible"],
                },
                {
                    "title": "Session token hijacking",
                    "description": "Attacker steals or predicts a session token to impersonate a user.",
                    "severity": "High",
                    "mitigations": ["Use HTTPOnly + Secure + SameSite cookies", "Rotate tokens on privilege change", "Bind tokens to client fingerprint"],
                },
                {
                    "title": "API key / service identity spoofing",
                    "description": "An attacker obtains or forges an API key to act as a trusted service.",
                    "severity": "High",
                    "mitigations": ["Use short-lived tokens (mTLS / JWT with rotation)", "Store keys in a secrets manager", "Audit key usage and anomalous source IPs"],
                },
            ],
        },
        "Tampering": {
            "description": "Modifying data or code",
            "applies_to": ["database", "datastore", "data_flow", "queue", "cache", "filesystem", "config"],
            "threats": [
                {
                    "title": "Data-in-transit modification",
                    "description": "Attacker on the network path alters request/response payloads.",
                    "severity": "High",
                    "mitigations": ["Enforce TLS 1.2+ on all flows", "Use HSTS", "Pin certificates for service-to-service calls"],
                },
                {
                    "title": "Stored data tampering via injection",
                    "description": "SQL/NoSQL/command injection alters records or schema.",
                    "severity": "Critical",
                    "mitigations": ["Use parameterized queries", "Validate and sanitize inputs", "Apply least-privilege DB users"],
                },
                {
                    "title": "Config / secret tampering",
                    "description": "Unauthorized changes to runtime config alter security behavior.",
                    "severity": "High",
                    "mitigations": ["Sign config bundles", "Audit config changes", "Restrict write access via IAM"],
                },
            ],
        },
        "Repudiation": {
            "description": "Denying having performed an action",
            "applies_to": ["api", "webapp", "auth_service", "database", "payment_service"],
            "threats": [
                {
                    "title": "Insufficient audit logging",
                    "description": "Critical user actions cannot be reliably attributed after the fact.",
                    "severity": "Medium",
                    "mitigations": ["Log auth, privilege changes, and write operations", "Ship logs to tamper-evident storage", "Include user, timestamp, source IP, action"],
                },
                {
                    "title": "Log tampering",
                    "description": "An attacker with access modifies or deletes audit trails.",
                    "severity": "High",
                    "mitigations": ["Stream logs off-host immediately", "Use append-only / WORM log storage", "Sign log batches"],
                },
            ],
        },
        "Information Disclosure": {
            "description": "Exposing information to unauthorized parties",
            "applies_to": ["database", "datastore", "api", "webapp", "data_flow", "cache", "filesystem", "external_entity"],
            "threats": [
                {
                    "title": "Sensitive data exposure in transit",
                    "description": "PII, secrets, or tokens transmitted over unencrypted channels.",
                    "severity": "High",
                    "mitigations": ["Enforce TLS for all internal & external flows", "Disable plaintext fallbacks", "Inspect with DLP scanners"],
                },
                {
                    "title": "Sensitive data exposure at rest",
                    "description": "Stored PII / secrets accessible without proper authorization.",
                    "severity": "High",
                    "mitigations": ["Encrypt at rest (AES-256)", "Tokenize / hash sensitive fields", "Apply row-level access control"],
                },
                {
                    "title": "Verbose error messages / stack traces",
                    "description": "Error responses leak implementation details to attackers.",
                    "severity": "Medium",
                    "mitigations": ["Return generic errors to clients", "Log detailed errors server-side only", "Disable debug mode in production"],
                },
                {
                    "title": "Insecure direct object reference (IDOR)",
                    "description": "User can access another user's resources by guessing IDs.",
                    "severity": "High",
                    "mitigations": ["Enforce object-level authz on every request", "Use unguessable IDs (UUIDs)", "Add object-ownership tests in CI"],
                },
            ],
        },
        "Denial of Service": {
            "description": "Making a service unavailable",
            "applies_to": ["webapp", "api", "database", "external_entity", "queue", "auth_service"],
            "threats": [
                {
                    "title": "Resource exhaustion via unbounded input",
                    "description": "Large payloads or unbounded loops exhaust CPU/memory.",
                    "severity": "Medium",
                    "mitigations": ["Set request size limits", "Apply timeouts on all I/O", "Use circuit breakers on downstreams"],
                },
                {
                    "title": "Application-layer DDoS",
                    "description": "Attacker floods expensive endpoints (e.g., search, login).",
                    "severity": "High",
                    "mitigations": ["Rate-limit per IP/user/key", "Front with WAF/CDN with DDoS protection", "Add CAPTCHA on abusive endpoints"],
                },
                {
                    "title": "Algorithmic complexity attack",
                    "description": "Crafted inputs trigger worst-case algorithm behavior (e.g., regex DoS).",
                    "severity": "Medium",
                    "mitigations": ["Avoid catastrophic regex patterns", "Cap input sizes", "Use timeouts on parsers"],
                },
            ],
        },
        "Elevation of Privilege": {
            "description": "Gaining capabilities without proper authorization",
            "applies_to": ["api", "webapp", "auth_service", "admin_panel", "database"],
            "threats": [
                {
                    "title": "Broken access control / missing authz check",
                    "description": "Endpoints fail to verify the caller has permission for the action.",
                    "severity": "Critical",
                    "mitigations": ["Centralize authz in middleware", "Default-deny on new routes", "Add automated authz tests per endpoint"],
                },
                {
                    "title": "Privilege escalation via mass assignment",
                    "description": "User submits extra fields (e.g., role=admin) and they bind to the model.",
                    "severity": "High",
                    "mitigations": ["Use explicit allow-lists for input binding", "Separate admin and user DTOs", "Review ORM model exposure"],
                },
                {
                    "title": "Container / process escape",
                    "description": "Attacker breaks out of a sandbox to gain host privileges.",
                    "severity": "Critical",
                    "mitigations": ["Run as non-root", "Drop Linux capabilities", "Apply seccomp / AppArmor profiles"],
                },
            ],
        },
    },
}

# ---------- DREAD (scoring overlay) ----------
DREAD = {
    "name": "DREAD",
    "description": "Risk-rating model: Damage, Reproducibility, Exploitability, Affected users, Discoverability (1-10 each)",
    "categories": {
        "Risk Rating": {
            "description": "Score each component's existing threats on 5 axes",
            "applies_to": ["*"],
            "threats": [
                {
                    "title": "High-damage data exposure (D)",
                    "description": "If exploited, breach would expose regulated data (PII, PHI, PCI).",
                    "severity": "High",
                    "mitigations": ["Map data classifications", "Apply encryption + tokenization", "Run DLP on egress"],
                },
                {
                    "title": "Easily reproducible exploit (R)",
                    "description": "Attack works the same way every time — no race or timing dependency.",
                    "severity": "High",
                    "mitigations": ["Add randomized rate limits / nonces", "Patch deterministic logic flaws first"],
                },
                {
                    "title": "Low exploitability barrier (E)",
                    "description": "Any unauthenticated attacker can attempt the exploit.",
                    "severity": "Critical",
                    "mitigations": ["Require auth on the affected surface", "Add WAF rule for the pattern"],
                },
                {
                    "title": "Wide blast radius — affected users (A)",
                    "description": "A single exploit impacts most or all users of the system.",
                    "severity": "Critical",
                    "mitigations": ["Add per-tenant isolation", "Cap session/token scope"],
                },
                {
                    "title": "High discoverability (D)",
                    "description": "Vulnerability is visible to anyone scanning the system.",
                    "severity": "High",
                    "mitigations": ["Reduce attack surface", "Hide internal interfaces from the public network"],
                },
            ],
        },
    },
}

# ---------- LINDDUN (privacy) ----------
LINDDUN = {
    "name": "LINDDUN",
    "description": "Privacy threat model: Linkability, Identifiability, Non-repudiation, Detectability, Disclosure of information, Unawareness, Non-compliance",
    "categories": {
        "Linkability": {
            "description": "Linking data items or actions to the same subject without their consent",
            "applies_to": ["database", "api", "webapp", "data_flow"],
            "threats": [
                {
                    "title": "Cross-service user linkability",
                    "description": "Identifiers (emails, device IDs) let separate datasets be joined to profile a user.",
                    "severity": "Medium",
                    "mitigations": ["Use per-context pseudonyms", "Avoid global IDs in analytics", "Apply k-anonymity for shared datasets"],
                },
            ],
        },
        "Identifiability": {
            "description": "Identifying a subject from supposedly anonymous data",
            "applies_to": ["database", "datastore", "data_flow", "external_entity"],
            "threats": [
                {
                    "title": "Re-identification of anonymized data",
                    "description": "Quasi-identifiers (zip, DOB, gender) re-identify users in 'anonymous' exports.",
                    "severity": "High",
                    "mitigations": ["Apply differential privacy on aggregates", "Generalize quasi-identifiers", "Audit re-identification risk before release"],
                },
            ],
        },
        "Non-repudiation": {
            "description": "Inability to deny a claim — adverse for privacy",
            "applies_to": ["webapp", "api", "auth_service"],
            "threats": [
                {
                    "title": "Forced attribution of sensitive actions",
                    "description": "User cannot deny a sensitive action even when they should have plausible deniability.",
                    "severity": "Low",
                    "mitigations": ["Offer ephemeral / deniable modes where appropriate", "Avoid logging more than needed"],
                },
            ],
        },
        "Detectability": {
            "description": "Distinguishing whether an item / action exists",
            "applies_to": ["api", "webapp", "auth_service"],
            "threats": [
                {
                    "title": "Account enumeration via differential responses",
                    "description": "Login / signup / password reset reveal whether an account exists.",
                    "severity": "Medium",
                    "mitigations": ["Return identical responses regardless of account existence", "Constant-time comparisons"],
                },
            ],
        },
        "Disclosure of information": {
            "description": "Exposing information beyond what is necessary",
            "applies_to": ["database", "datastore", "api", "data_flow", "webapp"],
            "threats": [
                {
                    "title": "Excessive data collection",
                    "description": "System collects more PII than needed for its purpose.",
                    "severity": "Medium",
                    "mitigations": ["Apply data minimization", "Document lawful basis per field", "Run privacy impact assessments"],
                },
                {
                    "title": "Third-party data leakage",
                    "description": "PII shared with analytics/ad SDKs without consent.",
                    "severity": "High",
                    "mitigations": ["Vendor review + DPAs", "Consent management platform", "Block third-party trackers by default"],
                },
            ],
        },
        "Unawareness": {
            "description": "Subject is unaware of data being collected / used",
            "applies_to": ["webapp", "mobile_app", "api"],
            "threats": [
                {
                    "title": "Lack of transparent privacy notice",
                    "description": "Users don't know what data is collected or for what purpose.",
                    "severity": "Medium",
                    "mitigations": ["Clear, layered privacy notice", "Just-in-time consent prompts", "Subject access / export tooling"],
                },
            ],
        },
        "Non-compliance": {
            "description": "Failure to meet regulatory or contractual privacy obligations",
            "applies_to": ["*"],
            "threats": [
                {
                    "title": "GDPR / CCPA / HIPAA gaps",
                    "description": "Missing DSAR handling, retention policies, or data residency controls.",
                    "severity": "High",
                    "mitigations": ["Map data flows to applicable regs", "Automate DSAR pipeline", "Set retention TTLs by data class"],
                },
            ],
        },
    },
}

# ---------- PASTA (process-oriented; we surface threat patterns) ----------
PASTA = {
    "name": "PASTA",
    "description": "Process for Attack Simulation and Threat Analysis — 7-stage risk-centric methodology",
    "categories": {
        "Stage 1 — Business Objectives": {
            "description": "Identify business impact of compromise",
            "applies_to": ["*"],
            "threats": [
                {
                    "title": "Unmapped business-critical asset",
                    "description": "Component handles revenue/regulated data but has no documented owner or risk tier.",
                    "severity": "Medium",
                    "mitigations": ["Assign asset owner", "Tag asset with business impact tier", "Include in BCP/DR scope"],
                },
            ],
        },
        "Stage 2 — Technical Scope": {
            "description": "Define infrastructure and dependencies",
            "applies_to": ["*"],
            "threats": [
                {
                    "title": "Unknown / outdated dependency",
                    "description": "Third-party library with known CVEs in the dependency graph.",
                    "severity": "High",
                    "mitigations": ["Continuous SCA scanning", "Pin and patch dependencies", "Track SBOM"],
                },
            ],
        },
        "Stage 3 — Application Decomposition": {
            "description": "Map data flows, trust boundaries, entry points",
            "applies_to": ["webapp", "api", "data_flow"],
            "threats": [
                {
                    "title": "Implicit trust across boundary",
                    "description": "Data crosses a trust boundary without authn/authz/validation.",
                    "severity": "High",
                    "mitigations": ["Enforce authn at every boundary", "Validate inputs server-side", "Use mTLS between services"],
                },
            ],
        },
        "Stage 4 — Threat Analysis": {
            "description": "Identify likely threat actors and TTPs",
            "applies_to": ["*"],
            "threats": [
                {
                    "title": "Threat actor profile not defined",
                    "description": "No mapping of plausible adversaries (script kiddie → nation-state) to system surfaces.",
                    "severity": "Low",
                    "mitigations": ["Document actor tiers and motives", "Map TTPs (MITRE ATT&CK) to surfaces"],
                },
            ],
        },
        "Stage 5 — Vulnerability Analysis": {
            "description": "Find weaknesses",
            "applies_to": ["webapp", "api", "database", "auth_service"],
            "threats": [
                {
                    "title": "OWASP Top-10 class weakness present",
                    "description": "Missing controls for injection, broken access, SSRF, etc.",
                    "severity": "High",
                    "mitigations": ["Adopt OWASP ASVS", "Run SAST + DAST in CI", "Threat-test on each release"],
                },
            ],
        },
        "Stage 6 — Attack Modeling": {
            "description": "Build attack trees",
            "applies_to": ["*"],
            "threats": [
                {
                    "title": "Untested attack path",
                    "description": "Plausible kill-chain (e.g., phish → token theft → admin) not exercised.",
                    "severity": "Medium",
                    "mitigations": ["Run purple-team exercises", "Model attack trees and rank by likelihood × impact"],
                },
            ],
        },
        "Stage 7 — Risk & Impact Analysis": {
            "description": "Quantify and prioritize",
            "applies_to": ["*"],
            "threats": [
                {
                    "title": "No residual-risk acceptance",
                    "description": "Risks are listed but not formally accepted/transferred/mitigated by an owner.",
                    "severity": "Low",
                    "mitigations": ["Track each risk to a decision (accept/mitigate/transfer/avoid)", "Re-review quarterly"],
                },
            ],
        },
    },
}


# ── OWASP Top 10 (2021) ────────────────────────────────────────────────────
OWASP_TOP10 = {
    "name": "OWASP Top 10",
    "description": "The 10 most critical web application security risks (OWASP 2021 edition)",
    "categories": {
        "A01 Broken Access Control": {
            "description": "Restrictions on authenticated users not properly enforced",
            "applies_to": ["api", "webapp", "admin_panel", "auth_service"],
            "threats": [
                {"title": "Insecure Direct Object Reference (IDOR)",
                 "description": "User can access other users' data by modifying IDs in requests.",
                 "severity": "High",
                 "mitigations": ["Enforce object-level auth on every endpoint", "Use indirect references (map IDs to UUIDs)", "Log and alert on access-denied spikes"]},
                {"title": "Missing function-level access control",
                 "description": "Administrative endpoints accessible to low-privilege users.",
                 "severity": "Critical",
                 "mitigations": ["Default-deny on all new routes", "Centralise authorisation in middleware", "Automated tests for privilege escalation paths"]},
                {"title": "CORS misconfiguration allowing credential sharing",
                 "description": "Wildcard or overly permissive CORS origin allows cross-origin credential theft.",
                 "severity": "High",
                 "mitigations": ["Whitelist specific origins", "Never combine Access-Control-Allow-Origin: * with credentials", "Review CORS policy in CI"]},
            ],
        },
        "A02 Cryptographic Failures": {
            "description": "Failures related to cryptography exposing sensitive data",
            "applies_to": ["database", "datastore", "api", "webapp", "cache"],
            "threats": [
                {"title": "Sensitive data stored in plaintext",
                 "description": "PII, passwords or payment data stored without encryption.",
                 "severity": "Critical",
                 "mitigations": ["Encrypt at rest using AES-256", "Use a KMS for key management", "Hash passwords with bcrypt/argon2 (never MD5/SHA1)"]},
                {"title": "Cleartext transmission of credentials",
                 "description": "Passwords or tokens transmitted over HTTP or unencrypted channels.",
                 "severity": "High",
                 "mitigations": ["Enforce HTTPS/TLS 1.2+ everywhere", "HSTS with preloading", "Certificate pinning in mobile clients"]},
                {"title": "Use of deprecated cryptographic algorithms",
                 "description": "MD5, SHA-1, DES, or RC4 used for hashing or encryption.",
                 "severity": "Medium",
                 "mitigations": ["Use SHA-256+ for hashing", "Use AES-GCM for encryption", "Run crypto audit with bandit / semgrep"]},
            ],
        },
        "A03 Injection": {
            "description": "Hostile data sent to an interpreter",
            "applies_to": ["api", "webapp", "database", "queue"],
            "threats": [
                {"title": "SQL injection via unsanitised input",
                 "description": "Attacker manipulates SQL queries to read, modify, or delete data.",
                 "severity": "Critical",
                 "mitigations": ["Use parameterised queries / prepared statements", "ORM with query binding", "WAF + input length limits"]},
                {"title": "Command injection via shell execution",
                 "description": "User-controlled data passed to OS shell commands.",
                 "severity": "Critical",
                 "mitigations": ["Avoid shell=True; use subprocess with argument lists", "Whitelist allowed command arguments", "Run processes with minimal OS privileges"]},
                {"title": "NoSQL injection",
                 "description": "Attacker manipulates MongoDB / DynamoDB query objects.",
                 "severity": "High",
                 "mitigations": ["Validate and sanitise all query parameters", "Use typed query builders", "Disable operator injection ($where, $regex)"]},
            ],
        },
        "A04 Insecure Design": {
            "description": "Missing or ineffective security controls in design",
            "applies_to": ["api", "webapp", "auth_service", "admin_panel"],
            "threats": [
                {"title": "No rate limiting on sensitive actions",
                 "description": "Brute-force, credential stuffing, or resource exhaustion possible.",
                 "severity": "High",
                 "mitigations": ["Rate-limit per IP and per user on login, registration, and password reset", "Exponential back-off after failures", "CAPTCHA on high-risk flows"]},
                {"title": "Insecure password reset flow",
                 "description": "Reset tokens guessable, long-lived, or reusable.",
                 "severity": "High",
                 "mitigations": ["Use cryptographically random tokens (≥128 bits)", "Expire tokens after 15 minutes", "Invalidate token on use"]},
            ],
        },
        "A05 Security Misconfiguration": {
            "description": "Improperly configured security controls",
            "applies_to": ["api", "webapp", "database", "config", "admin_panel"],
            "threats": [
                {"title": "Default credentials left on service",
                 "description": "Admin password or API key left at factory default.",
                 "severity": "Critical",
                 "mitigations": ["Rotate all defaults at provisioning", "Fail startup if SECRET_KEY is default", "Automated credential rotation"]},
                {"title": "Unnecessary features and ports exposed",
                 "description": "Debug endpoints, stack traces, or unused services reachable from outside.",
                 "severity": "Medium",
                 "mitigations": ["Disable debug mode in production", "Network-level port allow-list", "Remove unused dependencies and routes"]},
                {"title": "Missing security headers",
                 "description": "CSP, X-Frame-Options, HSTS absent, enabling clickjacking and injection.",
                 "severity": "Medium",
                 "mitigations": ["Implement Content-Security-Policy", "Add all OWASP-recommended headers", "Scan headers with securityheaders.com in CI"]},
            ],
        },
        "A06 Vulnerable and Outdated Components": {
            "description": "Using components with known vulnerabilities",
            "applies_to": ["api", "webapp", "database", "cache"],
            "threats": [
                {"title": "Known CVE in a third-party dependency",
                 "description": "npm/pip/maven package has an unpatched vulnerability.",
                 "severity": "High",
                 "mitigations": ["Run pip-audit / npm audit in CI", "Enable Dependabot / Renovate", "Pin versions and review changelogs before updates"]},
                {"title": "End-of-life runtime or framework",
                 "description": "Python 2, Node 14, or OpenSSL 1.0 in use — no security patches.",
                 "severity": "High",
                 "mitigations": ["Upgrade runtime to supported LTS version", "Track EOL dates in a dependency register", "Use container base images with automated rebuild on CVE"]},
            ],
        },
        "A07 Identification and Authentication Failures": {
            "description": "Weaknesses in authentication and session management",
            "applies_to": ["auth_service", "api", "webapp", "mobile_app"],
            "threats": [
                {"title": "Weak or absent MFA on privileged accounts",
                 "description": "Admin and high-privilege users authenticated by password only.",
                 "severity": "Critical",
                 "mitigations": ["Enforce MFA for all admin roles", "Prefer hardware tokens or passkeys", "Alert on MFA bypass attempts"]},
                {"title": "Session fixation",
                 "description": "Session ID not rotated after login, enabling fixation attacks.",
                 "severity": "High",
                 "mitigations": ["Regenerate session ID on authentication", "Set short session TTL for sensitive operations", "Bind session to user-agent and IP range"]},
            ],
        },
        "A08 Software and Data Integrity Failures": {
            "description": "Code and infrastructure without integrity verification",
            "applies_to": ["api", "webapp", "queue", "external_entity"],
            "threats": [
                {"title": "Insecure deserialisation",
                 "description": "Attacker sends crafted serialised objects to execute code or escalate privilege.",
                 "severity": "Critical",
                 "mitigations": ["Avoid deserialising untrusted data", "Use safe formats (JSON schema-validated)", "Integrity-check deserialised objects before use"]},
                {"title": "CI/CD pipeline compromise",
                 "description": "Attacker injects malicious code via a compromised build step.",
                 "severity": "High",
                 "mitigations": ["Pin CI action versions to full SHA", "Require signed commits on main", "Audit third-party GitHub Actions used"]},
            ],
        },
        "A09 Security Logging and Monitoring Failures": {
            "description": "Insufficient logging, monitoring, and alerting",
            "applies_to": ["api", "auth_service", "database", "admin_panel"],
            "threats": [
                {"title": "Failed logins not logged or alerted",
                 "description": "Brute-force attacks invisible to security team.",
                 "severity": "High",
                 "mitigations": ["Log all auth events with IP, user-agent, and outcome", "Alert on N failures in M minutes", "Ship logs to SIEM / immutable store"]},
                {"title": "Audit trail absent for sensitive data access",
                 "description": "No record of who accessed PII or admin functions.",
                 "severity": "Medium",
                 "mitigations": ["Append-only audit log for data access events", "Include actor, resource, action, timestamp", "Periodic audit log integrity check"]},
            ],
        },
        "A10 Server-Side Request Forgery (SSRF)": {
            "description": "Server fetches remote resource without validation",
            "applies_to": ["api", "webapp", "external_entity"],
            "threats": [
                {"title": "SSRF via user-supplied URL parameter",
                 "description": "Attacker makes the server fetch internal metadata endpoints or internal services.",
                 "severity": "Critical",
                 "mitigations": ["Validate and whitelist URL schemes and hosts", "Block RFC-1918 and metadata IP ranges (169.254.0.0/16)", "Use an egress proxy with explicit allow-list"]},
            ],
        },
    },
}

METHODOLOGIES = {
    "stride": STRIDE,
    "dread": DREAD,
    "linddun": LINDDUN,
    "pasta": PASTA,
    "owasp": OWASP_TOP10,
}

# ---- Component type taxonomy used by the analyzer/UI ----
COMPONENT_TYPES = [
    "user", "external_entity", "webapp", "mobile_app", "api",
    "auth_service", "admin_panel", "database", "datastore",
    "cache", "queue", "filesystem", "config", "payment_service", "data_flow",
]
