graph TD
classDef client fill:#e3f2fd,stroke:#1976d2,stroke-width:2px;
classDef sec fill:#ffebee,stroke:#c62828,stroke-width:2px;
classDef api fill:#e8f5e9,stroke:#388e3c,stroke-width:2px;
classDef ai fill:#f3e5f5,stroke:#8e24aa,stroke-width:2px;
classDef data fill:#fff3e0,stroke:#f57c00,stroke-width:2px;
classDef auth fill:#fce4ec,stroke:#c2185b,stroke-width:2px;
classDef ext fill:#eceff1,stroke:#455a64,stroke-width:2px;

subgraph CLIENT ["ACE FRONTEND (static/index.html + security.html)"]
LOGIN[Google Sign-In button]:::client
UPLOAD[File Upload: drag & drop IaC]:::client
TEXTIN[Manual Description]:::client
GHIN[GitHub Repo URL input]:::client
DASH[Compliance Dashboard: readiness + pending]:::client
REVIEW[Review UI: approve/reject/remediate]:::client
PDFBTN[Download Audit PDF]:::client
ESC[Output Escaping XSS-safe]:::sec
end

subgraph IDENTITY ["IDENTITY"]
GOOGLE[Google OAuth 2.0]:::auth
SUPA_AUTH[Supabase Auth: issues JWT HS256]:::auth
end

subgraph EXTERNAL ["EXTERNAL SOURCES"]
GHAPI[GitHub Public API: api.github.com + raw]:::ext
end

subgraph SECLAYER ["SECURITY MIDDLEWARE (app.py)"]
BODYLIM[Body Limits: 25KB JSON / 120KB upload]:::sec
CORS[CORS env-driven ALLOWED_ORIGINS]:::sec
RATELIMIT[Rate Limit: per-user JWT sub]:::sec
HEADERS[Security Headers: CSP/HSTS/XFO/nosniff]:::sec
end

subgraph AUTHV ["AUTH VALIDATION (auth.py)"]
BEARER[get_bearer: extract token]:::sec
JWTVERIFY[verify_token: HS256, aud=authenticated, exp+sub]:::sec
end

subgraph INPUTV ["INPUT VALIDATION"]
FILECHK[File Guard: ext allowlist, UTF-8, 100KB, control-strip]:::sec
GHFETCH[github_import.py: URL-pattern validated, 25 files, 7KB cap]:::sec
IAC[iac_parser.py: Terraform/K8s/Docker/Compose]:::api
VDESC[validate_description: 15-8000 chars, injection filter]:::sec
VNAME[validate_name]:::sec
end

subgraph ENDPOINTS ["ACE API ENDPOINTS (app.py)"]
E_DEMO["/api/demo PUBLIC 3/hr"]:::api
E_GEN["/api/generate AUTH 20/hr"]:::api
E_FILE["/api/generate-from-file AUTH 20/hr"]:::api
E_GH["/api/generate-from-github AUTH 10/hr"]:::api
E_LIST["/api/projects AUTH"]:::api
E_PROJ["/api/projects/id AUTH"]:::api
E_STATS["/api/projects/id/stats AUTH"]:::api
E_PDF["/api/projects/id/pdf AUTH"]:::api
E_STATUS["PATCH /threats/id/status AUTH"]:::api
E_REMED["PATCH /threats/id/remediation AUTH"]:::api
E_DEL["DELETE /api/projects/id AUTH"]:::api
end

subgraph AIENGINE ["AI ENGINE (generate.py)"]
CAP[Daily Spend Cap + timeout]:::sec
PROMPT[STRIDE Prompt: SOC2/ISO/NIST, injection-hardened]:::ai
GEMINI[Gemini 2.5 Flash: schema-locked JSON]:::ai
PYDANTIC[Pydantic ThreatModel validation]:::ai
end

subgraph OUT ["OUTPUT (pdf.py)"]
PDFGEN[ReportLab PDF: accepted threats only]:::api
end

subgraph DATA ["SUPABASE POSTGRES + RLS (db.py, anon key + user JWT)"]
RLS{{"RLS Policies: auth.uid = user_id"}}:::data
T_PROJ[(projects: source_type manual/github)]:::data
T_THREAT[(threats: status + remediation + frameworks)]:::data
T_MIT[(mitigations)]:::data
T_AUDIT[(audit_log append-only)]:::data
end

%% Auth flow
LOGIN --> SUPA_AUTH
SUPA_AUTH --> GOOGLE
GOOGLE --> SUPA_AUTH
SUPA_AUTH -->|JWT| CLIENT

%% Entry through security middleware
UPLOAD --> BODYLIM
TEXTIN --> BODYLIM
GHIN --> BODYLIM
REVIEW --> BODYLIM
BODYLIM --> CORS
CORS --> RATELIMIT
RATELIMIT --> HEADERS

%% Endpoint routing
HEADERS --> E_DEMO
HEADERS --> E_GEN
HEADERS --> E_FILE
HEADERS --> E_GH
HEADERS --> E_LIST
HEADERS --> E_PROJ
HEADERS --> E_STATS
HEADERS --> E_PDF
HEADERS --> E_STATUS
HEADERS --> E_REMED
HEADERS --> E_DEL

%% Public demo path
E_DEMO --> VDESC

%% Auth on protected endpoints
E_GEN --> BEARER
E_FILE --> BEARER
E_GH --> BEARER
E_LIST --> BEARER
E_PROJ --> BEARER
E_STATS --> BEARER
E_PDF --> BEARER
E_STATUS --> BEARER
E_REMED --> BEARER
E_DEL --> BEARER
BEARER --> JWTVERIFY

%% Manual generate path
E_GEN --> VNAME
E_GEN --> VDESC

%% File upload path
E_FILE --> FILECHK
FILECHK --> IAC
E_FILE --> VNAME

%% GitHub import path
E_GH --> GHFETCH
GHFETCH --> GHAPI
GHAPI --> GHFETCH
GHFETCH --> IAC
E_GH --> VNAME

%% Parsed content into validation
IAC --> VDESC

%% AI pipeline
VDESC --> CAP
CAP --> PROMPT
PROMPT --> GEMINI
GEMINI --> PYDANTIC
PYDANTIC -->|save as pending| RLS

%% Data relationships
JWTVERIFY --> RLS
RLS --> T_PROJ
T_PROJ --> T_THREAT
T_THREAT --> T_MIT

%% Audit logging
E_GEN -->|log create| T_AUDIT
E_FILE -->|log create| T_AUDIT
E_GH -->|log create| T_AUDIT
E_STATUS -->|log status| T_AUDIT
E_REMED -->|log remediation| T_AUDIT
E_DEL -->|log delete| T_AUDIT

%% Reads back to client
RLS -->|readiness score| DASH
RLS -->|project + threats| REVIEW
RLS -->|accepted only| PDFGEN
PDFGEN --> PDFBTN
REVIEW --> ESC