mermaid
graph TD
classDef client fill:#e3f2fd,stroke:#1976d2,stroke-width:2px;
classDef sec fill:#ffebee,stroke:#c62828,stroke-width:2px;
classDef api fill:#e8f5e9,stroke:#388e3c,stroke-width:2px;
classDef ai fill:#f3e5f5,stroke:#8e24aa,stroke-width:2px;
classDef data fill:#fff3e0,stroke:#f57c00,stroke-width:2px;
classDef auth fill:#fce4ec,stroke:#c2185b,stroke-width:2px;

subgraph CLIENT ["FRONTEND"]
UPLOAD[File Upload: drag & drop IaC]:::client
TEXTIN[Manual Description]:::client
DASH[Compliance Dashboard]:::client
REVIEW[Review UI: approve/reject/remediate]:::client
PDFBTN[Download Audit PDF]:::client
ESC[Output Escaping XSS-safe]:::sec
LOGIN[Google Sign-In]:::client
end

subgraph AUTHP ["IDENTITY"]
GOOGLE[Google OAuth 2.0]:::auth
SUPA_AUTH[Supabase Auth: issues JWT]:::auth
end

subgraph SECLAYER ["SECURITY MIDDLEWARE"]
BODYLIM[Body Limits: 25KB JSON / 120KB upload]:::sec
HEADERS[Security Headers: CSP/HSTS/XFO]:::sec
CORS[CORS env-driven]:::sec
RATELIMIT[Rate Limit: per-user JWT sub]:::sec
end

subgraph AUTHV ["AUTH VALIDATION"]
JWTVERIFY[verify_token: aud + exp + sub]:::sec
end

subgraph INPUTV ["INPUT VALIDATION"]
FILECHK[File Guard: allowlist, UTF-8, 100KB]:::sec
IAC[IaC Parser: Terraform/K8s/Docker]:::api
VDESC[validate_description: injection filter]:::sec
VNAME[validate_name]:::sec
end

subgraph ENDPOINTS ["FASTAPI ENDPOINTS"]
E_DEMO["/api/demo PUBLIC"]:::api
E_GEN["/api/generate AUTH"]:::api
E_FILE["/api/generate-from-file AUTH"]:::api
E_STATS["/stats AUTH"]:::api
E_PDF["/pdf AUTH"]:::api
E_STATUS["PATCH status"]:::api
E_REMED["PATCH remediation"]:::api
E_DEL["DELETE project"]:::api
end

subgraph AIENGINE ["AI ENGINE"]
CAP[Daily Spend Cap + timeout]:::sec
PROMPT[STRIDE Prompt: SOC2/ISO/NIST]:::ai
GEMINI[Gemini 2.5 Flash: schema-locked]:::ai
PYDANTIC[Pydantic Validation]:::ai
end

subgraph OUT ["OUTPUT"]
PDFGEN[ReportLab PDF: approved threats only]:::api
end

subgraph DATA ["SUPABASE POSTGRES + RLS"]
RLS{{"RLS Policies: auth.uid = user_id"}}:::data
T_PROJ[(projects)]:::data
T_THREAT[(threats)]:::data
T_MIT[(mitigations)]:::data
T_AUDIT[(audit_log append-only)]:::data
end

%% Auth flow
LOGIN --> SUPA_AUTH
SUPA_AUTH --> GOOGLE
GOOGLE --> SUPA_AUTH
SUPA_AUTH -->|JWT| CLIENT

%% Request entry through security layer
UPLOAD --> BODYLIM
TEXTIN --> BODYLIM
REVIEW --> BODYLIM
BODYLIM --> CORS
CORS --> RATELIMIT
RATELIMIT --> HEADERS

%% Endpoint routing
RATELIMIT --> E_DEMO
RATELIMIT --> E_GEN
RATELIMIT --> E_FILE
RATELIMIT --> E_STATS
RATELIMIT --> E_PDF
RATELIMIT --> E_STATUS
RATELIMIT --> E_REMED
RATELIMIT --> E_DEL

%% Public demo
E_DEMO --> VDESC

%% Auth-gated flows
E_GEN --> JWTVERIFY
E_FILE --> JWTVERIFY
E_STATS --> JWTVERIFY
E_PDF --> JWTVERIFY
E_STATUS --> JWTVERIFY
E_REMED --> JWTVERIFY
E_DEL --> JWTVERIFY

%% Input validation chain
E_FILE --> FILECHK
FILECHK --> IAC
IAC --> VDESC
JWTVERIFY --> VDESC
E_GEN --> VNAME
E_FILE --> VNAME

%% AI pipeline
VDESC --> CAP
CAP --> PROMPT
PROMPT --> GEMINI
GEMINI --> PYDANTIC
PYDANTIC -->|save as pending| RLS

%% Data relations
RLS --> T_PROJ
T_PROJ --> T_THREAT
T_THREAT --> T_MIT

%% Audit logging
E_GEN -->|log| T_AUDIT
E_FILE -->|log| T_AUDIT
E_STATUS -->|log| T_AUDIT
E_REMED -->|log| T_AUDIT
E_DEL -->|log| T_AUDIT

%% Reads
RLS -->|readiness| DASH
RLS -->|approved only| PDFGEN
PDFGEN --> PDFBTN
RLS --> REVIEW
REVIEW --> ESC