flowchart TD
    classDef runner fill:#1f2937,stroke:#3b82f6,stroke-width:2px,color:#fff
    classDef core fill:#111827,stroke:#10b981,stroke-width:2px,color:#fff
    classDef cloud fill:#1e1b4b,stroke:#8b5cf6,stroke-width:2px,color:#fff
    classDef manifest fill:#374151,stroke:#f59e0b,stroke-width:1px,color:#fff
    classDef cli fill:#064e3b,stroke:#34d399,stroke-width:2px,color:#fff
    classDef gate fill:#7f1d1d,stroke:#ef4444,stroke-width:2px,color:#fff
    classDef approval fill:#1e3a5f,stroke:#3b82f6,stroke-width:2px,color:#fff

    subgraph CLI["ace-cli Docker Container (CI/CD Agnostic)"]
        subgraph Runner["Static Analysis Layer"]
            AST["AST Parser Engine\n(tree-sitter 0.26, manual walker)\n(Python only — Milestone 1)"]
            IaC["IaC HCL Parser\n(python-hcl2)\n(Terraform only — Milestone 1)"]
        end

        RPM["Required Permissions Manifest\n(What code actually calls)\nOPA-compatible JSON"]:::manifest
        GPM["Granted Permissions Manifest\n(What infrastructure allows)\nOPA-compatible JSON"]:::manifest

        Matcher["RPM→GPM Fuzzy Matcher\n(Token overlap, MIN_SCORE=1)\n(AMBIGUOUS fallback — never forces)"]
        DeltaEngine["Privilege Delta Engine\nP_excess = P_granted - P_required\nSeverity assigned here, never in parsers"]
        PatchGen["Auto-Patch Generator\n(HCL diff, wildcard expansion)\nABORTS if requires_human_review=True"]
        RedGate["Red-Risk Gate\n(CI fails on patch_risk=red\nwithout approval record)"]:::gate
    end

    subgraph CIWrapper["CI/CD Wrapper Layer"]
        GHA["GitHub Actions\n.github/workflows/ace.yml\n(ace-cli Docker + gate_approval.py)"]
    end

    subgraph ApprovalLayer["Human Approval Layer (Week 5 — NEW)"]
        WebhookHandler["GitHub Webhook Handler\nPOST /webhooks/github\nHMAC-SHA256 verified"]:::approval
        ApprovalGate["gate_approval.py\n(CI script — exit 0=approved, exit 1=blocked)"]:::approval
        ApprovalStore[("Supabase approvals table\n(commit_sha, role_arn, approver,\npr_number, repo, approved_at)\nRLS: service_role only")]:::approval
    end

    subgraph CoreEngine["ACE Core & Governance Layer"]
        HITL["Human-in-the-Loop Gateway\n(PR Comment — /ace approve SHA role_arn)\n(Approval bound to exact commit SHA)"]
        MetricsExtract["Per-Patch Metrics Extraction\n(Milestone 3)"]
        ThreatDelta["Blast Radius Assessment\n(Milestone 3 — replaces STRIDE delta)"]
        DB[(PostgreSQL Audit Store\nRLS Tenant Isolation\nMilestone 2)]
        Metrics["Metrics Dashboard\n(Milestone 3)"]
    end

    subgraph CloudEnv["Cloud Provider Telemetry (Milestone 2+)"]
        Sweeper["Service Account Orphan Sweeper\n(14-day cooling-off period\nbefore any PR suggestion)"]
        CloudAPIs["Native Cloud Telemetry\n(AWS IAM Access Analyzer)"]
        DeprovisionPR["Deprovisioning PR Generator\n(human-gated, never automated)"]
    end

    GHA --> CLI
    AST --> RPM
    IaC --> GPM
    RPM --> Matcher
    GPM --> Matcher
    Matcher -->|FUZZY_NAME| DeltaEngine
    Matcher -->|AMBIGUOUS| HITL
    DeltaEngine -->|P_excess > 0, requires_human_review=False| PatchGen
    DeltaEngine -->|requires_human_review=True| HITL
    PatchGen --> RedGate
    RedGate -->|patch_risk=red| ApprovalGate
    RedGate -->|patch_risk=green| GHA
    ApprovalGate -->|checks| ApprovalStore
    ApprovalGate -->|approved| GHA
    ApprovalGate -->|not approved — CI blocked| HITL
    HITL -->|/ace approve SHA role_arn| WebhookHandler
    WebhookHandler -->|HMAC verified + authorized| ApprovalStore
    WebhookHandler -->|post PR comment| GHA
    MetricsExtract --> DB
    ThreatDelta --> DB
    Metrics --> DB
    CloudAPIs <--> Sweeper
    Sweeper -->|14-day flag| DeprovisionPR
    DeprovisionPR --> HITL