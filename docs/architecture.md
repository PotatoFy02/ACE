flowchart TD
    classDef runner fill:#1f2937,stroke:#3b82f6,stroke-width:2px,color:#fff
    classDef core fill:#111827,stroke:#10b981,stroke-width:2px,color:#fff
    classDef cloud fill:#1e1b4b,stroke:#8b5cf6,stroke-width:2px,color:#fff
    classDef manifest fill:#374151,stroke:#f59e0b,stroke-width:1px,color:#fff
    classDef cli fill:#064e3b,stroke:#34d399,stroke-width:2px,color:#fff

    subgraph CLI["ace-cli Docker Container (CI/CD Agnostic)"]
        class CLI cli

        subgraph Runner["Static Analysis Layer"]
            AST["AST Parser Engine\n(Python, TypeScript, Go)"]
            IaC["IaC HCL Graph Parser\n(Terraform Modules & State)"]
        end

        GitOwner["Git Commit History Parser\n(Author, PR, Last Modified)"]:::manifest
        RPM["Required Permissions Manifest (RPM)\n(Extracted App Intent — OPA-compatible JSON)"]:::manifest
        GPM["Granted Permissions Manifest (GPM)\n(Infrastructure Access Graph — OPA-compatible JSON)"]:::manifest
        DeltaEngine["Privilege Delta Engine\n[ P_excess = P_granted - P_required ]\n(OPA/Rego in Milestone 2)"]
        PatchGen["Auto-Patch Generator\n(Least-Privilege HCL Diff Engine)"]
        Validator["Patch Validation Layer\n(Syntax + Drift + Safety + Dry-Run)"]
    end

    subgraph CIWrapper["CI/CD Wrapper Layer (Thin)"]
        GHA["GitHub Actions\ndocker run ace-cli analyze"]
        GitLab["GitLab CI\ndocker run ace-cli analyze"]
        Jenkins["Jenkins\ndocker run ace-cli analyze"]
    end

    subgraph CoreEngine["ACE Core & Governance Layer"]
        HITL["Human-in-the-Loop Gateway\n(PR Comment & Approval Handler)\n(Approval bound to commit SHA)"]
        MetricsExtract["Per-Patch Metrics Extraction\n(Privileges eliminated, risk delta, approval time)"]
        ThreatDelta["Threat Delta Engine\n(STRIDE delta on patch approval)"]
        DB[(PostgreSQL Audit Store\nRLS Tenant Isolation)]
        Metrics["Metrics Dashboard\n(Tier 1 measured + Tier 2 modelled)"]
    end

    subgraph CloudEnv["Cloud Provider Telemetry"]
        Sweeper["Service Account Orphan Sweeper"]
        CloudAPIs["Native Cloud Telemetry\n(AWS IAM Access Analyzer / GCP Recommender)"]
        DeprovisionPR["Deprovisioning PR Generator\n(terraform destroy + role deletion)"]
    end

    GHA --> CLI
    GitLab --> CLI
    Jenkins --> CLI
    AST --> RPM
    IaC --> GitOwner
    GitOwner --> GPM
    IaC --> GPM
    RPM --> DeltaEngine
    GPM --> DeltaEngine
    DeltaEngine -->|P_excess > 0| PatchGen
    PatchGen --> Validator
    Validator --> HITL
    HITL -->|Post Interactive PR Gate| GHA
    HITL --> MetricsExtract
    HITL --> ThreatDelta
    MetricsExtract --> DB
    ThreatDelta --> DB
    Metrics --> DB
    CloudAPIs <--> Sweeper
    Sweeper --> DeprovisionPR
    DeprovisionPR -->|Flag Dormant NHIs| HITL