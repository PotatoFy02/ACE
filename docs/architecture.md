flowchart TD
    Dev((Developer pushes code)) --> CLI_Boundary

    subgraph CLI_Boundary [ace-cli Pipeline]
        direction TB
        RPM["<b>RPM Engine</b><br/>Required Permission Model"]
        GPM["<b>GPM Engine</b><br/>Granted Permission Model"]
        Delta["<b>Delta Engine</b><br/>Computes P_excess"]
        Patch["<b>Patch Generator</b><br/>Produces HCL diff"]
        Gate{"<b>Gate Check</b>"}

        RPM --> Delta
        GPM --> Delta
        Delta --> Patch
        Patch --> Gate
    end

    %% CI Outcomes
    Gate -->|Green/Yellow Risk| Pass((CI Passes))
    Gate -->|Red Risk| Human>Human Approval Required]

    %% The Gemini Labeling Flow (Runs regardless of findings)
    Delta -->|After every delta run| Gemini["<b>Gemini Labeling (generate.py)</b><br/>STRIDE + SOC2 Mapping"]

    %% The Webhook Flow
    Human --> Webhook["<b>GitHub Webhook</b><br/>HMAC-SHA256 verified"]

    %% Independent Sweeper Flow
    subgraph Sweeper_Boundary [Sweeper Engine]
        direction TB
        SweeperCron((Scheduled Run)) --> SweeperLogic["<b>Dormant Role Detection</b><br/>14-day cooling-off state machine"]
    end

    %% Database & API Boundary
    subgraph API_Boundary [ace-api Backend]
        direction TB
        DB[("<b>Supabase (Postgres)</b><br/>Tables: threats, approvals, sweeper_roles<br/>View: <i>ace_unified_view</i>")]
        Endpoint["<b>GET /evidence-pdf</b><br/>Queries ace_unified_view"]
    end

    %% Routing into the DB
    Webhook -->|Inserts Approval (SHA-bound)| DB
    Gemini -->|Populates Threats Table| DB
    SweeperLogic -->|Updates sweeper_roles Table| DB

    %% Final Output
    DB --> Endpoint
    Endpoint --> Final((SOC2 CC6.3 Evidence PDF))