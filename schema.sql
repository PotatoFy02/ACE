create table if not exists projects (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users(id) on delete cascade,
    name text not null,
    architecture_description text not null,
    system_summary text,
    model_json jsonb,
    source_type text default 'manual',
    compliance_status text default 'draft',
    created_at timestamptz default now()
);

create table if not exists threats (
    id uuid primary key default gen_random_uuid(),
    project_id uuid not null references projects(id) on delete cascade,
    category text not null,
    title text not null,
    description text not null,
    affected_component text,
    severity text not null,
    soc2_control text,
    frameworks jsonb default '{}'::jsonb,
    status text default 'pending' check (status in ('pending','accepted','rejected')),
    remediation_status text default 'not_started'
        check (remediation_status in ('not_started','in_progress','resolved')),
    is_custom boolean default false,
    updated_at timestamptz default now(),
    created_at timestamptz default now()
);

create table if not exists mitigations (
    id uuid primary key default gen_random_uuid(),
    threat_id uuid not null references threats(id) on delete cascade,
    description text not null,
    created_at timestamptz default now()
);

create table if not exists audit_log (
    id uuid primary key default gen_random_uuid(),
    user_id uuid,
    action text not null,
    target_id uuid,
    created_at timestamptz default now()
);

alter table projects enable row level security;
alter table threats enable row level security;
alter table mitigations enable row level security;
alter table audit_log enable row level security;

drop policy if exists "own_projects" on projects;
create policy "own_projects" on projects
    for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

drop policy if exists "own_threats" on threats;
create policy "own_threats" on threats
    for all
    using (
        exists (select 1 from projects p where p.id = threats.project_id and p.user_id = auth.uid())
    )
    with check (
        exists (select 1 from projects p where p.id = threats.project_id and p.user_id = auth.uid())
    );

drop policy if exists "own_mitigations" on mitigations;
create policy "own_mitigations" on mitigations
    for all
    using (
        exists (
            select 1 from threats t
            join projects p on p.id = t.project_id
            where t.id = mitigations.threat_id and p.user_id = auth.uid()
        )
    )
    with check (
        exists (
            select 1 from threats t
            join projects p on p.id = t.project_id
            where t.id = mitigations.threat_id and p.user_id = auth.uid()
        )
    );

revoke update, delete on audit_log from anon, authenticated;

drop policy if exists "audit_insert" on audit_log;
create policy "audit_insert" on audit_log
    for insert with check (auth.uid() = user_id);

drop policy if exists "audit_read_own" on audit_log;
create policy "audit_read_own" on audit_log
    for select using (auth.uid() = user_id);