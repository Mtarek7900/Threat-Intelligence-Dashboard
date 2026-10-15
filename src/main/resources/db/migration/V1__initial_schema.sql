-- The local MVP has no sign-in: every Lookup belongs to this one Analyst, so GitHub
-- sign-in can add more Analysts later without migrating the Lookup History.
create table analyst (
    id           uuid primary key,
    display_name text not null
);

insert into analyst (id, display_name)
values ('00000000-0000-0000-0000-000000000001', 'Local Analyst');

create table lookup (
    id             uuid primary key,
    analyst_id     uuid        not null references analyst (id),
    indicator      text        not null,
    indicator_type text        not null,
    verdict        text        not null,
    partial        boolean     not null,
    looked_up_at   timestamptz not null
);

create index lookup_history_idx on lookup (analyst_id, looked_up_at desc);
