-- Source Results are append-only: asking a Source again inserts a new row and never changes an
-- old one, so a past Lookup can always show the Source Results it was made from.
create table source_result (
    id             uuid primary key,
    source         text        not null,
    indicator      text        not null,
    indicator_type text        not null,
    outcome        text        not null,
    facts          jsonb,
    link           text        not null,
    -- The Source's response body exactly as received, so text rather than jsonb
    raw_response   text        not null,
    fetched_at     timestamptz not null
);

-- The Source Results a Lookup used, with the Signal and "Why?" line the Verdict rule gave each at
-- the time, so later threshold changes don't rewrite past Lookups.
create table lookup_source_result (
    lookup_id        uuid not null references lookup (id),
    source_result_id uuid not null references source_result (id),
    signal           text not null,
    explanation      text not null,
    primary key (lookup_id, source_result_id)
);
