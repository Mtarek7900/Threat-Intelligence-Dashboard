-- Whether a Lookup reused a Source Result an earlier Lookup fetched, rather than asking the Source,
-- so a past Lookup can show which of its Source Results were reused.
alter table lookup_source_result add column reused boolean not null default false;
