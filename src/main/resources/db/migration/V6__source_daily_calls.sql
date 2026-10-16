-- How many times each Source has been asked on each UTC day, so it stops being asked before its
-- daily quota runs out
create table source_daily_calls (
    source text    not null,
    day    date    not null,
    calls  integer not null,
    primary key (source, day)
);
