-- The order a Lookup's Source Results were shown in, so a past Lookup shows them the same way. Lookups
-- kept before this get the order the Sources were asked in at the time.
alter table lookup_source_result add column position integer;

update lookup_source_result
set position = case source_result.source
                   when 'VirusTotal' then 0
                   when 'AbuseIPDB' then 1
                   else 2
               end
from source_result
where source_result.id = lookup_source_result.source_result_id;

alter table lookup_source_result alter column position set not null;
