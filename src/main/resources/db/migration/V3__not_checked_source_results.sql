-- A Source that wasn't asked or couldn't answer still gets a Source Result: Not Checked, with
-- the reason. It has no response body.
alter table source_result add column not_checked_reason text;
alter table source_result alter column raw_response drop not null;
