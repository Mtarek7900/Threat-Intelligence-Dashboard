# 07: Reuse of Source Results and Refresh

**What to build:** If a Source Result for the same Indicator is less than 24 hours old, it is reused instead of asking that Source again. This is decided per Source, so only stale Sources are asked. Each panel shows when its result was fetched and whether it was reused. A Refresh button asks every relevant Source again regardless of age. Spec user stories 34–37 and 40.

**Blocked by:** 03 (VirusTotal Lookup with Verdict)

**Status:** done

- [x] Each Source's newest Seen or Not Seen Source Result younger than the reuse window (default 24 h, configurable) is reused; Not Checked results are never reused
- [x] Reuse is decided per Source: in a single Lookup, a fresh result from one Source can sit alongside a reused result from another
- [x] `POST /api/lookups` accepts a refresh flag that skips reuse for every relevant Source
- [x] Reused results still create a new Lookup that records which Source Results it used; Source Results are never updated
- [x] Integration tests use the controllable clock to prove reuse at 23 h, fresh calls at 25 h, per-Source reuse and Refresh, checking WireMock call counts
- [x] Each panel shows its fetched-at time and a "reused" marker; the Lookup screen has a Refresh button; frontend tests cover these
