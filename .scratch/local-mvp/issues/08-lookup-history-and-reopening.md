# 08: Lookup History and reopening a past Lookup

**What to build:** The home screen lists the Analyst's past Lookups, most recent first. Each entry shows its Indicator, Indicator Type, Verdict at the time and timestamp, and repeated Lookups of the same Indicator are grouped with a count badge. Opening an entry shows that Lookup exactly as it was: its Verdict and the Source Results it used, even if newer results exist since. Spec user stories 42–45 and 48.

**Blocked by:** 03 (VirusTotal Lookup with Verdict)

**Status:** ready-for-agent

- [ ] `GET /api/lookups` returns the Lookup History most recent first, grouped by Indicator with a count and the latest Lookup per group
- [ ] `GET /api/lookups/{id}` returns that Lookup with its stored Verdict, Partial info, "Why?" lines and the exact Source Results it used
- [ ] Integration tests prove ordering, grouping and that a past Lookup is unchanged after newer Source Results arrive for the same Indicator
- [ ] The home screen renders history entries with Verdict, Type, timestamp and a "×N" badge for repeats; clicking an entry opens it; the empty state still shows when there's no history
- [ ] A group can be expanded to show each individual Lookup in it
- [ ] Frontend tests cover the list, the grouping and opening a past Lookup
