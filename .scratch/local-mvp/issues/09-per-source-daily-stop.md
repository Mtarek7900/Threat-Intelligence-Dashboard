# 09: Per-Source daily stop

**What to build:** To protect the owner's API quotas, each Source stops being asked once it reaches 90% of its configured daily quota. Lookups still work: that Source's Source Result is Not Checked (daily limit reached), and the Verdict is Partial. The count resets at midnight UTC. Spec user stories 38–40.

**Blocked by:** 06 (Parallel Source calls, Not Checked and Partial Verdict)

**Status:** done

> Note from ticket 06: a call that times out is not cancelled at the Source, so it still uses that Source's quota. Count each call when it is sent, not when it succeeds.

- [x] Each real call to a Source is counted per UTC day; reused Source Results don't count
- [x] Per-Source daily quota and stop percentage (default 90%) are configurable, defaulting to VirusTotal 500, AbuseIPDB 1,000 and OTX generous
- [x] At or above the stop, the Source isn't called and its Source Result is Not Checked with reason "daily limit reached"
- [x] Counts reset at midnight UTC
- [x] Integration tests use a low configured quota and the controllable clock to prove the stop, that reused results still work, and the reset at midnight UTC
- [x] The Not Checked panel shows the "daily limit reached" reason; frontend test covers it
