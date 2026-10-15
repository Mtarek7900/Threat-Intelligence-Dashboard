# 06: Parallel Source calls, Not Checked and Partial Verdict

**What to build:** The Sources for a Lookup are asked at the same time, each with a 10-second timeout, so the Analyst waits only as long as the slowest Source. A loading state shows while they wait. If a Source times out, returns an error or has no API key configured, its Source Result is Not Checked with the reason shown, and the Verdict becomes a Partial Verdict naming the missing Sources. Spec user stories 11–13, 21, 22, 32 and 41.

**Blocked by:** 03 (VirusTotal Lookup with Verdict)

**Status:** done

- [x] Relevant Sources are called in parallel; the per-Source timeout (default 10 s) is configurable
- [x] Timeout, server error, rate-limited response and missing API key each produce a Not Checked Source Result with a distinct reason; the app never fails because of one Source
- [x] The Verdict rule marks the Verdict Partial and lists the Sources that weren't checked whenever any asked Source is Not Checked; table tests cover this, including "all Not Checked" (Unknown, Partial)
- [x] Integration tests use WireMock delays and errors to prove the timeout, the error handling and that total time is bounded by the slowest Source rather than the sum
- [x] The UI shows a loading state during a Lookup, a "Partial" label naming the missing Sources, and the reason on each Not Checked panel; frontend tests cover these
