# 04: AbuseIPDB Source

**What to build:** IP Lookups also ask AbuseIPDB, and its panel shows the abuse confidence, number of reports, country and ISP. Domains and hashes skip AbuseIPDB, and the "Sources asked" line makes that visible. Spec user stories 14–16, 18 and 28.

**Blocked by:** 03 (VirusTotal Lookup with Verdict)

**Status:** ready-for-agent

- [ ] The AbuseIPDB adapter covers IP addresses only and maps its JSON into a Source Result with confidence, report count, country, ISP, a link and the raw JSON
- [ ] AbuseIPDB gives a Malicious Signal at confidence 75 or above and Suspicious at 25–74 (configurable); Verdict rule table tests are extended to cover it
- [ ] Domain and hash Lookups don't ask AbuseIPDB and create no AbuseIPDB Source Result
- [ ] Recorded AbuseIPDB responses (high confidence, low confidence, no reports) served by WireMock; integration tests cover an IP with both Sources, and a domain where AbuseIPDB isn't asked
- [ ] The AbuseIPDB panel renders, and the "Sources asked" line reflects the Indicator Type; frontend tests cover both
- [ ] The AbuseIPDB API key is read from the environment and listed in the example env file
