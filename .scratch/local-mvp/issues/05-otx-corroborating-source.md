# 05: OTX as a Corroborating Source

**What to build:** Lookups for all three Indicator Types also ask AlienVault OTX, and its panel shows the names and tags of the pulses that mention the Indicator. OTX is a Corroborating Source: its Signal counts only when another Source also gives a Signal. A benign reference like `8.8.8.8` therefore stays Clean even though it appears in many pulses. Spec user stories 14, 15, 19 and 29.

**Blocked by:** 03 (VirusTotal Lookup with Verdict)

**Status:** ready-for-agent

- [ ] The OTX adapter covers IPs, domains and hashes and maps its JSON into a Source Result with pulse count, pulse names, tags, a link and the raw JSON
- [ ] OTX gives a Suspicious Signal when it appears in at least one pulse, and is marked as a Corroborating Source; the Verdict rule counts its Signal only when another Source also gives one
- [ ] Verdict rule table tests cover OTX alone (no effect), OTX plus a Suspicious or Malicious Signal from another Source, and the "Why?" wording for each
- [ ] Recorded OTX responses (many pulses, no pulses) served by WireMock; an integration test reproduces the `8.8.8.8` case: OTX pulses plus a clean VirusTotal result gives Clean
- [ ] The OTX panel renders pulse names and tags; the "Why?" section says when OTX's Signal was not counted; frontend tests cover both
- [ ] The OTX API key is read from the environment and listed in the example env file
