# 03: VirusTotal Lookup with Verdict

**What to build:** A Lookup asks VirusTotal about the Indicator, and the result screen shows a real Verdict with a "Why?" explanation, a VirusTotal panel and the raw response. This establishes the Source adapter pattern, append-only Source Results and the Verdict rule that every later Source plugs into. Spec user stories 14, 17, 20, 21, 23–27, 30, 31 and 33.

**Blocked by:** 02 (Indicator input and validation)

**Status:** ready-for-human

- [x] A common Source interface: the Indicator Types it covers, and fetching a Source Result for an Indicator
- [x] The VirusTotal adapter covers IPs, domains and hashes and maps the JSON into a Source Result: outcome (Seen or Not Seen), engines flagged out of total, last analysis date, link to the Indicator's VirusTotal page, and the raw JSON
- [x] Source Results are stored append-only, and a Lookup records which Source Results it used and the Signal of each
- [x] A pure Verdict rule module returns the Verdict and the "Why?" lines: worst counted Signal wins; VirusTotal gives Malicious at 3 or more engines and Suspicious at 1–2; Clean only if at least one Source has Seen the Indicator and none gave a Signal; Unknown if no Source has Seen it
- [x] Verdict thresholds are in application configuration and can be overridden with environment variables
- [x] Table-driven JUnit tests for the Verdict rule cover every Signal combination, Clean vs Unknown, and threshold edges
- [ ] Real VirusTotal responses (malicious, clean, not found) are recorded once, stripped of any account details, committed as test data and served by WireMock
  - Not yet recorded: there was no VirusTotal key on the build machine, so the four fixtures in `src/test/resources/wiremock/__files/virustotal/` follow VirusTotal's documented v3 response format. Replace them with real responses (same file names) once a key is available.
- [x] Integration tests at the REST API cover a Malicious, a Clean and an Unknown Lookup end to end
- [x] The result screen shows the Verdict, the "Why?" section, the "Sources asked" line, the VirusTotal panel with its outcome and link, and a collapsed raw-JSON section; frontend tests cover these
- [x] The VirusTotal API key is read from the environment
