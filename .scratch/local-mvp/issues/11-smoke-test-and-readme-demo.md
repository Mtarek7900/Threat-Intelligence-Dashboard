# 11: Smoke test and README demo

**What to build:** Proof that the packaged app works end to end, and a README that sells the project to a recruiter who will never run it. Spec user stories 49–53.

**Blocked by:** 04, 05, 06, 07, 08, 09, 10

**Status:** done

- [x] One Playwright test runs against the packaged jar (Postgres plus WireMock-faked Sources): load the home page, look up an Indicator, see a Verdict and Source panels, see it in Lookup History
- [x] The Playwright test runs in GitHub Actions
- [x] README: one-paragraph pitch, feature list, tech stack, architecture sketch (single deployable, Sources, Verdict rule), screenshots, and a 60–90 second demo video or GIF
- [x] README: how to get free VirusTotal, AbuseIPDB and OTX API keys, set up `.env` and run `docker compose up` (Docker Desktop must be running)
- [x] README: known limitations (hash Verdicts rest on VirusTotal; VirusTotal's per-minute limit can produce rate-limited Not Checked results) and the planned Hosted milestone
- [x] README links to `CONTEXT.md` and `docs/adr/` to show the design process
