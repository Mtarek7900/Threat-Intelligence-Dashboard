# Spec: Local-first MVP — Indicator Lookup with combined Verdict

Status: ready-for-agent

## Problem Statement

A SOC analyst triaging an alert finds an unfamiliar IP address, domain or file hash and has to decide quickly whether it is malicious. Today that means opening VirusTotal, AbuseIPDB and AlienVault OTX in separate tabs, pasting the value into each (often after manually "refanging" a defanged value like `evil[.]com`), reading three differently shaped reports, and forming a judgement in their head. Nothing records what they saw or when, so the reasoning behind a call made on Monday is gone by Friday.

The project is also a portfolio piece: it must run locally with one command and demo convincingly to recruiters and interviewers through a README video and live screen-share.

## Solution

A locally run web dashboard where the Analyst pastes one Indicator — defanged or not — and gets back a single **Verdict** (Malicious, Suspicious, Clean or Unknown) with a plain-language "Why?", plus one panel per relevant **Source** showing its key facts and a link to that Source's own page. Sources are asked in parallel; recent **Source Results** are reused so daily API quotas last. Every **Lookup** is kept in a **Lookup History** that shows each past Lookup exactly as it was, with a banner when newer results exist. The whole thing starts with `docker compose up` and API keys in a `.env` file.

## User Stories

### Making a Lookup

1. As an Analyst, I want to paste an IP address, domain or file hash into a single input box, so that I don't have to say what kind of value it is.
2. As an Analyst, I want the dashboard to work out the Indicator Type from the value itself, so that I can paste anything straight from an alert.
3. As an Analyst, I want defanged values like `1.2.3[.]4`, `evil[.]com`, `evil(.)com` and `hxxp://evil[.]com` to be refanged automatically, so that I can paste straight from threat reports and tickets.
4. As an Analyst, I want leading/trailing whitespace trimmed and domains and hashes lower-cased, so that `EVIL.com ` and `evil.com` are treated as the same Indicator.
5. As an Analyst, I want IPv4 and IPv6 addresses accepted, so that I can investigate either.
6. As an Analyst, I want MD5, SHA-1 and SHA-256 hashes accepted, so that I can investigate files whatever hash my tools give me.
7. As an Analyst, I want private, loopback, link-local and other reserved IP addresses rejected with a clear message, so that I don't waste Source quota on internal addresses no Source knows about.
8. As an Analyst, I want input that is not a recognisable IP, domain or hash rejected with a message saying what is accepted, so that I know how to fix it.
9. As an Analyst, I want a URL I paste to be rejected with a message saying URLs aren't supported yet, so that I'm not confused by a generic error.
10. As an Analyst, I want to see the normalised Indicator that was actually looked up, so that I can confirm the refanging did what I expected.
11. As an Analyst, I want all relevant Sources asked at the same time, so that I wait only as long as the slowest one.
12. As an Analyst, I want a loading state while a Lookup is in progress, so that I know the dashboard is working.
13. As an Analyst, I want a Lookup to finish within roughly ten seconds even if a Source hangs, so that one slow Source doesn't block my triage.

### Sources

14. As an Analyst, I want IP addresses checked against VirusTotal, AbuseIPDB and AlienVault OTX, so that I get three independent opinions.
15. As an Analyst, I want domains and hashes checked against VirusTotal and AlienVault OTX only, so that Sources that don't cover a type aren't asked pointlessly.
16. As an Analyst, I want to see which Sources were asked for this Lookup, so that I understand why a panel is missing.
17. As an Analyst, I want VirusTotal's panel to show how many engines flagged the Indicator out of how many, and when it was last analysed, so that I can judge how strong its opinion is.
18. As an Analyst, I want AbuseIPDB's panel to show the abuse confidence score, number of reports, country and ISP, so that I can judge the IP's reputation and ownership.
19. As an Analyst, I want OTX's panel to show the names and tags of the pulses that mention the Indicator, so that I can link it to known campaigns.
20. As an Analyst, I want each Source panel to link to that Indicator's page on the Source's own site, so that I can dig deeper.
21. As an Analyst, I want each Source panel to say whether the Source has Seen the Indicator, has Not Seen it, or was Not Checked, so that "no record" and "couldn't ask" are never confused.
22. As an Analyst, I want a Not Checked panel to say why (timeout, Source error, daily limit reached, missing API key), so that I know whether retrying will help.
23. As an Analyst, I want to expand a collapsed section showing each Source's raw response, so that I can see details the panel doesn't summarise.

### Verdict

24. As an Analyst, I want one Verdict — Malicious, Suspicious, Clean or Unknown — at the top of the result, so that I can triage at a glance.
25. As an Analyst, I want a "Why?" explanation listing which Source Results produced which Signal, so that I can trust or challenge the Verdict.
26. As an Analyst, I want the Verdict to be the worst counted Signal across Sources, so that one confident Source is enough to raise the alarm.
27. As an Analyst, I want VirusTotal to give a Malicious Signal when 3 or more engines flag the Indicator and a Suspicious Signal when 1–2 do, so that a lone false positive doesn't read as Malicious.
28. As an Analyst, I want AbuseIPDB to give a Malicious Signal at confidence 75 or above and a Suspicious Signal at 25–74, so that its score maps to the same scale.
29. As an Analyst, I want OTX treated as a Corroborating Source — its Signal counts only when another Source also gives a Signal — so that benign reference IPs like `8.8.8.8` that appear in many pulses aren't marked Suspicious.
30. As an Analyst, I want the Verdict to be Clean only when at least one Source has Seen the Indicator and none gave a counted Signal, so that "Clean" always means someone actually looked.
31. As an Analyst, I want the Verdict to be Unknown when no Source has Seen the Indicator, so that I never mistake absence of data for safety.
32. As an Analyst, I want the Verdict marked as a Partial Verdict, naming the missing Sources, whenever any asked Source was Not Checked, so that I know the judgement is incomplete.
33. As the project owner, I want the Verdict thresholds held in configuration, so that I can tune them without code changes.

### Reuse of Source Results and quota protection

34. As an Analyst, I want a Source Result less than 24 hours old to be reused instead of asking the Source again, so that repeat Lookups are instant and quota lasts.
35. As an Analyst, I want each Source panel to show when its Source Result was fetched and whether it was reused, so that I know how current the information is.
36. As an Analyst, I want a Refresh action that asks every relevant Source again regardless of age, so that I can get the latest picture when it matters.
37. As an Analyst, I want reuse decided per Source, so that if one Source's result is stale only that Source is asked again.
38. As the project owner, I want each Source to stop being asked once it reaches 90% of its daily quota, with its Source Result marked Not Checked (daily limit reached), so that I never get locked out of a Source's API.
39. As the project owner, I want each Source's daily count to reset at midnight UTC, so that the stop matches how the Sources count their own quotas.
40. As the project owner, I want the reuse window, quota limits and stop percentage in configuration, so that I can match them to my API plans.
41. As an Analyst, I want a Source with no API key configured to show as Not Checked (missing API key) rather than breaking the app, so that I can run the dashboard with only some keys.

### Lookup History

42. As an Analyst, I want the home screen to show my Lookup History, most recent first, so that I can return to recent investigations.
43. As an Analyst, I want each history entry to show the Indicator, its Type, the Verdict at the time and when it was looked up, so that I can scan my recent work.
44. As an Analyst, I want repeated Lookups of the same Indicator grouped with a count badge (e.g. "×3"), so that the history stays readable while every Lookup is still kept.
45. As an Analyst, I want opening a past Lookup to show the Verdict and Source Results exactly as they were at that moment, so that I can see what I knew when I made a call.
46. As an Analyst, I want a banner on a past Lookup when newer Source Results exist for that Indicator, showing the newer Verdict, so that I notice when the picture has changed.
47. As an Analyst, I want to open the newer picture from that banner, so that I can move from the old Lookup to current information in one click.
48. As an Analyst, I want an empty-state message on the home screen before my first Lookup, so that a fresh install doesn't look broken.

### Running and demoing locally

49. As the project owner, I want to start the dashboard and its database with one `docker compose up`, so that a demo or interview screen-share takes seconds to set up.
50. As the project owner, I want Source API keys read from a `.env` file that is never committed, with a committed example file listing the keys, so that secrets stay out of the public repo.
51. As the project owner, I want the database schema created automatically on start-up, so that a fresh clone works without manual steps.
52. As the project owner, I want the README to include a short demo video or GIF, screenshots, a feature list and the tech stack, so that recruiters understand the project without running it.
53. As the project owner, I want every push to GitHub to run the backend and frontend test suites in GitHub Actions, so that the public repo visibly stays green.
54. As a developer, I want the React dev server to proxy API calls to the Spring Boot app, so that I get hot reload locally with the same single-origin setup as the packaged app.

## Implementation Decisions

- **Shape (ADR 0001):** one repo with a Spring Boot 3 / Java 21 / Maven backend and a React + TypeScript + Vite + Tailwind frontend. Maven builds the frontend and packages it into the Spring Boot jar's static resources; one container serves UI and REST API from the same origin. Base package `io.github.mtarek7900.tid`. MIT licence.
- **Local runtime:** Docker Compose runs the app and PostgreSQL. API keys and tunables come from environment variables supplied via `.env`.
- **Persistence:** PostgreSQL with Flyway migrations. Core tables: Lookups, Source Results, the association from a Lookup to the Source Results it used (each with its Signal), and per-Source daily call counts. Source Results are append-only: never updated or deleted; asking again inserts a new row. A Lookup stores its normalised Indicator, Indicator Type, Verdict, Partial flag and timestamp.
- **Single Analyst:** the local MVP has no sign-in. The data model still records an Analyst on each Lookup (a single fixed local Analyst) so that GitHub sign-in can be added later without migrating history.
- **Indicator parsing module (pure, deep):** one entry point takes raw text and returns either a normalised Indicator with its Indicator Type or a rejection reason (unrecognised, URL not supported, private/reserved IP). It owns refanging (`[.]`, `(.)`, `[dot]`, `hxxp`/`hxxps`, `[:]`), trimming, lower-casing domains and hashes, IPv4/IPv6 detection with reserved-range rejection, domain validation, and hash detection by length and hex alphabet.
- **Verdict rule module (pure, deep):** one entry point takes the Source Results for a Lookup and returns the Verdict, the Partial flag with the missing Sources, and the per-Source explanation lines for "Why?". Each Source maps its own result to a Signal; OTX is flagged as a Corroborating Source. Thresholds come from configuration.
- **Source clients:** one adapter per Source behind a common interface: which Indicator Types it covers, and "fetch a Source Result for this Indicator". Each adapter maps the Source's JSON into a Source Result (outcome Seen / Not Seen / Not Checked with reason, key facts for the panel, link to the Source's page, raw JSON). Adding a fourth Source should mean adding one adapter and its config.
- **Lookup service:** given raw input, parse it; pick the Sources covering the Indicator Type; for each Source, reuse its newest Source Result if younger than the reuse window and Refresh wasn't requested, otherwise check that Source's daily stop and ask it; call Sources in parallel with a per-Source timeout (default 10 s); persist new Source Results; compute the Verdict; persist and return the Lookup.
- **Clock:** time is read from an injected clock everywhere (reuse window, daily reset at midnight UTC, timestamps) so tests can control it.
- **REST API (JSON):**
  - `POST /api/lookups` with the raw input and an optional refresh flag → the full Lookup (normalised Indicator, Type, Verdict, Partial info, "Why?" lines, Sources asked, each Source Result with outcome, facts, link, fetched-at, reused flag, raw JSON). Rejected input returns a 400 response with the rejection reason.
  - `GET /api/lookups` → the Lookup History, most recent first, grouped by Indicator with counts.
  - `GET /api/lookups/{id}` → that Lookup as it was, plus a "newer results" summary (newer Verdict and timestamp) when Source Results newer than those it used exist for the Indicator.
- **Configuration:** reuse window (24 h), per-Source daily quota and stop percentage (90%), per-Source timeout (10 s), and Verdict thresholds all live in application config and can be overridden through environment variables.
- **Frontend:** a home screen (input box plus Lookup History with grouping and empty state) and a Lookup screen (Verdict + "Why?", Partial label, Sources-asked line, Source panels, Refresh, raw-JSON section, newer-results banner). Plain `fetch` against the REST API; no global state library needed at this size.
- **CI:** GitHub Actions runs the Maven build (backend tests, including Testcontainers) and the frontend tests on every push.

## Testing Decisions

- **What makes a good test here:** it exercises behaviour through a seam the way a caller would, and asserts on observable outcomes (HTTP responses, rendered text), never on internal classes, method calls or database rows directly. A test should survive a refactor that keeps behaviour unchanged.
- **Seam 1 — backend REST API (primary):** Spring Boot integration tests send real HTTP requests to the running app. Sources are faked at the network edge with WireMock, serving recorded real responses per Source (malicious, clean, not found, rate-limited, server error, slow/timeout). PostgreSQL runs via Testcontainers (Docker must be running). The clock is controlled by the test. This seam covers: rejection messages; Type detection and which Sources are asked; Verdict and Partial Verdict end to end; reuse within 24 h and fresh calls after; Refresh; per-Source reuse; the 90% daily stop and its midnight-UTC reset; timeouts and missing keys producing Not Checked; history ordering and grouping; past Lookups returned as they were; the newer-results summary.
- **Pure-logic modules (table-driven unit tests):** the Indicator parsing module and the Verdict rule module each get a table of input → expected output cases (every refang pattern, reserved IP ranges, hash lengths, edge domains; every Signal combination, Corroborating Source behaviour, Clean vs Unknown, Partial). Seam 1 then needs only a few representative cases to prove they're wired in.
- **Seam 2 — React UI:** Vitest + React Testing Library with the API faked by MSW. Tests assert on what the Analyst sees: Verdict and "Why?", Partial label naming missing Sources, Source panels for each outcome, Sources-asked line, validation messages, loading state, history grouping and empty state, newer-results banner and its link, Refresh.
- **Smoke test:** one Playwright test against the packaged jar (with Postgres and WireMock-faked Sources) that loads the home screen, makes a Lookup and sees a Verdict, which proves the React-in-Spring-Boot packaging works. It's written in the final ticket.
- **Recorded responses:** each Source's real JSON is captured once with a real key, with personal or account details removed, and committed as test fixtures. Tests never call real Source APIs.
- **Prior art:** none yet (no code in the repo). The first tickets establish the patterns that later tickets follow.

## Out of Scope

- Hosting, deployment from CI, HTTPS (later "Hosted" milestone; Oracle Cloud Always Free is the leading candidate, to be confirmed with `/research`).
- GitHub sign-in, multiple Analysts, per-Analyst Lookup Allowance and its counter, private-per-Analyst history, "Delete my history" (all in the Hosted milestone).
- URL Indicators, email addresses and other Indicator Types.
- Batch Lookups (pasting a list).
- Streaming Source Results as they arrive (Server-Sent Events).
- Trending Indicators or any cross-Analyst views.
- Additional Sources (abuse.ch, Shodan, MalwareBazaar, etc.).
- Admin screens, weighted risk scores, alerting or scheduled feed collection.

## Further Notes

- Terminology follows `CONTEXT.md`: Analyst, Indicator, Indicator Type, Defanged/Refanging, Lookup, Lookup History, Source, Source Result (Seen / Not Seen / Not Checked), Signal, Corroborating Source, Verdict, Unknown, Partial Verdict.
- Known limitation to state in the README: file hashes are covered only by VirusTotal and OTX, and OTX is a Corroborating Source, so a hash's Verdict effectively rests on VirusTotal alone.
- Free-tier quotas assumed for defaults (to be confirmed when keys are obtained): VirusTotal about 4 requests/min and 500/day; AbuseIPDB 1,000/day; OTX generous. VirusTotal's per-minute limit means a burst of Lookups can produce "rate-limited" Not Checked results. That's acceptable for the MVP and must be handled gracefully.
- Docker Desktop must be running for Compose and for Testcontainers.
