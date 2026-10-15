# 01: Walking skeleton

**What to build:** Running `docker compose up` starts the dashboard and PostgreSQL. Opening the app in a browser shows the React home page, served from the Spring Boot jar, with an empty Lookup History and a friendly empty-state message. The page reads the history through the REST API from Postgres. All the test and CI tooling every later ticket relies on is in place and green. See spec: `.scratch/local-mvp/spec.md` and ADR 0001.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] Backend is Spring Boot 3, Java 21 and Maven (with the Maven wrapper), base package `io.github.mtarek7900.tid`; frontend is React, TypeScript, Vite and Tailwind
- [ ] The Maven build compiles the frontend and packages it into the Spring Boot jar; one container serves the UI and `/api/**` from the same origin
- [ ] The Vite dev server proxies `/api` to Spring Boot for hot-reload development
- [ ] Docker Compose runs the app and PostgreSQL; a fresh clone plus `docker compose up` works with no manual steps
- [ ] Flyway creates the initial schema on start-up, including the single local Analyst that every Lookup will belong to
- [ ] `GET /api/lookups` returns the (empty) Lookup History as JSON
- [ ] The home page renders the empty Lookup History with an empty-state message
- [ ] An example env file, committed, lists every Source API key with no values; `.env` is git-ignored
- [ ] Time is read from an injected clock that tests can control
- [ ] Backend test harness: JUnit 5 and AssertJ, Spring Boot integration tests over real HTTP, PostgreSQL via Testcontainers, WireMock available for faking Sources. One passing integration test covers the empty `GET /api/lookups`
- [ ] Frontend test harness: Vitest, React Testing Library and MSW. One passing test covers the empty-state home page
- [ ] GitHub Actions runs the Maven build (backend tests) and the frontend tests on every push
- [ ] MIT `LICENSE` file and a minimal README with run instructions
