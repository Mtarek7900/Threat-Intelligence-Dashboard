# Threat Intelligence Dashboard

Paste an IP address, domain or file hash and get one Verdict (Malicious, Suspicious, Clean or Unknown) drawn from VirusTotal, AbuseIPDB and AlienVault OTX, with every Lookup kept in a Lookup History.

> Work in progress: the local-first MVP is being built ticket by ticket (see `.scratch/local-mvp/`).

## Run it

Needs [Docker Desktop](https://www.docker.com/products/docker-desktop/) running.

```sh
cp .env.example .env   # optional: add the Source API keys you have
docker compose up
```

Open http://localhost:8080. The database schema is created on start-up. After pulling new code, run `docker compose up --build` to rebuild the app.

## Develop

Needs Java 21 and Node 22.12+ (see `frontend/.nvmrc`). Maven comes with the wrapper.

```sh
docker compose up db          # PostgreSQL only
./mvnw spring-boot:run        # API on http://localhost:8080
cd frontend && npm ci && npm run dev   # UI with hot reload on http://localhost:5173, proxies /api
```

## Test

```sh
./mvnw verify                 # backend tests; Testcontainers needs Docker running
cd frontend && npm test       # frontend tests
```

## Tech stack

Spring Boot 3, Java 21, PostgreSQL, Flyway · React, TypeScript, Vite, Tailwind · JUnit 5, AssertJ, Testcontainers, WireMock · Vitest, React Testing Library, MSW · Docker Compose, GitHub Actions.

## Licence

[MIT](LICENSE)
