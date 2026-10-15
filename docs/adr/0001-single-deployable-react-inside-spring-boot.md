# Single deployable: React bundled inside the Spring Boot jar

The React (TypeScript + Vite) frontend lives in `frontend/` and is built by Maven into the Spring Boot jar's static resources, so one container serves both the UI and the REST API from the same origin. Because they share an origin, sign-in (added with hosting, after the local-first MVP) will use Spring Security's server-side session cookie after GitHub OAuth. There will be no JWTs and no CORS configuration. We chose this over hosting the frontend separately (e.g. Vercel plus an API host): that layout would need cross-origin auth and token handling, a whole class of bugs that adds nothing to a single-person portfolio app.

## Consequences

- Moving the frontend to a separate host later means introducing CORS and token-based auth. It's not just a deploy change.
- During local development the Vite dev server proxies `/api` and auth routes to Spring Boot, so the browser still sees one origin.
