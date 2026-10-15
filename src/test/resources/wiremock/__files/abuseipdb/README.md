# AbuseIPDB responses

AbuseIPDB v2 `check` responses, served by WireMock (see `FakeAbuseIpdb`).

Recorded from the real API on 2026-10-15, except `rate-limited.json`: a free key allows 1,000 checks a day, so that one is hand-written to AbuseIPDB's documented 429 format.

| File | Request | Answer |
| --- | --- | --- |
| `high-confidence.json` | `GET /api/v2/check?ipAddress=185.220.101.1&maxAgeInDays=90` | 200, confidence 100%, 425 reports |
| `low-confidence.json` | `GET /api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90` | 200, confidence 0%, 238 reports |
| `suspicious-confidence.json` | `GET /api/v2/check?ipAddress=118.193.40.10&maxAgeInDays=90` | 200, confidence 66%, 19 reports |
| `whitelisted.json` | `GET /api/v2/check?ipAddress=9.9.9.9&maxAgeInDays=90` | 200, confidence 0%, 54 reports, whitelisted |
| `no-reports.json` | `GET /api/v2/check?ipAddress=203.0.114.7&maxAgeInDays=90` | 200, no reports |
| `rate-limited.json` | any | 429 (hand-written) |

To record, send the request with headers `Key: <your key>` and `Accept: application/json` and save the body unchanged.
