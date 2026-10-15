# AbuseIPDB responses

AbuseIPDB v2 `check` responses, served by WireMock (see `FakeAbuseIpdb`).

**Not recorded yet.** There was no AbuseIPDB key when these were written, so they follow AbuseIPDB's documented v2 format. Replace each with a real response under the same file name once `ABUSEIPDB_API_KEY` is in `.env`.

| File | Request | Answer |
| --- | --- | --- |
| `high-confidence.json` | `GET /api/v2/check?ipAddress=185.220.101.1&maxAgeInDays=90` | 200, confidence 100%, 1,874 reports |
| `low-confidence.json` | `GET /api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90` | 200, confidence 0%, 63 reports |
| `suspicious-confidence.json` | `GET /api/v2/check?ipAddress=45.155.205.233&maxAgeInDays=90` | 200, confidence 40%, 9 reports |
| `no-reports.json` | `GET /api/v2/check?ipAddress=203.0.114.7&maxAgeInDays=90` | 200, no reports |
| `rate-limited.json` | any | 429 |

To record, send the request with headers `Key: <your key>` and `Accept: application/json` and save the body unchanged.
