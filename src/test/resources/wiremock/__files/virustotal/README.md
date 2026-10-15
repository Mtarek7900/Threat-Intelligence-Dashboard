# VirusTotal recordings

Real VirusTotal v3 API responses, recorded once on 2026-10-15 with a free-tier key and served by WireMock (see `FakeVirusTotal`). They hold no account details. The WHOIS/RDAP contacts in them are public registry data.

| File | Request | Answer |
| --- | --- | --- |
| `ip-address-malicious.json` | `GET /api/v3/ip_addresses/185.220.101.1` | 200, 15 of 92 engines malicious |
| `ip-address-clean.json` | `GET /api/v3/ip_addresses/9.9.9.9` | 200, 0 engines malicious (1 suspicious) |
| `domain-clean.json` | `GET /api/v3/domains/example.com` | 200, 0 engines malicious |
| `file-not-found.json` | `GET /api/v3/files/9f2c…0d2e` | 404 `NotFoundError` |
| `domain-not-found.json` | `GET /api/v3/domains/tid-fixture-q8v3x1k9z2w7.com` | 404 `NotFoundError` |

Two files are exceptions and were **written by hand**:

- `rate-limited.json` follows VirusTotal's documented `429 QuotaExceededError` body. A burst of requests on the free tier wasn't rate-limited when recording, so a real one couldn't be captured.
- `ip-address-never-analysed.json`: VirusTotal analyses an IP address as soon as it is asked about one, so this answer (known, but with no `last_analysis_date`) couldn't be recorded on demand. The adapter still treats it as Not Seen, so that an Indicator nobody has analysed is never shown as Clean.

To re-record, request the same paths with an `x-apikey` header and save each body unchanged under the same file name. The free tier allows 4 requests a minute.
