# AlienVault OTX recordings

Real OTX v1 API responses, recorded on 2026-10-15 with a free key and served by WireMock (see `FakeOtx`). They hold no account details.

| File | Request | Answer |
| --- | --- | --- |
| `ip-address-pulses.json` | `GET /api/v1/indicators/IPv4/9.9.9.9/general` | 200, 50 pulses; OTX also lists it as a whitelisted IP |
| `ip-address-one-pulse.json` | `GET /api/v1/indicators/IPv4/118.193.40.10/general` | 200, 1 pulse |
| `ip-address-no-pulses.json` | `GET /api/v1/indicators/IPv4/203.0.114.7/general` | 200, no pulses |
| `ipv6-address-no-pulses.json` | `GET /api/v1/indicators/IPv6/2001:4860:4860::8888/general` | 200, no pulses |
| `domain-no-pulses.json` | `GET /api/v1/indicators/domain/tid-fixture-q8v3x1k9z2w7.com/general` | 200, no pulses |
| `hostname-no-pulses.json` | `GET /api/v1/indicators/hostname/www.tid-fixture-q8v3x1k9z2w7.com/general` | 200, no pulses |
| `file-no-pulses.json` | `GET /api/v1/indicators/file/9f2c…0d2e/general` | 200, no pulses |

Pulses are written by OTX members. In `ip-address-pulses.json`, two pulse names accused a named private person; that name is replaced with `[name redacted]`. Nothing else was changed.

To re-record, send the same requests with an `X-OTX-API-KEY` header and save each body unchanged under the same file name, redacting the same way if needed.
