# 02: Indicator input and validation

**What to build:** The Analyst pastes a value into an input box on the home page. If it's a valid IP address, domain or file hash (defanged or not), a Lookup is created and shown with the normalised Indicator and its Indicator Type. The Verdict is Unknown, because no Sources exist yet. Invalid input gets a clear message saying what's wrong. Spec user stories 1–10.

**Blocked by:** 01 (Walking skeleton)

**Status:** done

- [x] A pure Indicator parsing module turns raw text into either a normalised Indicator with its Indicator Type, or a rejection reason
- [x] Refanging handles `[.]`, `(.)`, `[dot]`, `hxxp`/`hxxps` and `[:]`; whitespace is trimmed; domains and hashes are lower-cased
- [x] IPv4 and IPv6 are accepted; private, loopback, link-local and other reserved ranges are rejected with a message
- [x] MD5, SHA-1 and SHA-256 hashes are detected by length and hex characters
- [x] URLs get a specific "URLs aren't supported yet" rejection; anything else unrecognised gets a message listing what is accepted
- [x] Table-driven JUnit tests cover every refang pattern, reserved range, hash length and edge-case domain
- [x] `POST /api/lookups` with valid input stores and returns a Lookup (normalised Indicator, Indicator Type, Verdict Unknown, timestamp); invalid input returns 400 with the rejection reason
- [x] Integration tests at the REST API cover a few representative accepted and rejected inputs
- [x] The home page has the input box; submitting shows the result (normalised Indicator, Type, Verdict) or the rejection message; frontend tests cover both
