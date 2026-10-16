# 10: "Newer results exist" banner

**What to build:** When the Analyst opens a past Lookup and newer Source Results exist for its Indicator, a banner says so and shows the newer Verdict and when it was reached. One click opens the current picture. Spec user stories 46 and 47.

**Blocked by:** 07 (Reuse of Source Results and Refresh), 08 (Lookup History and reopening a past Lookup)

**Status:** done

- [x] `GET /api/lookups/{id}` includes a "newer results" summary (newer Verdict and timestamp) when any Source has a Source Result for the Indicator newer than those the Lookup used, and omits it otherwise
- [x] Opening the newer picture shows the latest Lookup for the Indicator (or makes a new Lookup that reuses the latest Source Results, without using fresh Source calls)
- [x] Integration tests cover: no newer results means no banner; a refresh by a later Lookup produces the banner with the right Verdict
- [x] The Lookup screen shows the banner with the newer Verdict and a link; frontend tests cover banner present, banner absent and the link
