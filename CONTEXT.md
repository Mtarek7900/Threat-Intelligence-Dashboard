# Threat Intelligence Dashboard

A tool that lets a SOC analyst look up a suspicious indicator and see what external threat-intelligence sources know about it.

## Language

**Analyst**:
A person who looks up Indicators, typically a SOC analyst triaging an alert. A local install has a single Analyst; a hosted one identifies each Analyst by their GitHub sign-in.
_Avoid_: User, customer, operator, account

**Indicator**:
An observable value that might point to malicious activity, such as an IP address, domain or file hash. Always held in its normalised form: refanged, trimmed, and lower-cased where case doesn't matter.
_Avoid_: IOC, artifact, observable, entity

**Defanged**:
Describes an Indicator written so it can't be clicked or resolved by accident, e.g. `1.2.3[.]4` or `hxxp://evil[.]com`. **Refanging** turns it back into the real value.
_Avoid_: Sanitised, escaped, neutered

**Indicator Type**:
The kind of an Indicator: IP address, domain or file hash. It is worked out from the value itself, not chosen by the Analyst.
_Avoid_: Kind, category, IOC type

**Lookup**:
One request by an Analyst to find out what is known about a single Indicator. A Lookup belongs to the Analyst who made it and keeps the Verdict and Source Results as they were at that moment; looking up the same Indicator again creates a new Lookup.
_Avoid_: Search, query, scan, check

**Lookup History**:
An Analyst's own past Lookups, most recent first. Repeated Lookups of the same Indicator are grouped under it with a count, but each is still kept and can be opened as it was. It is visible only to that Analyst.
_Avoid_: Recent searches, activity, log, feed

**Lookup Allowance**:
The number of Lookups that need fresh Source calls an Analyst may make per day. A Lookup answered entirely from recent Source Results doesn't use it up.
_Avoid_: Quota, credits, rate limit

## Intelligence

**Source**:
An external threat-intelligence service that the dashboard asks about Indicators: VirusTotal, AbuseIPDB or AlienVault OTX. Each Source covers certain Indicator Types and is asked only about those (AbuseIPDB covers IP addresses only).
_Avoid_: Provider, feed, vendor, integration, engine

**Source Result**:
What one Source reported about one Indicator at a specific time. Source Results are shared by all Analysts: a recent one is reused rather than asking the Source again. A Source Result is never changed or replaced; asking again creates a new one. Its outcome is one of: Seen, Not Seen or Not Checked.
_Avoid_: Response, report, finding, hit

**Not Checked**:
A Source Result outcome meaning the Source wasn't asked or couldn't answer (daily limit reached, timeout, outage). Distinct from Not Seen, where the Source answered and has no record of the Indicator.
_Avoid_: Failed, error, unavailable

**Signal**:
A Source Result's own reading of the Indicator: Malicious, Suspicious or none. A Signal from a Corroborating Source counts only when another Source also gives a Signal.
_Avoid_: Flag, detection, alert

**Corroborating Source**:
A Source whose Signal never decides the Verdict alone; it adds context and strengthens other Sources' Signals. AlienVault OTX is one.
_Avoid_: Secondary source, weak source

**Verdict**:
The dashboard's combined judgement on an Indicator, derived from its Source Results by a rule the Analyst can see: Malicious, Suspicious, Clean or Unknown. The worst counted Signal wins.
_Avoid_: Score, rating, risk, reputation

**Unknown**:
The Verdict when no Source has seen the Indicator. Distinct from Clean, which means at least one Source has seen it and none gave a Signal.
_Avoid_: Not found, none, neutral

**Partial Verdict**:
A Verdict reached while at least one Source was Not Checked. It is always shown with which Sources are missing.
_Avoid_: Incomplete result, degraded verdict
