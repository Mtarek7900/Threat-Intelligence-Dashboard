export type LookupHistoryEntry = {
  id: string
  indicator: string
  indicatorType: IndicatorType
  verdict: Verdict
  lookedUpAt: string
}

export async function fetchLookupHistory(): Promise<LookupHistoryEntry[]> {
  const response = await fetch('/api/lookups')
  if (!response.ok) {
    throw new Error(`GET /api/lookups failed with ${response.status}`)
  }
  return response.json()
}

export type IndicatorType = 'IP_ADDRESS' | 'DOMAIN' | 'FILE_HASH'

export type Verdict = 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNKNOWN'

export type Outcome = 'SEEN' | 'NOT_SEEN' | 'NOT_CHECKED'

export type NotCheckedReason = 'TIMEOUT' | 'SOURCE_ERROR' | 'RATE_LIMITED' | 'MISSING_API_KEY'

export type Signal = 'MALICIOUS' | 'SUSPICIOUS' | 'NONE'

export type VirusTotalFacts = {
  enginesFlagged: number
  enginesTotal: number
  lastAnalysedAt: string
}

export type AbuseIpdbFacts = {
  abuseConfidence: number
  totalReports: number
  countryCode: string | null
  isp: string | null
}

export type OtxFacts = {
  pulseCount: number
  /** The pulses OTX listed, which can be fewer than `pulseCount`. */
  pulses: { name: string; tags: string[] }[]
}

/**
 * A Source Result the Lookup used. `facts` is null unless the Source has Seen the Indicator;
 * `notCheckedReason` is null and `rawResponse` present unless it was Not Checked.
 */
export type SourceResult = {
  outcome: Outcome
  notCheckedReason: NotCheckedReason | null
  signal: Signal
  link: string
  fetchedAt: string
  rawResponse: string | null
} & (
  | { source: 'VirusTotal'; facts: VirusTotalFacts | null }
  | { source: 'AbuseIPDB'; facts: AbuseIpdbFacts | null }
  | { source: 'AlienVault OTX'; facts: OtxFacts | null }
)

export type Lookup = {
  id: string
  indicator: string
  indicatorType: IndicatorType
  verdict: Verdict
  partial: boolean
  sourcesNotChecked: string[]
  why: string[]
  sourcesAsked: string[]
  sourceResults: SourceResult[]
  lookedUpAt: string
}

export type LookupOutcome = { status: 'made'; lookup: Lookup } | { status: 'rejected'; message: string }

/** Rejected input isn't an error: the server's message tells the Analyst what to fix. */
export async function makeLookup(input: string): Promise<LookupOutcome> {
  const response = await fetch('/api/lookups', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ input }),
  })
  if (response.status === 400) {
    const problem: { detail: string } = await response.json()
    return { status: 'rejected', message: problem.detail }
  }
  if (!response.ok) {
    throw new Error(`POST /api/lookups failed with ${response.status}`)
  }
  return { status: 'made', lookup: await response.json() }
}
