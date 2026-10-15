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

export type Lookup = {
  id: string
  indicator: string
  indicatorType: IndicatorType
  verdict: Verdict
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
