export type LookupHistoryEntry = {
  id: string
  indicator: string
  indicatorType: string
  verdict: string
  lookedUpAt: string
}

export async function fetchLookupHistory(): Promise<LookupHistoryEntry[]> {
  const response = await fetch('/api/lookups')
  if (!response.ok) {
    throw new Error(`GET /api/lookups failed with ${response.status}`)
  }
  return response.json()
}
