import { useEffect, useState } from 'react'
import { fetchLookupHistory, type LookupHistoryEntry } from './api/lookups'

type HistoryState =
  | { status: 'loading' }
  | { status: 'loaded'; entries: LookupHistoryEntry[] }
  | { status: 'failed' }

export function HomePage() {
  const [history, setHistory] = useState<HistoryState>({ status: 'loading' })

  useEffect(() => {
    let ignore = false
    fetchLookupHistory()
      .then((entries) => !ignore && setHistory({ status: 'loaded', entries }))
      .catch(() => !ignore && setHistory({ status: 'failed' }))
    return () => {
      ignore = true
    }
  }, [])

  return (
    <main className="mx-auto max-w-3xl px-4 py-10">
      <h1 className="text-2xl font-semibold text-slate-900">Threat Intelligence Dashboard</h1>

      <section className="mt-8">
        <h2 className="text-lg font-medium text-slate-800">Lookup History</h2>
        <div className="mt-3 rounded-lg border border-slate-200 bg-white p-6 text-slate-600">
          {history.status === 'loading' && <p>Loading Lookup History…</p>}
          {history.status === 'failed' && <p>Couldn't load the Lookup History. Is the server running?</p>}
          {history.status === 'loaded' && history.entries.length === 0 && (
            <p>No Lookups yet. Lookups you make will appear here, most recent first.</p>
          )}
        </div>
      </section>
    </main>
  )
}
