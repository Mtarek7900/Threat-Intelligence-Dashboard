import { useEffect, useRef, useState } from 'react'
import {
  fetchLookup,
  fetchLookupHistory,
  makeLookup,
  type Lookup,
  type LookupHistoryGroup,
  type LookupOutcome,
} from './api/lookups'
import { LookupForm } from './LookupForm'
import { LookupHistory } from './LookupHistory'
import { LookupResult } from './LookupResult'

type HistoryState =
  | { status: 'loading' }
  | { status: 'loaded'; groups: LookupHistoryGroup[] }
  | { status: 'failed' }

type LookupState =
  | { status: 'idle' }
  | { status: 'looking-up' }
  | { status: 'opening' }
  | LookupOutcome
  | { status: 'failed' }
  | { status: 'open-failed' }

/** A Refresh keeps the Lookup on screen until the new one arrives, and after it fails. */
type RefreshState = 'idle' | 'refreshing' | 'failed'

export function HomePage() {
  const [history, setHistory] = useState<HistoryState>({ status: 'loading' })
  // Bumped whenever a Lookup is made, so the Lookup History is fetched again and shows it
  const [historyVersion, setHistoryVersion] = useState(0)
  const [state, setState] = useState<LookupState>({ status: 'idle' })
  const [refresh, setRefresh] = useState<RefreshState>('idle')
  // Only the most recent request may change what's on screen, however its answers arrive
  const latestRequest = useRef(0)

  useEffect(() => {
    let ignore = false
    fetchLookupHistory()
      .then((groups) => !ignore && setHistory({ status: 'loaded', groups }))
      .catch(() => !ignore && setHistory({ status: 'failed' }))
    return () => {
      ignore = true
    }
  }, [historyVersion])

  /** Runs a request, applying its outcome only if no later request has started since. */
  async function request<T>(send: () => Promise<T>, onDone: (result: T) => void, onFailed: () => void) {
    const id = ++latestRequest.current
    try {
      const result = await send()
      if (id === latestRequest.current) onDone(result)
    } catch {
      if (id === latestRequest.current) onFailed()
    }
  }

  function lookUp(input: string) {
    setState({ status: 'looking-up' })
    setRefresh('idle')
    request(
      () => makeLookup(input),
      (outcome) => {
        setState(outcome)
        if (outcome.status === 'made') setHistoryVersion((version) => version + 1)
      },
      () => setState({ status: 'failed' }),
    )
  }

  function refreshLookup(lookup: Lookup) {
    setRefresh('refreshing')
    request(
      () => makeLookup(lookup.indicator, { refresh: true }),
      (outcome) => {
        setState(outcome)
        setRefresh('idle')
        setHistoryVersion((version) => version + 1)
      },
      () => setRefresh('failed'),
    )
  }

  function open(id: string) {
    setState({ status: 'opening' })
    setRefresh('idle')
    request(
      () => fetchLookup(id),
      (lookup) => setState({ status: 'made', lookup }),
      () => setState({ status: 'open-failed' }),
    )
  }

  return (
    <main className="mx-auto max-w-3xl px-4 py-10">
      <h1 className="text-2xl font-semibold text-slate-900">Threat Intelligence Dashboard</h1>

      <section className="mt-8">
        <LookupForm onLookUp={lookUp} lookingUp={state.status === 'looking-up'} />

        {state.status === 'looking-up' && (
          <p role="status" className="mt-3 text-slate-600">
            Asking the Sources…
          </p>
        )}
        {state.status === 'opening' && (
          <p role="status" className="mt-3 text-slate-600">
            Opening the Lookup…
          </p>
        )}
        {state.status === 'rejected' && (
          <p role="alert" className="mt-3 rounded-lg border border-amber-300 bg-amber-50 px-4 py-3 text-amber-900">
            {state.message}
          </p>
        )}
        {state.status === 'failed' && (
          <p role="alert" className="mt-3 rounded-lg border border-red-300 bg-red-50 px-4 py-3 text-red-900">
            The Lookup failed. Is the server running?
          </p>
        )}
        {state.status === 'open-failed' && (
          <p role="alert" className="mt-3 rounded-lg border border-red-300 bg-red-50 px-4 py-3 text-red-900">
            Couldn't open that Lookup. Is the server running?
          </p>
        )}
        {state.status === 'made' && refresh === 'refreshing' && (
          <p role="status" className="mt-3 text-slate-600">
            Asking the Sources again…
          </p>
        )}
        {state.status === 'made' && refresh === 'failed' && (
          <p role="alert" className="mt-3 rounded-lg border border-red-300 bg-red-50 px-4 py-3 text-red-900">
            The Refresh failed, so this is still the earlier Lookup. Is the server running?
          </p>
        )}
        {state.status === 'made' && (
          <LookupResult
            lookup={state.lookup}
            refreshing={refresh === 'refreshing'}
            onRefresh={() => refreshLookup(state.lookup)}
          />
        )}
      </section>

      <section className="mt-8">
        <h2 className="text-lg font-medium text-slate-800">Lookup History</h2>
        <div className="mt-3 rounded-lg border border-slate-200 bg-white p-4 text-slate-600">
          {history.status === 'loading' && <p>Loading Lookup History…</p>}
          {history.status === 'failed' && <p>Couldn't load the Lookup History. Is the server running?</p>}
          {history.status === 'loaded' && history.groups.length === 0 && (
            <p>No Lookups yet. Lookups you make will appear here, most recent first.</p>
          )}
          {history.status === 'loaded' && history.groups.length > 0 && (
            <LookupHistory groups={history.groups} onOpen={open} />
          )}
        </div>
      </section>
    </main>
  )
}
