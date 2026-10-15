import { useState, type FormEvent } from 'react'
import { makeLookup, type IndicatorType, type Lookup, type Verdict } from './api/lookups'

const indicatorTypeLabels: Record<IndicatorType, string> = {
  IP_ADDRESS: 'IP address',
  DOMAIN: 'Domain',
  FILE_HASH: 'File hash',
}

const verdictLabels: Record<Verdict, string> = {
  MALICIOUS: 'Malicious',
  SUSPICIOUS: 'Suspicious',
  CLEAN: 'Clean',
  UNKNOWN: 'Unknown',
}

type LookupState =
  | { status: 'idle' }
  | { status: 'looking-up' }
  | { status: 'made'; lookup: Lookup }
  | { status: 'rejected'; message: string }
  | { status: 'failed' }

export function LookupForm() {
  const [input, setInput] = useState('')
  const [state, setState] = useState<LookupState>({ status: 'idle' })

  async function submit(event: FormEvent) {
    event.preventDefault()
    setState({ status: 'looking-up' })
    try {
      setState(await makeLookup(input))
    } catch {
      setState({ status: 'failed' })
    }
  }

  return (
    <section className="mt-8">
      <form onSubmit={submit} className="flex gap-2">
        <label htmlFor="indicator" className="sr-only">
          Indicator
        </label>
        <input
          id="indicator"
          value={input}
          onChange={(event) => setInput(event.target.value)}
          placeholder="Paste an IP address, domain or file hash"
          autoComplete="off"
          spellCheck={false}
          className="flex-1 rounded-lg border border-slate-300 bg-white px-3 py-2 font-mono text-slate-900 focus:border-slate-500 focus:outline-none"
        />
        <button
          type="submit"
          disabled={state.status === 'looking-up'}
          className="rounded-lg bg-slate-900 px-4 py-2 font-medium text-white hover:bg-slate-700 disabled:opacity-50"
        >
          Look up
        </button>
      </form>

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
      {state.status === 'made' && (
        <section aria-label="Lookup" className="mt-3 rounded-lg border border-slate-200 bg-white p-6">
          <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2">
            <dt className="text-slate-500">Indicator</dt>
            <dd className="font-mono break-all text-slate-900">{state.lookup.indicator}</dd>
            <dt className="text-slate-500">Type</dt>
            <dd className="text-slate-900">{indicatorTypeLabels[state.lookup.indicatorType]}</dd>
            <dt className="text-slate-500">Verdict</dt>
            <dd className="font-semibold text-slate-900">{verdictLabels[state.lookup.verdict]}</dd>
          </dl>
        </section>
      )}
    </section>
  )
}
