import { useId } from 'react'
import type { IndicatorType, Lookup, NotCheckedReason, OtxFacts, Outcome, SourceResult, Verdict } from './api/lookups'

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

const verdictStyles: Record<Verdict, string> = {
  MALICIOUS: 'border-red-300 bg-red-50 text-red-900',
  SUSPICIOUS: 'border-amber-300 bg-amber-50 text-amber-900',
  CLEAN: 'border-emerald-300 bg-emerald-50 text-emerald-900',
  UNKNOWN: 'border-slate-300 bg-slate-100 text-slate-800',
}

const outcomeLabels: Record<Outcome, string> = {
  SEEN: 'Seen',
  NOT_SEEN: 'Not Seen',
  NOT_CHECKED: 'Not Checked',
}

const notCheckedReasonLabels: Record<NotCheckedReason, string> = {
  TIMEOUT: 'timed out',
  SOURCE_ERROR: 'Source error',
  RATE_LIMITED: 'rate limited',
  MISSING_API_KEY: 'missing API key',
}

/** @param onRefresh asks every Source about the Indicator again, however recent its Source Result */
export function LookupResult({ lookup, onRefresh }: { lookup: Lookup; onRefresh: () => void }) {
  return (
    <section aria-label="Lookup" className="mt-3 space-y-4">
      <div className="rounded-lg border border-slate-200 bg-white p-6">
        <div className="flex items-start justify-between gap-4">
          <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2">
            <dt className="text-slate-500">Indicator</dt>
            <dd className="font-mono break-all text-slate-900">{lookup.indicator}</dd>
            <dt className="text-slate-500">Type</dt>
            <dd className="text-slate-900">{indicatorTypeLabels[lookup.indicatorType]}</dd>
          </dl>
          <button
            type="button"
            onClick={onRefresh}
            title="Ask every Source again, however recent its Source Result"
            className="rounded-lg border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-800 hover:bg-slate-50"
          >
            Refresh
          </button>
        </div>

        <div className={`mt-4 rounded-lg border px-4 py-3 ${verdictStyles[lookup.verdict]}`}>
          <p className="text-sm">Verdict</p>
          <p className="text-2xl font-semibold">{verdictLabels[lookup.verdict]}</p>
          {lookup.partial && (
            <p className="mt-1 text-sm">
              Partial Verdict: {lookup.sourcesNotChecked.join(', ')}{' '}
              {lookup.sourcesNotChecked.length === 1 ? 'was' : 'were'} Not Checked
            </p>
          )}
        </div>

        <section aria-labelledby="why" className="mt-4">
          <h2 id="why" className="font-medium text-slate-800">
            Why?
          </h2>
          <ul className="mt-1 list-disc pl-5 text-slate-700">
            {lookup.why.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </section>

        <p className="mt-4 text-sm text-slate-500">Sources asked: {lookup.sourcesAsked.join(', ')}</p>
      </div>

      {lookup.sourceResults.map((result) => (
        <SourcePanel key={result.source} result={result} />
      ))}
    </section>
  )
}

function SourcePanel({ result }: { result: SourceResult }) {
  const headingId = useId()
  return (
    <section aria-labelledby={headingId} className="rounded-lg border border-slate-200 bg-white p-6">
      <div className="flex items-baseline justify-between gap-4">
        <h2 id={headingId} className="font-medium text-slate-900">
          {result.source}
        </h2>
        <span className="rounded-full bg-slate-100 px-2 py-0.5 text-sm text-slate-700">
          {outcomeLabels[result.outcome]}
          {result.notCheckedReason && `: ${notCheckedReasonLabels[result.notCheckedReason]}`}
        </span>
      </div>

      <p className="mt-1 text-sm text-slate-500">
        Fetched {formatUtc(result.fetchedAt)}
        {result.reused && (
          <span
            title="An earlier Lookup fetched this Source Result, so the Source wasn't asked again"
            className="ml-2 rounded-full bg-sky-50 px-2 py-0.5 text-sky-800"
          >
            Reused
          </span>
        )}
      </p>

      <SourceFacts result={result} />

      <a
        href={result.link}
        target="_blank"
        rel="noreferrer"
        className="mt-2 inline-block text-sm text-slate-900 underline hover:text-slate-600"
      >
        Open in {result.source}
      </a>

      {result.rawResponse !== null && (
        <details className="mt-3 text-sm">
          <summary className="cursor-pointer text-slate-500">Raw response</summary>
          <pre className="mt-2 max-h-96 overflow-auto rounded bg-slate-50 p-3 text-xs text-slate-800">
            {prettyJson(result.rawResponse)}
          </pre>
        </details>
      )}
    </section>
  )
}

/** The key facts each Source reported, when it has Seen the Indicator. */
function SourceFacts({ result }: { result: SourceResult }) {
  switch (result.source) {
    case 'VirusTotal':
      return (
        result.facts && (
          <ul className="mt-2 text-slate-700">
            <li>
              {result.facts.enginesFlagged} of {result.facts.enginesTotal} engines flagged it
            </li>
            <li>Last analysed {formatUtc(result.facts.lastAnalysedAt)}</li>
          </ul>
        )
      )
    case 'AbuseIPDB':
      return (
        result.facts && (
          <ul className="mt-2 text-slate-700">
            <li>
              Abuse confidence {result.facts.abuseConfidence}% from{' '}
              {result.facts.totalReports.toLocaleString('en')} reports
            </li>
            {result.facts.countryCode && <li>Country {countryName(result.facts.countryCode)}</li>}
            {result.facts.isp && <li>ISP {result.facts.isp}</li>}
          </ul>
        )
      )
    case 'AlienVault OTX':
      return result.facts && <OtxPulses facts={result.facts} />
  }
}

/** Tags shown per pulse: some pulses carry dozens. */
const TAGS_SHOWN = 8

function OtxPulses({ facts: { pulseCount, pulses } }: { facts: OtxFacts }) {
  return (
    <div className="mt-2 text-slate-700">
      <p>
        In {pulseCount.toLocaleString('en')} {pulseCount === 1 ? 'pulse' : 'pulses'}
        {pulses.length < pulseCount && `, ${pulses.length} of them listed here`}
      </p>
      <ul className="mt-2 max-h-80 space-y-2 overflow-auto">
        {pulses.map((pulse, index) => (
          <li key={index}>
            <p className="text-slate-900">{pulse.name}</p>
            {pulse.tags.length > 0 && (
              <p className="mt-1 flex flex-wrap gap-1 text-xs">
                {pulse.tags.slice(0, TAGS_SHOWN).map((tag, tagIndex) => (
                  <span key={tagIndex} className="rounded bg-slate-100 px-1.5 py-0.5 text-slate-600">
                    {tag}
                  </span>
                ))}
                {pulse.tags.length > TAGS_SHOWN && (
                  <span className="px-1.5 py-0.5 text-slate-500">+{pulse.tags.length - TAGS_SHOWN} more</span>
                )}
              </p>
            )}
          </li>
        ))}
      </ul>
    </div>
  )
}

/** E.g. "Germany (DE)", or just the code if the browser doesn't know it. */
function countryName(code: string) {
  const name = new Intl.DisplayNames(['en'], { type: 'region' }).of(code)
  return name && name !== code ? `${name} (${code})` : code
}

/** E.g. "2026-01-14 08:30 UTC": the same for every Analyst, whatever their time zone. */
function formatUtc(instant: string) {
  return new Date(instant).toISOString().slice(0, 16).replace('T', ' ') + ' UTC'
}

function prettyJson(raw: string) {
  try {
    return JSON.stringify(JSON.parse(raw), null, 2)
  } catch {
    return raw
  }
}
