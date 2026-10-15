import type { IndicatorType, Lookup, NotCheckedReason, Outcome, SourceResult, Verdict } from './api/lookups'

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

export function LookupResult({ lookup }: { lookup: Lookup }) {
  return (
    <section aria-label="Lookup" className="mt-3 space-y-4">
      <div className="rounded-lg border border-slate-200 bg-white p-6">
        <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2">
          <dt className="text-slate-500">Indicator</dt>
          <dd className="font-mono break-all text-slate-900">{lookup.indicator}</dd>
          <dt className="text-slate-500">Type</dt>
          <dd className="text-slate-900">{indicatorTypeLabels[lookup.indicatorType]}</dd>
        </dl>

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
  const headingId = `source-${result.source}`
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
  }
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
