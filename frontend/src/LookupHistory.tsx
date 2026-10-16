import { useState } from 'react'
import type { LookupHistoryGroup, Verdict } from './api/lookups'
import { formatUtc, indicatorTypeLabels, verdictLabels, verdictStyles } from './labels'

/**
 * The Lookup History, one entry per Indicator with its latest Lookup, most recent first.
 *
 * @param onOpen shows that past Lookup as it was made
 */
export function LookupHistory({ groups, onOpen }: { groups: LookupHistoryGroup[]; onOpen: (id: string) => void }) {
  return (
    <ul aria-label="Lookup History" className="divide-y divide-slate-200">
      {groups.map((group) => (
        <HistoryGroup key={`${group.indicatorType} ${group.indicator}`} group={group} onOpen={onOpen} />
      ))}
    </ul>
  )
}

function HistoryGroup({ group, onOpen }: { group: LookupHistoryGroup; onOpen: (id: string) => void }) {
  const [expanded, setExpanded] = useState(false)
  return (
    <li className="py-2 first:pt-0 last:pb-0">
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={() => onOpen(group.latest.id)}
          className="flex min-w-0 flex-1 flex-wrap items-center gap-x-3 gap-y-1 rounded-lg px-2 py-1.5 text-left hover:bg-slate-50"
        >
          <span className="font-mono break-all text-slate-900">{group.indicator}</span>
          <span className="text-sm text-slate-500">{indicatorTypeLabels[group.indicatorType]}</span>
          <VerdictBadge verdict={group.latest.verdict} />
          <span className="text-sm text-slate-500">{formatUtc(group.latest.lookedUpAt)}</span>
          {group.count > 1 && (
            <span
              title={`Looked up ${group.count} times`}
              className="rounded-full bg-slate-900 px-2 py-0.5 text-xs font-medium text-white"
            >
              ×{group.count}
            </span>
          )}
        </button>
        {group.count > 1 && (
          <button
            type="button"
            onClick={() => setExpanded(!expanded)}
            aria-expanded={expanded}
            aria-label={`Show all ${group.count} Lookups of ${group.indicator}`}
            className="rounded-lg px-2 py-1.5 text-sm text-slate-600 hover:bg-slate-50"
          >
            Show all {group.count} <span aria-hidden="true">{expanded ? '▴' : '▾'}</span>
          </button>
        )}
      </div>
      {expanded && (
        <ul aria-label={`Lookups of ${group.indicator}`} className="mt-1 ml-4 border-l border-slate-200 pl-2">
          {group.lookups.map((lookup) => (
            <li key={lookup.id}>
              <button
                type="button"
                onClick={() => onOpen(lookup.id)}
                className="flex items-center gap-3 rounded-lg px-2 py-1 text-left hover:bg-slate-50"
              >
                <VerdictBadge verdict={lookup.verdict} />
                <span className="text-sm text-slate-500">{formatUtc(lookup.lookedUpAt)}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </li>
  )
}

/** The Verdict the Lookup reached at the time. */
function VerdictBadge({ verdict }: { verdict: Verdict }) {
  return (
    <span className={`rounded-full border px-2 py-0.5 text-xs font-medium ${verdictStyles[verdict]}`}>
      {verdictLabels[verdict]}
    </span>
  )
}
