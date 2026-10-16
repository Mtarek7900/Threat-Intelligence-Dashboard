import type { IndicatorType, Verdict } from './api/lookups'

export const indicatorTypeLabels: Record<IndicatorType, string> = {
  IP_ADDRESS: 'IP address',
  DOMAIN: 'Domain',
  FILE_HASH: 'File hash',
}

export const verdictLabels: Record<Verdict, string> = {
  MALICIOUS: 'Malicious',
  SUSPICIOUS: 'Suspicious',
  CLEAN: 'Clean',
  UNKNOWN: 'Unknown',
}

export const verdictStyles: Record<Verdict, string> = {
  MALICIOUS: 'border-red-300 bg-red-50 text-red-900',
  SUSPICIOUS: 'border-amber-300 bg-amber-50 text-amber-900',
  CLEAN: 'border-emerald-300 bg-emerald-50 text-emerald-900',
  UNKNOWN: 'border-slate-300 bg-slate-100 text-slate-800',
}

/** E.g. "2026-01-14 08:30 UTC": the same for every Analyst, whatever their time zone. */
export function formatUtc(instant: string) {
  return new Date(instant).toISOString().slice(0, 16).replace('T', ' ') + ' UTC'
}
