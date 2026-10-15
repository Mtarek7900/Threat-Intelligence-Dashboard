import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { beforeEach, expect, test } from 'vitest'
import { server } from './test/server'
import { App } from './App'

const virusTotal = {
  source: 'VirusTotal',
  outcome: 'SEEN',
  notCheckedReason: null,
  signal: 'MALICIOUS',
  facts: { enginesFlagged: 15, enginesTotal: 92, lastAnalysedAt: '2026-10-15T18:44:02Z' },
  link: 'https://www.virustotal.com/gui/ip-address/185.220.101.1',
  fetchedAt: '2026-01-15T10:00:00Z',
  rawResponse: '{}',
}

const abuseIpdb = {
  source: 'AbuseIPDB',
  outcome: 'SEEN',
  notCheckedReason: null,
  signal: 'MALICIOUS',
  facts: { abuseConfidence: 100, totalReports: 425, countryCode: 'DE', isp: 'Artikel10 e.V.' },
  link: 'https://www.abuseipdb.com/check/185.220.101.1',
  fetchedAt: '2026-01-15T10:00:00Z',
  rawResponse: '{"data":{"abuseConfidenceScore":100}}',
}

function ipLookup(sourceResults: object[]) {
  return {
    id: '6f1c2a9e-0000-4000-8000-000000000004',
    indicator: '185.220.101.1',
    indicatorType: 'IP_ADDRESS',
    verdict: 'MALICIOUS',
    partial: false,
    sourcesNotChecked: [],
    why: [
      'VirusTotal: 15 of 92 engines flagged it. 3 or more is Malicious.',
      'AbuseIPDB: abuse confidence 100%. 75% or more is Malicious.',
    ],
    sourcesAsked: ['VirusTotal', 'AbuseIPDB'],
    sourceResults,
    lookedUpAt: '2026-01-15T10:00:00Z',
  }
}

beforeEach(() => {
  server.use(http.get('/api/lookups', () => HttpResponse.json([])))
})

async function lookUp(lookup: object) {
  server.use(http.post('/api/lookups', () => HttpResponse.json(lookup, { status: 201 })))
  render(<App />)
  await userEvent.click(screen.getByLabelText('Indicator'))
  await userEvent.paste('185.220.101.1')
  await userEvent.click(screen.getByRole('button', { name: 'Look up' }))
  return screen.findByRole('region', { name: 'Lookup' })
}

test('the AbuseIPDB panel shows the abuse confidence, reports, country and ISP', async () => {
  const result = await lookUp(ipLookup([virusTotal, abuseIpdb]))

  const panel = within(result).getByRole('region', { name: 'AbuseIPDB' })
  expect(panel).toHaveTextContent('Seen')
  expect(panel).toHaveTextContent('Abuse confidence 100%')
  expect(panel).toHaveTextContent('425 reports')
  expect(panel).toHaveTextContent('Country Germany (DE)')
  expect(panel).toHaveTextContent('ISP Artikel10 e.V.')
  expect(within(panel).getByRole('link', { name: /open in abuseipdb/i })).toHaveAttribute(
    'href',
    'https://www.abuseipdb.com/check/185.220.101.1',
  )
  expect(within(panel).getByText('Raw response')).toBeInTheDocument()
})

test('an IP address Lookup shows a panel for each Source asked', async () => {
  const result = await lookUp(ipLookup([virusTotal, abuseIpdb]))

  expect(result).toHaveTextContent('Sources asked: VirusTotal, AbuseIPDB')
  expect(within(result).getByRole('region', { name: 'VirusTotal' })).toHaveTextContent('15 of 92 engines flagged it')
  expect(within(result).getByRole('region', { name: 'AbuseIPDB' })).not.toHaveTextContent('engines flagged it')
})

test('the AbuseIPDB panel says when nobody has reported the IP address', async () => {
  const result = await lookUp(ipLookup([virusTotal, { ...abuseIpdb, outcome: 'NOT_SEEN', signal: 'NONE', facts: null }]))

  const panel = within(result).getByRole('region', { name: 'AbuseIPDB' })
  expect(panel).toHaveTextContent('Not Seen')
  expect(panel).not.toHaveTextContent('Abuse confidence')
})
