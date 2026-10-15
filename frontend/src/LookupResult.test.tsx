import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { beforeEach, expect, test } from 'vitest'
import { server } from './test/server'
import { App } from './App'

const rawMalicious = JSON.stringify({
  data: { id: '185.220.101.1', type: 'ip_address', attributes: { last_analysis_stats: { malicious: 14 } } },
})

const maliciousLookup = {
  id: '6f1c2a9e-0000-4000-8000-000000000001',
  indicator: '185.220.101.1',
  indicatorType: 'IP_ADDRESS',
  verdict: 'MALICIOUS',
  why: ['VirusTotal: 14 of 94 engines flagged it. 3 or more is Malicious.'],
  sourcesAsked: ['VirusTotal'],
  sourceResults: [
    {
      source: 'VirusTotal',
      outcome: 'SEEN',
      signal: 'MALICIOUS',
      facts: { enginesFlagged: 14, enginesTotal: 94, lastAnalysedAt: '2026-01-14T08:30:00Z' },
      link: 'https://www.virustotal.com/gui/ip-address/185.220.101.1',
      fetchedAt: '2026-01-15T10:00:00Z',
      rawResponse: rawMalicious,
    },
  ],
  lookedUpAt: '2026-01-15T10:00:00Z',
}

const unknownLookup = {
  id: '6f1c2a9e-0000-4000-8000-000000000002',
  indicator: '9f2c4e1b7a5d3c8e6f0a2b4d6c8e0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d2e',
  indicatorType: 'FILE_HASH',
  verdict: 'UNKNOWN',
  why: ['VirusTotal has no record of it. No Signal.'],
  sourcesAsked: ['VirusTotal'],
  sourceResults: [
    {
      source: 'VirusTotal',
      outcome: 'NOT_SEEN',
      signal: 'NONE',
      facts: null,
      link: 'https://www.virustotal.com/gui/file/9f2c4e1b7a5d3c8e6f0a2b4d6c8e0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d2e',
      fetchedAt: '2026-01-15T10:00:00Z',
      rawResponse: '{"error":{"code":"NotFoundError","message":"File not found"}}',
    },
  ],
  lookedUpAt: '2026-01-15T10:00:00Z',
}

beforeEach(() => {
  server.use(http.get('/api/lookups', () => HttpResponse.json([])))
})

async function lookUp(lookup: object) {
  server.use(http.post('/api/lookups', () => HttpResponse.json(lookup, { status: 201 })))
  render(<App />)
  await userEvent.click(screen.getByLabelText('Indicator'))
  await userEvent.paste('anything')
  await userEvent.click(screen.getByRole('button', { name: 'Look up' }))
  return screen.findByRole('region', { name: 'Lookup' })
}

test('shows the Verdict and why the Sources led to it', async () => {
  const result = await lookUp(maliciousLookup)

  expect(within(result).getByText('Malicious')).toBeInTheDocument()
  const why = within(result).getByRole('region', { name: 'Why?' })
  expect(within(why).getAllByRole('listitem').map((item) => item.textContent)).toEqual([
    'VirusTotal: 14 of 94 engines flagged it. 3 or more is Malicious.',
  ])
})

test('says which Sources were asked', async () => {
  const result = await lookUp(maliciousLookup)

  expect(result).toHaveTextContent('Sources asked: VirusTotal')
})

test("the VirusTotal panel shows the engines that flagged it, when it was analysed and a link to VirusTotal's page", async () => {
  const result = await lookUp(maliciousLookup)

  const panel = within(result).getByRole('region', { name: 'VirusTotal' })
  expect(panel).toHaveTextContent('Seen')
  expect(panel).toHaveTextContent('14 of 94 engines flagged it')
  expect(panel).toHaveTextContent('Last analysed 2026-01-14 08:30 UTC')
  expect(within(panel).getByRole('link', { name: /open in virustotal/i })).toHaveAttribute(
    'href',
    'https://www.virustotal.com/gui/ip-address/185.220.101.1',
  )
})

test('the VirusTotal panel says when VirusTotal has Not Seen the Indicator', async () => {
  const result = await lookUp(unknownLookup)

  expect(within(result).getByText('Unknown')).toBeInTheDocument()
  const panel = within(result).getByRole('region', { name: 'VirusTotal' })
  expect(panel).toHaveTextContent('Not Seen')
  expect(panel).not.toHaveTextContent('engines flagged it')
  expect(within(panel).getByRole('link', { name: /open in virustotal/i })).toHaveAttribute(
    'href',
    unknownLookup.sourceResults[0].link,
  )
})

test("the Source's raw response is collapsed until the Analyst expands it", async () => {
  const result = await lookUp(maliciousLookup)

  const panel = within(result).getByRole('region', { name: 'VirusTotal' })
  const raw = within(panel).getByRole('group')
  expect(raw).not.toHaveAttribute('open')

  await userEvent.click(within(raw).getByText('Raw response'))

  expect(raw).toHaveAttribute('open')
  expect(within(raw).getByText(/"malicious": 14/)).toBeInTheDocument()
})
