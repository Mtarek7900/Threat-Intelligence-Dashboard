import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { beforeEach, expect, test } from 'vitest'
import type { NewerResults } from './api/lookups'
import { server } from './test/server'
import { App } from './App'

function lookup(id: string, verdict: string, lookedUpAt: string, newerResults?: NewerResults) {
  return {
    id,
    indicator: '185.220.101.1',
    indicatorType: 'IP_ADDRESS',
    verdict,
    partial: false,
    sourcesNotChecked: [],
    why: [`VirusTotal gave a ${verdict} reading.`],
    sourcesAsked: ['VirusTotal'],
    sourceResults: [
      {
        source: 'VirusTotal',
        outcome: 'SEEN',
        notCheckedReason: null,
        signal: 'NONE',
        facts: { enginesFlagged: 0, enginesTotal: 94, lastAnalysedAt: lookedUpAt },
        link: 'https://www.virustotal.com/gui/ip-address/185.220.101.1',
        fetchedAt: lookedUpAt,
        reused: false,
        rawResponse: '{}',
      },
    ],
    lookedUpAt,
    ...(newerResults && { newerResults }),
  }
}

const entries = [
  { id: 'new', indicator: '185.220.101.1', indicatorType: 'IP_ADDRESS', verdict: 'CLEAN', lookedUpAt: '2026-01-15T11:00:00Z' },
  { id: 'old', indicator: '185.220.101.1', indicatorType: 'IP_ADDRESS', verdict: 'MALICIOUS', lookedUpAt: '2026-01-15T10:00:00Z' },
]

beforeEach(() => {
  server.use(
    http.get('/api/lookups', () =>
      HttpResponse.json([
        { indicator: '185.220.101.1', indicatorType: 'IP_ADDRESS', count: 2, latest: entries[0], lookups: entries },
      ]),
    ),
  )
})

async function openOldLookup() {
  render(<App />)
  const list = within(await screen.findByRole('list', { name: 'Lookup History' }))
  await userEvent.click(list.getByRole('button', { name: 'Show all 2 Lookups of 185.220.101.1' }))
  const lookups = within(list.getByRole('list', { name: 'Lookups of 185.220.101.1' }))
  await userEvent.click(lookups.getByRole('button', { name: /2026-01-15 10:00 UTC/ }))
  return screen.findByRole('region', { name: 'Lookup' })
}

test('a past Lookup with newer Source Results shows a banner with the newer Verdict and when it was reached', async () => {
  server.use(
    http.get('/api/lookups/old', () =>
      HttpResponse.json(
        lookup('old', 'MALICIOUS', '2026-01-15T10:00:00Z', {
          lookupId: 'new',
          verdict: 'CLEAN',
          lookedUpAt: '2026-01-15T11:00:00Z',
        }),
      ),
    ),
  )

  const result = await openOldLookup()

  const banner = within(result).getByRole('note', { name: 'Newer Source Results' })
  expect(banner).toHaveTextContent('Newer Source Results exist for this Indicator')
  expect(banner).toHaveTextContent('Clean')
  expect(banner).toHaveTextContent('2026-01-15 11:00 UTC')
})

test('a past Lookup without newer Source Results shows no banner', async () => {
  server.use(http.get('/api/lookups/old', () => HttpResponse.json(lookup('old', 'MALICIOUS', '2026-01-15T10:00:00Z'))))

  const result = await openOldLookup()

  expect(within(result).queryByRole('note', { name: 'Newer Source Results' })).not.toBeInTheDocument()
})

test('the banner opens the newer Lookup in one click', async () => {
  server.use(
    http.get('/api/lookups/old', () =>
      HttpResponse.json(
        lookup('old', 'MALICIOUS', '2026-01-15T10:00:00Z', {
          lookupId: 'new',
          verdict: 'CLEAN',
          lookedUpAt: '2026-01-15T11:00:00Z',
        }),
      ),
    ),
    http.get('/api/lookups/new', () => HttpResponse.json(lookup('new', 'CLEAN', '2026-01-15T11:00:00Z'))),
  )

  const result = await openOldLookup()
  await userEvent.click(within(result).getByRole('button', { name: 'Open the newer Lookup' }))

  const newer = await screen.findByRole('region', { name: 'Lookup' })
  await within(newer).findByText('2026-01-15 11:00 UTC')
  expect(within(newer).getByText('Looked up').nextElementSibling).toHaveTextContent('2026-01-15 11:00 UTC')
  expect(newer).toHaveTextContent('Clean')
  expect(within(newer).queryByRole('note', { name: 'Newer Source Results' })).not.toBeInTheDocument()
})
