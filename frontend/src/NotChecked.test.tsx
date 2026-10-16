import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { delay, http, HttpResponse } from 'msw'
import { beforeEach, expect, test } from 'vitest'
import { server } from './test/server'
import { App } from './App'

function notCheckedLookup(notCheckedReason: string) {
  return {
    id: '6f1c2a9e-0000-4000-8000-000000000003',
    indicator: '185.220.101.1',
    indicatorType: 'IP_ADDRESS',
    verdict: 'UNKNOWN',
    partial: true,
    sourcesNotChecked: ['VirusTotal'],
    why: ["VirusTotal was Not Checked: it didn't answer in time."],
    sourcesAsked: ['VirusTotal'],
    sourceResults: [
      {
        source: 'VirusTotal',
        outcome: 'NOT_CHECKED',
        notCheckedReason,
        signal: 'NONE',
        facts: null,
        link: 'https://www.virustotal.com/gui/ip-address/185.220.101.1',
        fetchedAt: '2026-01-15T10:00:00Z',
        rawResponse: null,
      },
    ],
    lookedUpAt: '2026-01-15T10:00:00Z',
  }
}

beforeEach(() => {
  server.use(http.get('/api/lookups', () => HttpResponse.json([])))
})

async function submit() {
  render(<App />)
  await userEvent.click(screen.getByLabelText('Indicator'))
  await userEvent.paste('185.220.101.1')
  await userEvent.click(screen.getByRole('button', { name: 'Look up' }))
}

test('shows that the Sources are being asked while the Lookup is in progress', async () => {
  server.use(
    http.post('/api/lookups', async () => {
      await delay(50)
      return HttpResponse.json(notCheckedLookup('TIMEOUT'), { status: 201 })
    }),
  )

  await submit()

  expect(screen.getByRole('status')).toHaveTextContent('Asking the Sources…')
  expect(screen.getByRole('button', { name: 'Look up' })).toBeDisabled()
  await screen.findByRole('region', { name: 'Lookup' })
  expect(screen.queryByRole('status')).not.toBeInTheDocument()
})

test('a Partial Verdict is labelled with the Sources that were Not Checked', async () => {
  server.use(http.post('/api/lookups', () => HttpResponse.json(notCheckedLookup('TIMEOUT'), { status: 201 })))

  await submit()

  const result = await screen.findByRole('region', { name: 'Lookup' })
  expect(result).toHaveTextContent('Partial Verdict: VirusTotal was Not Checked')
})

test('a Verdict reached with every Source is not labelled Partial', async () => {
  const lookup = {
    ...notCheckedLookup('TIMEOUT'),
    partial: false,
    sourcesNotChecked: [],
    sourceResults: [
      {
        ...notCheckedLookup('TIMEOUT').sourceResults[0],
        outcome: 'NOT_SEEN',
        notCheckedReason: null,
        rawResponse: '{}',
      },
    ],
  }
  server.use(http.post('/api/lookups', () => HttpResponse.json(lookup, { status: 201 })))

  await submit()

  const result = await screen.findByRole('region', { name: 'Lookup' })
  expect(result).not.toHaveTextContent('Partial')
})

test.each([
  ['TIMEOUT', 'Not Checked: timed out'],
  ['SOURCE_ERROR', 'Not Checked: Source error'],
  ['RATE_LIMITED', 'Not Checked: rate limited'],
  ['MISSING_API_KEY', 'Not Checked: missing API key'],
  ['DAILY_LIMIT_REACHED', 'Not Checked: daily limit reached'],
])('a Not Checked panel says why (%s)', async (reason, shown) => {
  server.use(http.post('/api/lookups', () => HttpResponse.json(notCheckedLookup(reason), { status: 201 })))

  await submit()

  const result = await screen.findByRole('region', { name: 'Lookup' })
  const panel = within(result).getByRole('region', { name: 'VirusTotal' })
  expect(panel).toHaveTextContent(shown)
  expect(within(panel).queryByText('Raw response')).not.toBeInTheDocument()
  expect(within(panel).getByRole('link', { name: /open in virustotal/i })).toBeInTheDocument()
})
