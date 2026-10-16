import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { expect, test } from 'vitest'
import { server } from './test/server'
import { App } from './App'

function entry(id: string, indicator: string, indicatorType: string, verdict: string, lookedUpAt: string) {
  return { id, indicator, indicatorType, verdict, lookedUpAt }
}

function group(...lookups: ReturnType<typeof entry>[]) {
  const [latest] = lookups
  return { indicator: latest.indicator, indicatorType: latest.indicatorType, count: lookups.length, latest, lookups }
}

const ipLookups = [
  entry('ip-3', '185.220.101.1', 'IP_ADDRESS', 'MALICIOUS', '2026-01-15T10:30:00Z'),
  entry('ip-2', '185.220.101.1', 'IP_ADDRESS', 'SUSPICIOUS', '2026-01-15T09:00:00Z'),
  entry('ip-1', '185.220.101.1', 'IP_ADDRESS', 'CLEAN', '2026-01-14T08:15:00Z'),
]
const domainLookup = entry('domain-1', 'evil.com', 'DOMAIN', 'UNKNOWN', '2026-01-15T10:00:00Z')

function pastLookup(id: string, verdict: string, fetchedAt: string) {
  return {
    id,
    indicator: '185.220.101.1',
    indicatorType: 'IP_ADDRESS',
    verdict,
    partial: true,
    sourcesNotChecked: ['AbuseIPDB'],
    why: ['VirusTotal: 12 of 94 engines flagged it. Malicious.', 'AbuseIPDB was Not Checked: rate limited.'],
    sourcesAsked: ['VirusTotal', 'AbuseIPDB'],
    sourceResults: [
      {
        source: 'VirusTotal',
        outcome: 'SEEN',
        notCheckedReason: null,
        signal: 'MALICIOUS',
        facts: { enginesFlagged: 12, enginesTotal: 94, lastAnalysedAt: '2026-01-14T07:00:00Z' },
        link: 'https://www.virustotal.com/gui/ip-address/185.220.101.1',
        fetchedAt,
        reused: false,
        rawResponse: '{}',
      },
      {
        source: 'AbuseIPDB',
        outcome: 'NOT_CHECKED',
        notCheckedReason: 'RATE_LIMITED',
        signal: 'NONE',
        facts: null,
        link: 'https://www.abuseipdb.com/check/185.220.101.1',
        fetchedAt,
        reused: false,
        rawResponse: null,
      },
    ],
    lookedUpAt: fetchedAt,
  }
}

function historyHas(...groups: ReturnType<typeof group>[]) {
  server.use(http.get('/api/lookups', () => HttpResponse.json(groups)))
}

async function history() {
  render(<App />)
  return within(await screen.findByRole('list', { name: 'Lookup History' }))
}

test('lists the Lookup History most recent first with each Verdict, Type and time', async () => {
  historyHas(group(...ipLookups), group(domainLookup))

  const list = await history()

  const entries = list.getAllByRole('listitem')
  expect(entries).toHaveLength(2)
  expect(entries[0]).toHaveTextContent('185.220.101.1')
  expect(entries[0]).toHaveTextContent('IP address')
  expect(entries[0]).toHaveTextContent('Malicious')
  expect(entries[0]).toHaveTextContent('2026-01-15 10:30 UTC')
  expect(entries[1]).toHaveTextContent('evil.com')
  expect(entries[1]).toHaveTextContent('Domain')
  expect(entries[1]).toHaveTextContent('Unknown')
  expect(entries[1]).toHaveTextContent('2026-01-15 10:00 UTC')
})

test('repeated Lookups of an Indicator show as one entry with a count badge', async () => {
  historyHas(group(...ipLookups), group(domainLookup))

  const list = await history()

  const [ip, domain] = list.getAllByRole('listitem')
  expect(within(ip).getByText('×3')).toBeInTheDocument()
  expect(domain).not.toHaveTextContent('×')
})

test('a group expands to show each Lookup in it', async () => {
  historyHas(group(...ipLookups))

  const list = await history()
  const toggle = list.getByRole('button', { name: 'Show all 3 Lookups of 185.220.101.1' })
  expect(toggle).toHaveAttribute('aria-expanded', 'false')
  expect(list.queryByRole('list', { name: 'Lookups of 185.220.101.1' })).not.toBeInTheDocument()

  await userEvent.click(toggle)

  expect(toggle).toHaveAttribute('aria-expanded', 'true')
  const lookups = within(list.getByRole('list', { name: 'Lookups of 185.220.101.1' })).getAllByRole('listitem')
  expect(lookups.map((lookup) => lookup.textContent)).toEqual([
    expect.stringMatching(/Malicious.*2026-01-15 10:30 UTC/),
    expect.stringMatching(/Suspicious.*2026-01-15 09:00 UTC/),
    expect.stringMatching(/Clean.*2026-01-14 08:15 UTC/),
  ])
})

test('opening an entry shows its latest Lookup exactly as it was', async () => {
  historyHas(group(...ipLookups))
  server.use(
    http.get('/api/lookups/ip-3', () => HttpResponse.json(pastLookup('ip-3', 'MALICIOUS', '2026-01-15T10:30:00Z'))),
  )

  const list = await history()
  await userEvent.click(list.getByRole('button', { name: /^185\.220\.101\.1/ }))

  const lookup = await screen.findByRole('region', { name: 'Lookup' })
  expect(within(lookup).getByText('Looked up').nextElementSibling).toHaveTextContent('2026-01-15 10:30 UTC')
  expect(lookup).toHaveTextContent('Malicious')
  expect(lookup).toHaveTextContent('Partial Verdict: AbuseIPDB was Not Checked')
  expect(lookup).toHaveTextContent('AbuseIPDB was Not Checked: rate limited.')
  const panel = within(lookup).getByRole('region', { name: 'VirusTotal' })
  expect(panel).toHaveTextContent('12 of 94 engines flagged it')
  expect(panel).toHaveTextContent('Fetched 2026-01-15 10:30 UTC')
})

test('opening one Lookup of an expanded group shows that Lookup', async () => {
  historyHas(group(...ipLookups))
  server.use(
    http.get('/api/lookups/ip-1', () => HttpResponse.json(pastLookup('ip-1', 'CLEAN', '2026-01-14T08:15:00Z'))),
  )

  const list = await history()
  await userEvent.click(list.getByRole('button', { name: 'Show all 3 Lookups of 185.220.101.1' }))
  const lookups = within(list.getByRole('list', { name: 'Lookups of 185.220.101.1' }))
  await userEvent.click(lookups.getByRole('button', { name: /2026-01-14 08:15 UTC/ }))

  const lookup = await screen.findByRole('region', { name: 'Lookup' })
  expect(within(lookup).getByText('Looked up').nextElementSibling).toHaveTextContent('2026-01-14 08:15 UTC')
  expect(lookup).toHaveTextContent('Clean')
})

test('says so when a past Lookup cannot be opened', async () => {
  historyHas(group(domainLookup))
  server.use(http.get('/api/lookups/domain-1', () => new HttpResponse(null, { status: 404 })))

  const list = await history()
  await userEvent.click(list.getByRole('button', { name: /^evil\.com/ }))

  expect(await screen.findByRole('alert')).toHaveTextContent("Couldn't open that Lookup")
  expect(screen.queryByRole('region', { name: 'Lookup' })).not.toBeInTheDocument()
})

test('a new Lookup appears in the Lookup History once it is made', async () => {
  let groups: ReturnType<typeof group>[] = []
  server.use(
    http.get('/api/lookups', () => HttpResponse.json(groups)),
    http.post('/api/lookups', () => {
      groups = [group(ipLookups[0])]
      return HttpResponse.json(pastLookup('ip-3', 'MALICIOUS', '2026-01-15T10:30:00Z'), { status: 201 })
    }),
  )
  render(<App />)
  await screen.findByText(/no lookups yet/i)

  await userEvent.click(screen.getByLabelText('Indicator'))
  await userEvent.paste('185.220.101.1')
  await userEvent.click(screen.getByRole('button', { name: 'Look up' }))

  const list = within(await screen.findByRole('list', { name: 'Lookup History' }))
  expect(list.getByRole('listitem')).toHaveTextContent('185.220.101.1')
  expect(screen.queryByText(/no lookups yet/i)).not.toBeInTheDocument()
})
