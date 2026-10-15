import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { beforeEach, expect, test } from 'vitest'
import { server } from './test/server'
import { App } from './App'

const notCounted =
  'AlienVault OTX: in 2 pulses. Suspicious, but not counted: AlienVault OTX is a Corroborating Source and no other Source gave a Signal.'

const virusTotal = {
  source: 'VirusTotal',
  outcome: 'SEEN',
  notCheckedReason: null,
  signal: 'NONE',
  facts: { enginesFlagged: 0, enginesTotal: 92, lastAnalysedAt: '2026-10-15T18:44:02Z' },
  link: 'https://www.virustotal.com/gui/ip-address/9.9.9.9',
  fetchedAt: '2026-01-15T10:00:00Z',
  rawResponse: '{}',
}

const otx = {
  source: 'AlienVault OTX',
  outcome: 'SEEN',
  notCheckedReason: null,
  signal: 'SUSPICIOUS',
  facts: {
    pulseCount: 2,
    pulses: [
      { name: 'Mirai botnet C2', tags: ['mirai', 'botnet'] },
      { name: 'Honeypot scans', tags: [] },
    ],
  },
  link: 'https://otx.alienvault.com/indicator/ip/9.9.9.9',
  fetchedAt: '2026-01-15T10:00:00Z',
  rawResponse: '{"pulse_info":{"count":2}}',
}

function ipLookup(sourceResults: object[], why: string[]) {
  return {
    id: '6f1c2a9e-0000-4000-8000-000000000005',
    indicator: '9.9.9.9',
    indicatorType: 'IP_ADDRESS',
    verdict: 'CLEAN',
    partial: false,
    sourcesNotChecked: [],
    why,
    sourcesAsked: ['VirusTotal', 'AlienVault OTX'],
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
  await userEvent.paste('9.9.9.9')
  await userEvent.click(screen.getByRole('button', { name: 'Look up' }))
  return screen.findByRole('region', { name: 'Lookup' })
}

test('the OTX panel shows how many pulses mention the Indicator, with their names and tags', async () => {
  const result = await lookUp(ipLookup([virusTotal, otx], []))

  const panel = within(result).getByRole('region', { name: 'AlienVault OTX' })
  expect(panel).toHaveTextContent('Seen')
  expect(panel).toHaveTextContent('In 2 pulses')
  const pulses = within(panel).getAllByRole('listitem')
  expect(pulses).toHaveLength(2)
  expect(pulses[0]).toHaveTextContent('Mirai botnet C2')
  expect(pulses[0]).toHaveTextContent('mirai')
  expect(pulses[0]).toHaveTextContent('botnet')
  expect(pulses[1]).toHaveTextContent('Honeypot scans')
  expect(within(panel).getByRole('link', { name: /open in alienvault otx/i })).toHaveAttribute(
    'href',
    'https://otx.alienvault.com/indicator/ip/9.9.9.9',
  )
})

test('a pulse with many tags shows the first few and how many more there are', async () => {
  const tags = Array.from({ length: 11 }, (_, i) => `tag-${i + 1}`)
  const manyTags = { ...otx, facts: { pulseCount: 1, pulses: [{ name: 'Noisy feed', tags }] } }

  const result = await lookUp(ipLookup([virusTotal, manyTags], []))

  const panel = within(result).getByRole('region', { name: 'AlienVault OTX' })
  expect(panel).toHaveTextContent('tag-8')
  expect(panel).not.toHaveTextContent('tag-9')
  expect(panel).toHaveTextContent('+3 more')
})

test('the OTX panel says when it lists fewer pulses than mention the Indicator', async () => {
  const someListed = { ...otx, facts: { ...otx.facts, pulseCount: 120 } }

  const result = await lookUp(ipLookup([virusTotal, someListed], []))

  expect(within(result).getByRole('region', { name: 'AlienVault OTX' })).toHaveTextContent(
    'In 120 pulses, 2 of them listed here',
  )
})

test('the Why? section says when OTX’s Signal was not counted', async () => {
  const result = await lookUp(
    ipLookup([virusTotal, otx], ['VirusTotal: 0 of 92 engines flagged it. No Signal.', notCounted]),
  )

  expect(within(result).getByRole('region', { name: 'Why?' })).toHaveTextContent(notCounted)
  expect(result).toHaveTextContent('Clean')
})

test('the OTX panel says when no pulse mentions the Indicator', async () => {
  const result = await lookUp(
    ipLookup([virusTotal, { ...otx, outcome: 'NOT_SEEN', signal: 'NONE', facts: null }], []),
  )

  const panel = within(result).getByRole('region', { name: 'AlienVault OTX' })
  expect(panel).toHaveTextContent('Not Seen')
  expect(panel).not.toHaveTextContent('pulses')
})
