import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { delay, http, HttpResponse } from 'msw'
import { beforeEach, expect, test } from 'vitest'
import { server } from './test/server'
import { App } from './App'

function lookup({ reused, fetchedAt, verdict = 'UNKNOWN' }: { reused: boolean; fetchedAt: string; verdict?: string }) {
  return {
    id: crypto.randomUUID(),
    indicator: 'evil.com',
    indicatorType: 'DOMAIN',
    verdict,
    partial: false,
    sourcesNotChecked: [],
    why: ['VirusTotal has no record of it. No Signal.'],
    sourcesAsked: ['VirusTotal'],
    sourceResults: [
      {
        source: 'VirusTotal',
        outcome: 'NOT_SEEN',
        notCheckedReason: null,
        signal: 'NONE',
        facts: null,
        link: 'https://www.virustotal.com/gui/domain/evil.com',
        fetchedAt,
        reused,
        rawResponse: '{"error":{"code":"NotFoundError"}}',
      },
    ],
    lookedUpAt: '2026-01-15T10:00:00Z',
  }
}

beforeEach(() => {
  server.use(http.get('/api/lookups', () => HttpResponse.json([])))
})

async function submit(input: string) {
  render(<App />)
  await userEvent.click(screen.getByLabelText('Indicator'))
  await userEvent.paste(input)
  await userEvent.click(screen.getByRole('button', { name: 'Look up' }))
  return screen.findByRole('region', { name: 'Lookup' })
}

test('a panel shows when its Source Result was fetched and that it was reused', async () => {
  server.use(
    http.post('/api/lookups', () =>
      HttpResponse.json(lookup({ reused: true, fetchedAt: '2026-01-14T11:30:00Z' }), { status: 201 }),
    ),
  )

  const result = await submit('evil.com')

  const panel = within(result).getByRole('region', { name: 'VirusTotal' })
  expect(panel).toHaveTextContent('Fetched 2026-01-14 11:30 UTC')
  expect(within(panel).getByText('Reused')).toBeInTheDocument()
})

test('a panel for a freshly fetched Source Result is not marked reused', async () => {
  server.use(
    http.post('/api/lookups', () =>
      HttpResponse.json(lookup({ reused: false, fetchedAt: '2026-01-15T10:00:00Z' }), { status: 201 }),
    ),
  )

  const result = await submit('evil.com')

  const panel = within(result).getByRole('region', { name: 'VirusTotal' })
  expect(panel).toHaveTextContent('Fetched 2026-01-15 10:00 UTC')
  expect(within(panel).queryByText('Reused')).not.toBeInTheDocument()
})

test('Refresh asks every Source about the Indicator again and shows the new Lookup', async () => {
  const requests: unknown[] = []
  server.use(
    http.post('/api/lookups', async ({ request }) => {
      const body = (await request.json()) as { refresh?: boolean }
      requests.push(body)
      return body.refresh
        ? HttpResponse.json(lookup({ reused: false, fetchedAt: '2026-01-15T10:05:00Z', verdict: 'CLEAN' }), {
            status: 201,
          })
        : HttpResponse.json(lookup({ reused: true, fetchedAt: '2026-01-14T11:30:00Z' }), { status: 201 })
    }),
  )

  await submit('evil[.]com')
  await userEvent.click(screen.getByRole('button', { name: 'Refresh' }))

  await screen.findByText('Clean')
  const panel = within(screen.getByRole('region', { name: 'Lookup' })).getByRole('region', { name: 'VirusTotal' })
  expect(panel).toHaveTextContent('Fetched 2026-01-15 10:05 UTC')
  expect(within(panel).queryByText('Reused')).not.toBeInTheDocument()
  expect(requests).toEqual([
    { input: 'evil[.]com', refresh: false },
    { input: 'evil.com', refresh: true },
  ])
})

test('the earlier Lookup stays on screen while Refresh asks the Sources again', async () => {
  server.use(
    http.post('/api/lookups', async ({ request }) => {
      const body = (await request.json()) as { refresh: boolean }
      if (body.refresh) {
        await delay(50)
        return HttpResponse.json(lookup({ reused: false, fetchedAt: '2026-01-15T10:05:00Z', verdict: 'CLEAN' }), {
          status: 201,
        })
      }
      return HttpResponse.json(lookup({ reused: true, fetchedAt: '2026-01-14T11:30:00Z' }), { status: 201 })
    }),
  )

  await submit('evil.com')
  await userEvent.click(screen.getByRole('button', { name: 'Refresh' }))

  expect(screen.getByRole('status')).toHaveTextContent('Asking the Sources again…')
  expect(screen.getByRole('button', { name: 'Refresh' })).toBeDisabled()
  expect(screen.getByRole('region', { name: 'Lookup' })).toHaveTextContent('Fetched 2026-01-14 11:30 UTC')
  await screen.findByText('Clean')
  expect(screen.queryByRole('status')).not.toBeInTheDocument()
})

test('a failed Refresh keeps the earlier Lookup and says it failed', async () => {
  server.use(
    http.post('/api/lookups', async ({ request }) => {
      const body = (await request.json()) as { refresh: boolean }
      return body.refresh
        ? new HttpResponse(null, { status: 500 })
        : HttpResponse.json(lookup({ reused: true, fetchedAt: '2026-01-14T11:30:00Z' }), { status: 201 })
    }),
  )

  await submit('evil.com')
  await userEvent.click(screen.getByRole('button', { name: 'Refresh' }))

  expect(await screen.findByRole('alert')).toHaveTextContent('The Refresh failed')
  const panel = within(screen.getByRole('region', { name: 'Lookup' })).getByRole('region', { name: 'VirusTotal' })
  expect(panel).toHaveTextContent('Fetched 2026-01-14 11:30 UTC')
  expect(screen.getByRole('button', { name: 'Refresh' })).toBeEnabled()
})
