import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { beforeEach, expect, test } from 'vitest'
import { server } from './test/server'
import { App } from './App'

beforeEach(() => {
  server.use(http.get('/api/lookups', () => HttpResponse.json([])))
})

test('submitting an Indicator shows the normalised Indicator, its Type and the Verdict', async () => {
  let sentInput: unknown
  server.use(
    http.post('/api/lookups', async ({ request }) => {
      sentInput = ((await request.json()) as { input: unknown }).input
      return HttpResponse.json(
        {
          id: '6f1c2a9e-0000-4000-8000-000000000001',
          indicator: 'evil.com',
          indicatorType: 'DOMAIN',
          verdict: 'UNKNOWN',
          lookedUpAt: '2026-01-15T10:00:00Z',
        },
        { status: 201 },
      )
    }),
  )
  render(<App />)

  await userEvent.click(screen.getByLabelText('Indicator'))
  await userEvent.paste('evil[.]com')
  await userEvent.click(screen.getByRole('button', { name: 'Look up' }))

  const result = await screen.findByRole('region', { name: 'Lookup' })
  expect(sentInput).toBe('evil[.]com')
  expect(result).toHaveTextContent('evil.com')
  expect(result).toHaveTextContent('Domain')
  expect(result).toHaveTextContent('Unknown')
})

test('rejected input shows the reason it was rejected', async () => {
  server.use(
    http.post('/api/lookups', () =>
      HttpResponse.json(
        {
          status: 400,
          detail: 'URLs aren’t supported yet. Look up the URL’s domain or IP address instead.',
          reason: 'URL_NOT_SUPPORTED',
        },
        { status: 400, headers: { 'Content-Type': 'application/problem+json' } },
      ),
    ),
  )
  render(<App />)

  await userEvent.click(screen.getByLabelText('Indicator'))
  await userEvent.paste('hxxps://evil[.]com/login')
  await userEvent.click(screen.getByRole('button', { name: 'Look up' }))

  expect(await screen.findByRole('alert')).toHaveTextContent(
    'URLs aren’t supported yet. Look up the URL’s domain or IP address instead.',
  )
  expect(screen.queryByRole('region', { name: 'Lookup' })).not.toBeInTheDocument()
})
