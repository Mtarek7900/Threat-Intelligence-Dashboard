import { render, screen } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { expect, test } from 'vitest'
import { server } from './test/server'
import { App } from './App'

test('shows an empty-state message when the Lookup History is empty', async () => {
  server.use(http.get('/api/lookups', () => HttpResponse.json([])))

  render(<App />)

  expect(screen.getByRole('heading', { name: 'Lookup History' })).toBeInTheDocument()
  expect(await screen.findByText(/no lookups yet/i)).toBeInTheDocument()
})
