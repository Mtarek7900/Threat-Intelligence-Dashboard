import type { FullConfig } from '@playwright/test'
import { compose } from './compose'

// Building the image compiles the backend and the frontend, so allow it a while
const startupTimeoutMs = 10 * 60_000

export default async function globalSetup(config: FullConfig) {
  const baseURL = config.projects[0].use.baseURL!
  // Clears any stack a failed earlier run left behind (teardown doesn't run when setup fails)
  compose('down', '--volumes')
  compose('up', '--build', '--detach')
  await waitUntilServing(baseURL)
}

async function waitUntilServing(url: string) {
  const deadline = Date.now() + startupTimeoutMs
  while (Date.now() < deadline) {
    try {
      if ((await fetch(url)).ok) return
    } catch {
      // Not listening yet
    }
    await new Promise((resolve) => setTimeout(resolve, 1000))
  }
  compose('logs', 'app')
  throw new Error(`The app didn't start serving ${url} in time`)
}
