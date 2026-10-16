import { defineConfig, devices } from '@playwright/test'

const port = process.env.E2E_PORT ?? '8090'

export default defineConfig({
  testDir: '.',
  // Starts the packaged app with Postgres and faked Sources (compose.yaml), and stops it after
  globalSetup: './global-setup.ts',
  globalTeardown: './global-teardown.ts',
  forbidOnly: !!process.env.CI,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: `http://localhost:${port}`,
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
})
