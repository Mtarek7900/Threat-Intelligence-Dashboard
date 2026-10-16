import { expect, test } from '@playwright/test'

test('a Lookup in the packaged app shows a Verdict, the Source panels and lands in the Lookup History', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Threat Intelligence Dashboard' })).toBeVisible()

  await page.getByLabel('Indicator').fill('185.220.101[.]1')
  await page.getByRole('button', { name: 'Look up' }).click()

  const lookup = page.getByRole('region', { name: 'Lookup', exact: true })
  await expect(lookup).toContainText('185.220.101.1')
  const verdict = lookup.getByText('Verdict', { exact: true }).locator('..')
  await expect(verdict).toContainText('Malicious')
  for (const source of ['VirusTotal', 'AbuseIPDB', 'AlienVault OTX']) {
    await expect(lookup.getByRole('region', { name: source, exact: true })).toBeVisible()
  }

  const history = page.getByRole('list', { name: 'Lookup History' })
  await expect(history).toContainText('185.220.101.1')
  await expect(history).toContainText('Malicious')
})
