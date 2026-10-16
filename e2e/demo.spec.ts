import { mkdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { expect, test, type Locator, type Page } from '@playwright/test'
import { recordGif } from './recording'

// Not part of the smoke test: `npm run demo` re-records the README's screenshots and demo GIF
const images = new URL('../docs/images/', import.meta.url)
const image = (name: string) => fileURLToPath(new URL(name, images))

const hash = '9f2c4e1b7a5d3c8e6f0a2b4d6c8e0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d2e'

test.use({ viewport: { width: 1100, height: 760 } })
test.setTimeout(5 * 60_000)

test('demo', { tag: '@demo' }, async ({ page }) => {
  mkdirSync(images, { recursive: true })
  await showCursor(page)
  await page.goto('/')
  await page.mouse.move(550, 120)
  await expect(page.getByText('No Lookups yet')).toBeVisible()
  const lookup = page.getByRole('region', { name: 'Lookup', exact: true })

  await recordGif(page, image('demo.gif'), async () => {
    await pause(page, 2500)

    // A defanged IP address from an alert: Malicious, with the reasoning and each Source's view
    await lookUp(page, '185.220.101[.]1')
    await expect(lookup).toContainText('Malicious')
    await still(page, 'lookup.png', page, { fullPage: true })
    await pause(page, 3000)
    await scrollTo(page, lookup.getByRole('region', { name: 'VirusTotal' }))
    await pause(page, 2500)
    await scrollTo(page, lookup.getByRole('region', { name: 'AbuseIPDB' }))
    await pause(page, 2500)
    await scrollTo(page, lookup.getByRole('region', { name: 'AlienVault OTX' }))
    await pause(page, 2000)
    await scrollTo(page, page.getByRole('heading', { name: 'Lookup History' }))
    await pause(page, 2500)

    // A clean domain, and a file hash no Source has seen: Unknown, not Clean
    await lookUp(page, 'example.com')
    await expect(lookup).toContainText('Clean')
    await pause(page, 3500)
    await lookUp(page, hash)
    await expect(lookup).toContainText('Unknown')
    await pause(page, 3500)

    // VirusTotal is rate-limited: a Partial Verdict that says which Source is missing
    await lookUp(page, '118.193.40.10')
    await expect(lookup).toContainText('Partial Verdict')
    await still(page, 'partial-verdict.png', page)
    await pause(page, 3500)
    await scrollTo(page, lookup.getByRole('region', { name: 'VirusTotal' }))
    await pause(page, 3000)

    // Looking it up again reuses recent Source Results; Refresh asks every Source again
    await scrollToTop(page)
    await lookUp(page, '185.220.101.1')
    await expect(lookup.getByText('Reused').first()).toBeVisible()
    await scrollTo(page, lookup.getByRole('region', { name: 'VirusTotal' }))
    await pause(page, 3000)
    await scrollToTop(page)
    await click(page, lookup.getByRole('button', { name: 'Refresh' }))
    await expect(lookup.getByText('Reused')).toHaveCount(0)
    await pause(page, 2500)

    // The Lookup History keeps every Lookup; an old one opens as it was, with a banner when newer Source Results exist
    await scrollTo(page, page.getByRole('heading', { name: 'Lookup History' }))
    await pause(page, 2000)
    await click(page, page.getByRole('button', { name: /Show all 3 Lookups of 185\.220\.101\.1/ }))
    await pause(page, 1500)
    await click(page, page.getByRole('list', { name: 'Lookups of 185.220.101.1' }).getByRole('button').last())
    await expect(page.getByRole('note', { name: 'Newer Source Results' })).toBeVisible()
    await scrollToTop(page)
    await pause(page, 3500)
    await click(page, page.getByRole('button', { name: 'Open the newer Lookup' }))
    await expect(page.getByRole('note', { name: 'Newer Source Results' })).toHaveCount(0)
    await pause(page, 3000)
  })

  // The Lookup History collapsed again, as an Analyst usually sees it
  await page.getByRole('button', { name: /Show all \d+ Lookups of 185\.220\.101\.1/ }).click()
  await page.mouse.move(1090, 10)
  await still(page, 'lookup-history.png', page.getByRole('list', { name: 'Lookup History' }).locator('..'))
})

async function lookUp(page: Page, indicator: string) {
  const input = page.getByLabel('Indicator')
  await click(page, input)
  await input.clear()
  await input.pressSequentially(indicator, { delay: indicator.length > 20 ? 15 : 70 })
  await pause(page, 400)
  await click(page, page.getByRole('button', { name: 'Look up' }))
}

/** Glides the cursor to the element, so the GIF shows what is clicked. */
async function click(page: Page, target: Locator) {
  await target.scrollIntoViewIfNeeded()
  const box = (await target.boundingBox())!
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 15 })
  await pause(page, 250)
  await target.click()
}

async function scrollTo(page: Page, target: Locator) {
  await target.evaluate((element) => element.scrollIntoView({ behavior: 'smooth', block: 'start' }))
  await pause(page, 900)
}

async function scrollToTop(page: Page) {
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'smooth' }))
  await pause(page, 900)
}

/** Saves a README screenshot, without the drawn cursor. */
async function still(page: Page, name: string, of: Page | Locator, options: { fullPage?: boolean } = {}) {
  await page.evaluate(() => document.getElementById('demo-cursor')?.style.setProperty('visibility', 'hidden'))
  await of.screenshot({ path: image(name), ...options })
  await page.evaluate(() => document.getElementById('demo-cursor')?.style.removeProperty('visibility'))
}

function pause(page: Page, ms: number) {
  return page.waitForTimeout(ms)
}

/** Headless screenshots have no mouse pointer, so draw one that follows the mouse. */
function showCursor(page: Page) {
  return page.addInitScript(() => {
    window.addEventListener('DOMContentLoaded', () => {
      const cursor = document.createElement('div')
      cursor.innerHTML =
        '<svg width="22" height="22" viewBox="0 0 24 24"><path d="M4 2l15 11-7 1-4 7z" fill="#0f172a" stroke="#fff" stroke-width="1.5"/></svg>'
      cursor.id = 'demo-cursor'
      cursor.style.cssText = 'position:fixed;left:0;top:0;z-index:9999;pointer-events:none'
      document.body.append(cursor)
      document.addEventListener('mousemove', (event) => {
        cursor.style.transform = `translate(${event.clientX - 4}px, ${event.clientY - 2}px)`
      })
    })
  })
}
