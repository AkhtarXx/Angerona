import { test, expect } from '@playwright/test'

test.describe('landing page', () => {
  test.beforeEach(async ({ page }) => {
    const messages: string[] = []
    page.on('console', (msg) => {
      const text = msg.text()
      if (msg.type() === 'error' && !text.includes('favicon')) {
        messages.push(text)
      }
    })
    await page.goto('/')
    await page.waitForLoadState('networkidle')
    ;(test as unknown as { ext: { consoleErrors: string[] } }).ext = { consoleErrors: messages } as unknown as never
  })

  test('primary navigation renders with a stable compact height', async ({ page }) => {
    const nav = page.getByRole('navigation', { name: 'Primary' })
    await expect(nav).toBeVisible()
    const box = await nav.boundingBox()
    expect(box?.height).toBeGreaterThanOrEqual(36)
    expect(box?.height).toBeLessThanOrEqual(48)
  })

  test('hero states the public product objective', async ({ page }) => {
    await expect(page.locator('#top').getByText('Reverse Engineering', { exact: true })).toBeVisible()
    await expect(page.locator('#top')).toContainText(/authorized\s+binaries/i)
  })

  test('public page does not render internal sample provenance', async ({ page }) => {
    await expect(page.getByText(/lbuz_program|FUN_ram_|workspaces\/runs/i)).toHaveCount(0)
  })

  test('proof section reserves comfortable vertical space', async ({ page }) => {
    const proof = page.locator('#proof')
    await expect(proof).toBeVisible()
    const box = await proof.boundingBox()
    expect(box?.height).toBeGreaterThan(200)
  })

  test('no console errors beyond favicon', async ({ page }) => {
    await page.waitForTimeout(500)
    expect(((test as unknown as { ext: { consoleErrors: string[] } }).ext?.consoleErrors ?? []).length).toBe(0)
  })

  test('mobile viewport stacks hero without horizontal overflow', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 })
    await page.reload()
    await page.waitForLoadState('networkidle')
    const width = await page.evaluate(() => document.documentElement.scrollWidth)
    expect(width).toBeLessThanOrEqual(375)
  })

  test('contact CTAs lead to the engagement section', async ({ page }) => {
    const heroCta = page.locator('#top').getByRole('link', { name: /Talk to us/i })
    await expect(heroCta).toHaveAttribute('href', '#demo')
    await heroCta.click()
    await expect(page.locator('#demo').getByRole('button', { name: /Open email draft/i })).toBeVisible()
  })

  test('proof strip renders repository-backed facts', async ({ page }) => {
    await expect(page.locator('#proof').getByText('500+')).toBeVisible()
    await expect(page.locator('#proof').getByText('regression tests')).toBeVisible()
    await expect(page.locator('#proof').getByText('analysis engines')).toBeVisible()
  })

  test('navigation resolves an offscreen technology section', async ({ page }) => {
    const link = page.getByRole('navigation', { name: 'Primary', exact: true }).getByRole('link', { name: 'Technology' })
    if (await link.isVisible()) {
      await link.click()
      await expect(page.locator('#engine')).toBeInViewport()
    } else {
      await page.getByRole('button', { name: 'Open navigation menu' }).click()
      await page.getByRole('navigation', { name: 'Mobile', exact: true }).getByRole('link', { name: 'Technology' }).click()
      await expect(page.locator('#engine')).toBeInViewport()
    }
  })

  test('contact fragment resolves on a direct load', async ({ page }) => {
    await page.goto('/#demo')
    await expect(page.locator('#demo')).toBeInViewport()
  })

  test('mobile menu occupies viewport height', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 })
    await page.getByRole('button', { name: 'Open navigation menu' }).click()
    await expect(page.locator('#mobile-menu')).toBeVisible()
    const box = await page.locator('#mobile-menu').boundingBox()
    expect(box?.height).toBeGreaterThanOrEqual(811)
    await page.keyboard.press('Escape')
    await expect(page.locator('#mobile-menu')).toHaveCount(0)
  })
})
