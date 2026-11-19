// What the page promises beyond accessibility: the headers, working with scripts blocked, the documents other software
// reads, and no request leaving the origin.
import { expect, test } from '@playwright/test'
import { offline } from '@meddleware/frontend-config/look'

test.beforeEach(async ({ page }) => {
  await offline(page)
})

test('security headers, no cookie, the linkset link', async ({ request }) => {
  const r = await request.get('/')
  expect(r.status()).toBe(200)
  const h = r.headers()
  expect(h['content-security-policy']).toContain("default-src 'none'")
  expect(h['content-security-policy']).toContain("frame-ancestors 'none'")
  expect(h['referrer-policy']).toBe('no-referrer')
  expect(h['x-content-type-options']).toBe('nosniff')
  expect(h['set-cookie']).toBeUndefined()
  expect(h['link']).toContain('rel="linkset"')
})

test('the whole page works with scripts blocked', async ({ browser }) => {
  const context = await browser.newContext({ javaScriptEnabled: false })
  const page = await context.newPage()
  await offline(page)
  await page.goto('/')
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Ada Example')
  await expect(page.getByRole('link', { name: 'GitHub' })).toHaveAttribute('href', 'https://github.com/example')
  // The group is a native <details>: it opens without any script.
  const projects = page.locator('details').filter({ hasText: 'Projects' })
  await projects.locator('summary').click()
  await expect(page.getByRole('link', { name: /Documentation/ })).toBeVisible()
  // The address is selectable text; the copy button and the colour control appear only with scripts.
  await expect(page.locator('code.address-value')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Copy address' })).toBeHidden()
  await expect(page.getByRole('button', { name: 'Dark' })).toBeHidden()
  await context.close()
})

test('with scripts, the colour control works and is remembered only when asked (L-PECR-2)', async ({ page }) => {
  await page.goto('/')
  const remember = page.getByRole('checkbox', { name: 'Remember on this device' })
  await expect(remember).not.toBeChecked()
  // A choice applies at once but is not kept.
  await page.getByRole('button', { name: 'Dark', exact: true }).click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  expect(await page.evaluate(() => localStorage.length)).toBe(0)
  await page.reload()
  await expect(page.getByRole('button', { name: 'Dark', exact: true })).toHaveAttribute('aria-pressed', 'false')
  // Ticking keeps it across a reload.
  await page.getByRole('button', { name: 'Dark', exact: true }).click()
  await remember.check()
  await page.reload()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  await expect(page.getByRole('button', { name: 'Dark', exact: true })).toHaveAttribute('aria-pressed', 'true')
  await expect(remember).toBeChecked()
  // Unticking forgets it.
  await remember.uncheck()
  expect(await page.evaluate(() => localStorage.length)).toBe(0)
})

test('identity links carry rel=me and the page is an h-card', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByRole('link', { name: 'GitHub' })).toHaveAttribute('rel', 'me noopener noreferrer')
  await expect(page.getByRole('link', { name: /Blog/ })).toHaveAttribute('rel', 'noopener noreferrer')
  await expect(page.locator('.h-card .p-name')).toHaveText('Ada Example')
  await expect(page.locator('h1')).toHaveCount(1)
})

test('no request leaves the origin', async ({ page }) => {
  const external: string[] = []
  page.on('request', (r) => {
    if (!r.url().startsWith('http://localhost:4298/')) external.push(r.url())
  })
  await page.goto('/')
  await page.waitForLoadState('networkidle')
  expect(external).toEqual([])
})

test('link previews and documents', async ({ page, request }) => {
  await page.goto('/')
  await expect(page.locator('meta[property="og:title"]')).toHaveAttribute('content', 'Ada Example')
  await expect(page.locator('meta[name="twitter:card"]')).toHaveAttribute('content', 'summary')
  await expect(page.locator('meta[property="og:image"]')).toHaveAttribute('content', /^https:\/\/links\.example\.org\/_\/avatar\./)
  const ld = JSON.parse(await page.locator('script[type="application/ld+json"]').textContent() ?? '{}')
  expect(ld['@type']).toBe('ProfilePage')
  expect(ld.mainEntity.sameAs).toContain('https://github.com/example')
  const ls = await request.get('/links.json')
  expect(ls.headers()['content-type']).toContain('application/linkset+json; profile=')
  const body = await ls.json()
  expect(body.linkset[0].anchor).toBe('https://links.example.org/')
  const wf = await request.get('/.well-known/webfinger?resource=acct:ada@links.example.org')
  expect((await wf.json()).subject).toBe('acct:ada@links.example.org')
  expect((await request.get('/actor')).status()).toBe(200)
  expect((await request.get('/spec/profile-links/v1')).status()).toBe(200)
})

test('only GET and HEAD', async ({ request }) => {
  expect((await request.post('/')).status()).toBe(405)
  expect((await request.get('/.env')).status()).toBe(404)
})
