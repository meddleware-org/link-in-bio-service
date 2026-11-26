// What the page promises beyond accessibility: the headers, working with scripts blocked, the documents other software
// reads, and no request leaving the origin.
import { expect, test } from '@playwright/test'
import { offline } from '@meddleware/frontend-config/look'

// Every test runs with the network cut off except the page server itself, so nothing can depend on a third party.
test.beforeEach(async ({ page }) => {
  await offline(page)
})

// The headers the design promises: a strict CSP, no framing, no referrer, no sniffing, no cookie, and the linkset pointer.
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

// Progressive enhancement: with JavaScript off, the content, the links and the groups all work.
test('the whole page works with scripts blocked', async ({ browser }) => {
  // A fresh context so scripts can be disabled for this test only.
  const context = await browser.newContext({ javaScriptEnabled: false })
  const page = await context.newPage()
  await offline(page)
  await page.goto('/')
  // The name is the page's one h1, and an identity link keeps its address.
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

// The colour control and the "remember" box: a choice lasts for the visit, and storage is written only while the box is ticked.
test('with scripts, the colour control works and is remembered only when asked (L-PECR-2)', async ({ page }) => {
  await page.goto('/')
  // The box starts unticked: nothing is kept unless the visitor asks.
  const remember = page.getByRole('checkbox', { name: 'Remember on this device' })
  await expect(remember).not.toBeChecked()
  // A choice applies at once but is not kept.
  await page.getByRole('button', { name: 'Dark', exact: true }).click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  expect(await page.evaluate(() => localStorage.length)).toBe(0)
  // After a reload the choice is gone, because it was never kept.
  await page.reload()
  await expect(page.getByRole('button', { name: 'Dark', exact: true })).toHaveAttribute('aria-pressed', 'false')
  // Ticking keeps it across a reload.
  await page.getByRole('button', { name: 'Dark', exact: true }).click()
  await remember.check()
  // The reload reads the kept choice back.
  await page.reload()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  await expect(page.getByRole('button', { name: 'Dark', exact: true })).toHaveAttribute('aria-pressed', 'true')
  await expect(remember).toBeChecked()
  // Unticking forgets it.
  await remember.uncheck()
  expect(await page.evaluate(() => localStorage.length)).toBe(0)
})

// Identity links say so with rel=me, ordinary links do not, and the markup is a microformats h-card.
test('identity links carry rel=me and the page is an h-card', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByRole('link', { name: 'GitHub' })).toHaveAttribute('rel', 'me noopener noreferrer')
  await expect(page.getByRole('link', { name: /Blog/ })).toHaveAttribute('rel', 'noopener noreferrer')
  await expect(page.locator('.h-card .p-name')).toHaveText('Ada Example')
  await expect(page.locator('h1')).toHaveCount(1)
})

// The page loads nothing from anywhere else: every request goes to the page's own origin.
test('no request leaves the origin', async ({ page }) => {
  const external: string[] = []
  // Record every request whose address is not on the test server.
  page.on('request', (r) => {
    if (!r.url().startsWith('http://localhost:4298/')) external.push(r.url())
  })
  await page.goto('/')
  await page.waitForLoadState('networkidle')
  expect(external).toEqual([])
})

// The link-preview tags, the structured data and the documents other software reads (linkset, WebFinger, actor, profile specification).
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

// The server only reads: other methods are refused, and a dotfile is never served.
test('only GET and HEAD', async ({ request }) => {
  expect((await request.post('/')).status()).toBe(405)
  expect((await request.get('/.env')).status()).toBe(404)
})
