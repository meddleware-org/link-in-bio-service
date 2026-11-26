// Opening a page: the example (served by the binary) or a theme-matrix page (rendered by global setup, served at the same
// origin through a route, so its stylesheet, script and sprite come from the real server).
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Page } from '@playwright/test'

/**
 * Open the example page, which the binary serves in static mode at the test server's root.
 * @param {Page} page - the Playwright page to navigate
 * @returns {Promise<void>} once navigation has started and the response has loaded
 */
export async function openExample(page: Page): Promise<void> {
  await page.goto('/')
}

/**
 * Make an opener for one theme-matrix page.
 * @param {string} name - the page's name: a file in e2e/pages without its .json
 * @returns {(page: Page) => Promise<void>} a function that opens that page
 */
export function openMatrix(name: string) {
  return async (page: Page): Promise<void> => {
    // The markup the renderer wrote in global setup; it is served at a route on the same origin, so the page's stylesheet and sprite load from the server.
    const html = readFileSync(join('test-results', 'pages', name, 'index.html'), 'utf8')
    await page.route(`**/matrix/${name}`, (route) => route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: html }))
    await page.goto(`/matrix/${name}`)
  }
}

/** The theme-matrix pages: one per file in e2e/pages (each a combination of theme choices: layout, button style, font, colour mode, accent, season, radius), plus an empty page. */
export const MATRIX = ['filled-cards-serif', 'plain-compact-mono', 'dark-only-red', 'light-only-yellow-filled', 'winter-rounded', 'empty']
