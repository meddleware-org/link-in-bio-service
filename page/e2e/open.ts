// Opening a page: the example (served by the binary) or a theme-matrix page (rendered by global setup, served at the same
// origin through a route, so its stylesheet, script and sprite come from the real server).
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Page } from '@playwright/test'

export async function openExample(page: Page): Promise<void> {
  await page.goto('/')
}

export function openMatrix(name: string) {
  return async (page: Page): Promise<void> => {
    const html = readFileSync(join('test-results', 'pages', name, 'index.html'), 'utf8')
    await page.route(`**/matrix/${name}`, (route) => route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: html }))
    await page.goto(`/matrix/${name}`)
  }
}

export const MATRIX = ['filled-cards-serif', 'plain-compact-mono', 'dark-only-red', 'light-only-yellow-filled', 'winter-rounded', 'empty']
