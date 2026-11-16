#!/usr/bin/env node
// Copies the files this service vendors from the pinned shared packages, or (--check) fails if they differ:
//   @meddleware/design-tokens: tokens.json, tokens.css, seasons.css  -> crates/core/tokens/
//   @meddleware/ui brand files: favicon set                          -> assets/brand/
//   node page/scripts/sync-tokens.mjs [--check]
import { copyFileSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'

const here = dirname(new URL(import.meta.url).pathname)
const root = resolve(here, '../..')
// The packages' own directories (some do not export package.json, so resolve by path).
const pkgDir = (name) => join(root, 'page', 'node_modules', name)

const tokens = join(pkgDir('@meddleware/design-tokens'), 'src')
const brand = join(pkgDir('@meddleware/ui'), 'dist', 'brand')
const pairs = [
  ...['tokens.json', 'tokens.css', 'seasons.css'].map((f) => [join(tokens, f), join(root, 'crates/core/tokens', f)]),
  ...['favicon.svg', 'favicon.ico', 'apple-touch-icon.png', 'icon-192.png', 'icon-512.png'].map((f) => [join(brand, f), join(root, 'assets/brand', f)]),
]
const check = process.argv.includes('--check')
let stale = 0
for (const [from, to] of pairs) {
  if (check) {
    let same = false
    try { same = readFileSync(from).equals(readFileSync(to)) } catch {}
    if (!same) { console.error(`stale: ${to.replace(root + '/', '')}`); stale++ }
  } else copyFileSync(from, to)
}
if (check && stale) { console.error('run node page/scripts/sync-tokens.mjs'); process.exit(1) }
console.log(check ? 'vendored files: OK' : `copied ${pairs.length} files`)
