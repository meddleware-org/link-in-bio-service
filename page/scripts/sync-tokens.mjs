#!/usr/bin/env node
// Copies the files this service vendors from the pinned shared packages, or (--check) fails if they differ:
//   @meddleware/design-tokens: tokens.json, tokens.css, seasons.css  -> crates/core/tokens/
//   @meddleware/ui brand files: favicon set                          -> assets/brand/
//   node page/scripts/sync-tokens.mjs [--check]
import { copyFileSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'

// This script's own directory, then the repository root two levels up (page/scripts -> root).
const here = dirname(new URL(import.meta.url).pathname)
const root = resolve(here, '../..')
// The packages' own directories (some do not export package.json, so resolve by path).
const pkgDir = (name) => join(root, 'page', 'node_modules', name)

// The two source directories inside the pinned packages: the token files and the brand files.
const tokens = join(pkgDir('@meddleware/design-tokens'), 'src')
const brand = join(pkgDir('@meddleware/ui'), 'dist', 'brand')
// Every [source, destination] pair: the three token files, then the five brand files.
const pairs = [
  ...['tokens.json', 'tokens.css', 'seasons.css'].map((f) => [join(tokens, f), join(root, 'crates/core/tokens', f)]),
  ...['favicon.svg', 'favicon.ico', 'apple-touch-icon.png', 'icon-192.png', 'icon-512.png'].map((f) => [join(brand, f), join(root, 'assets/brand', f)]),
]
// `--check` compares instead of copying, and exits 1 if any file differs or is missing (the CI drift check).
const check = process.argv.includes('--check')
// How many destination files differ from their source.
let stale = 0
for (const [from, to] of pairs) {
  if (check) {
    // A missing file counts as different.
    let same = false
    try { same = readFileSync(from).equals(readFileSync(to)) } catch {}
    if (!same) { console.error(`stale: ${to.replace(root + '/', '')}`); stale++ }
  } else {
    // Without --check, copy the file over the vendored one.
    copyFileSync(from, to)
  }
}
// A drift is an error with the command that fixes it.
if (check && stale) { console.error('run node page/scripts/sync-tokens.mjs'); process.exit(1) }
console.log(check ? 'vendored files: OK' : `copied ${pairs.length} files`)
