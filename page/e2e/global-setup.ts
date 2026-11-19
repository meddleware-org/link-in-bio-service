// Renders every theme-matrix page (e2e/pages/*.json) with the service's own renderer, so the browser tests check the exact
// markup the server sends. The pages share the example's site config and picture.
import { execFileSync } from 'node:child_process'
import { mkdirSync, readdirSync } from 'node:fs'
import { join } from 'node:path'

export default function globalSetup() {
  // A prebuilt binary in CI's browser jobs (LIB_PAGE_BIN, from the page job); otherwise build it here.
  const bin = process.env.LIB_PAGE_BIN ?? '../target/debug/link-in-bio'
  if (!process.env.LIB_PAGE_BIN) execFileSync('cargo', ['build', '-q', '-p', 'link-in-bio'], { stdio: 'inherit' })
  const out = join('test-results', 'pages')
  mkdirSync(out, { recursive: true })
  for (const file of readdirSync(join('e2e', 'pages')).filter((f) => f.endsWith('.json'))) {
    const name = file.replace(/\.json$/, '')
    execFileSync(bin, [
      'render', join('e2e', 'pages', file), '--config', '../examples/site.json', '--assets', '../examples', '--out', join(out, name),
    ], { stdio: 'inherit' })
  }
}
