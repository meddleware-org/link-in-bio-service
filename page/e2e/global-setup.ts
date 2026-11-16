// Renders every theme-matrix page (e2e/pages/*.json) with the service's own renderer, so the browser tests check the exact
// markup the server sends. The pages share the example's site config and picture.
import { execFileSync } from 'node:child_process'
import { mkdirSync, readdirSync } from 'node:fs'
import { join } from 'node:path'

export default function globalSetup() {
  execFileSync('cargo', ['build', '-q', '-p', 'link-in-bio'], { stdio: 'inherit' })
  const out = join('test-results', 'pages')
  mkdirSync(out, { recursive: true })
  for (const file of readdirSync(join('e2e', 'pages')).filter((f) => f.endsWith('.json'))) {
    const name = file.replace(/\.json$/, '')
    execFileSync('../target/debug/link-in-bio', [
      'render', join('e2e', 'pages', file), '--config', '../examples/site.json', '--assets', '../examples', '--out', join(out, name),
    ], { stdio: 'inherit' })
  }
}
