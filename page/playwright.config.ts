// Browser tests of the page the Rust service renders: the real binary serves the example page (examples/) in static mode,
// and e2e/global-setup.ts renders the theme-matrix pages (e2e/pages/) with the same binary.
import { definePlaywrightConfig } from '@meddleware/frontend-config/playwright'

export const PORT = 4298
const bin = '../target/debug/link-in-bio'

export default definePlaywrightConfig({
  port: PORT,
  command: `cargo build -q -p link-in-bio && ${bin} serve --mode static --config ../examples/site.json --manifest ../examples/manifest.json --listen 127.0.0.1:${PORT}`,
  extra: {
    globalSetup: './e2e/global-setup.ts',
    // The sweep injects a style (200% text); the page's strict CSP rightly refuses inline styles, so the browser is told to
    // bypass the policy for the harness only. page.spec.ts checks the real header separately.
    use: { baseURL: `http://localhost:${PORT}`, viewport: { width: 1280, height: 900 }, trace: 'retain-on-failure', bypassCSP: true },
  },
})
