// Browser tests of the page the Rust service renders: the real binary serves the example page (examples/) in static mode,
// and e2e/global-setup.ts renders the theme-matrix pages (e2e/pages/) with the same binary.
import { definePlaywrightConfig } from '@meddleware/frontend-config/playwright'

/** The port the static server listens on during the tests (also used by the Lighthouse configuration). */
export const PORT = 4298
// CI's browser jobs run in Playwright's image with the binary the page job built (LIB_PAGE_BIN); locally it is built here.
// The binary to run: the prebuilt one when the environment names it, otherwise the debug build.
const bin = process.env.LIB_PAGE_BIN ?? '../target/debug/link-in-bio'
// The build step, which is skipped when a prebuilt binary is supplied.
const build = process.env.LIB_PAGE_BIN ? '' : 'cargo build -q -p link-in-bio && '

// The shared fleet configuration: the browsers, the reporters and the server, with this page's command and extras.
export default definePlaywrightConfig({
  port: PORT,
  // Start the real binary on the example page, in static mode, on loopback only.
  command: `${build}${bin} serve --mode static --config ../examples/site.json --manifest ../examples/manifest.json --listen 127.0.0.1:${PORT}`,
  extra: {
    // Render the theme-matrix pages once before the tests.
    globalSetup: './e2e/global-setup.ts',
    // The sweep injects a style (200% text); the page's strict CSP rightly refuses inline styles, so the browser is told to
    // bypass the policy for the harness only. page.spec.ts checks the real header separately.
    use: { baseURL: `http://localhost:${PORT}`, viewport: { width: 1280, height: 900 }, trace: 'retain-on-failure', bypassCSP: true },
  },
})
