// Lighthouse CI on the page the binary serves (the example in examples/): accessibility 100, best practices ≥ 0.95.
// The shared Lighthouse CI configuration, with this page's port.
const { lighthouseConfig } = require('@meddleware/frontend-config/lighthouserc')

// Port 4298 is the one the Playwright config also uses for the static server.
const config = lighthouseConfig({ port: 4298 })
// Lighthouse starts the real binary on the example page, building it first if needed.
config.ci.collect.startServerCommand =
  'cargo build -q -p link-in-bio && ../target/debug/link-in-bio serve --mode static --config ../examples/site.json --manifest ../examples/manifest.json --listen 127.0.0.1:4298'
// The server prints this word once it is ready, so Lighthouse starts only then.
config.ci.collect.startServerReadyPattern = 'listening'
// Lighthouse CI reads the configuration from this export.
module.exports = config
