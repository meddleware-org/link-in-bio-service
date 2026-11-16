// Lighthouse CI on the page the binary serves (the example in examples/): accessibility 100, best practices ≥ 0.95.
const { lighthouseConfig } = require('@meddleware/frontend-config/lighthouserc')

const config = lighthouseConfig({ port: 4298 })
config.ci.collect.startServerCommand =
  'cargo build -q -p link-in-bio && ../target/debug/link-in-bio serve --mode static --config ../examples/site.json --manifest ../examples/manifest.json --listen 127.0.0.1:4298'
config.ci.collect.startServerReadyPattern = 'listening'
module.exports = config
