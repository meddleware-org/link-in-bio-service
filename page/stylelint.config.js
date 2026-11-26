// The shared fleet Stylelint configuration, unchanged: it checks page.css (src/**/*.css) in the `lint:css` script.
import { stylelintConfig } from '@meddleware/frontend-config/stylelint'

// The one export Stylelint reads; the shared package supplies every rule.
export default stylelintConfig()
