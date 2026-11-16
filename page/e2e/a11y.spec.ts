// The shared accessibility sweep (WCAG 2.2 AA and AAA in every colour mode × season, reflow at 320 px, 200% text, forced
// colours, reduced motion, keyboard) over the example page and every theme-matrix page.
import { defineA11ySuite } from '@meddleware/frontend-config/a11y'
import { MATRIX, openExample, openMatrix } from './open'

defineA11ySuite(
  {
    example: openExample,
    'group open': async (page) => {
      await openExample(page)
      await page.locator('summary').filter({ hasText: 'Projects' }).click()
    },
    ...Object.fromEntries(MATRIX.map((name) => [name, openMatrix(name)])),
  },
  { aaa: 'gate' },
)
