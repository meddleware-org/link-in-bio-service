// Screenshots for looking (npm run shots): the example and each theme-matrix page at phone, tablet and desktop.
import { defineShots } from '@meddleware/frontend-config/shots'
import { MATRIX, openExample, openMatrix } from './open'

defineShots({ example: openExample, ...Object.fromEntries(MATRIX.map((name) => [name, openMatrix(name)])) })
