import { node } from '@aa900031/tsdown-config'

export default node({ entry: ['src/index.ts', 'src/client.ts'] }, {
	format: ['esm', 'cjs'],
	treeshake: true,
})
