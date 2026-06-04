export function escapeRdnValue(
	raw: string,
): string {
	let escaped = ''
	let changed = false
	const lastIndex = raw.length - 1

	for (let index = 0; index <= lastIndex; index++) {
		const character = raw[index]!
		let replacement: string | undefined

		switch (character) {
			case ' ':
				if (index === 0 || index === lastIndex) {
					replacement = '\\ '
				}
				break
			case '"':
				replacement = '\\"'
				break
			case '#':
				replacement = '\\#'
				break
			case '+':
				replacement = '\\+'
				break
			case ',':
				replacement = '\\,'
				break
			case ';':
				replacement = '\\;'
				break
			case '<':
				replacement = '\\<'
				break
			case '=':
				replacement = '\\='
				break
			case '>':
				replacement = '\\>'
				break
			case '\\':
				replacement = '\\\\'
				break
		}

		if (!replacement) {
			if (changed) {
				escaped += character
			}
			continue
		}

		if (!changed) {
			escaped = raw.slice(0, index)
			changed = true
		}

		escaped += replacement
	}

	return changed ? escaped : raw
}
