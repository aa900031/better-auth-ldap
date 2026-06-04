import { describe, expect, it } from 'vitest'
import { escapeRdnValue } from './escape'

describe('escapeRdnValue', () => {
	it('returns the original string when escaping is not needed', () => {
		expect(escapeRdnValue('gauss')).toBe('gauss')
	})

	it('escapes special RDN characters', () => {
		expect(escapeRdnValue('"#+,;<>\\=')).toBe('\\"\\#\\+\\,\\;\\<\\>\\\\\\=')
	})

	it('escapes leading and trailing spaces only', () => {
		expect(escapeRdnValue(' gauss ')).toBe('\\ gauss\\ ')
		expect(escapeRdnValue('ga uss')).toBe('ga uss')
	})
})
