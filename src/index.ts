import type { BetterAuthPlugin } from 'better-auth'
import type { LdapOptions } from './options'
import pkg from '../package.json' with { type: 'json' }
import { LDAP_ERROR_CODES } from './error-codes'
import { signInWithLdap } from './routes/sign-in-with-ldap'

export { LDAP_ERROR_CODES } from './error-codes'

// eslint-disable-next-line ts/explicit-function-return-type
export function ldap(
	options: LdapOptions,
) {
	return {
		id: 'ldap',
		version: pkg.version,
		$ERROR_CODES: LDAP_ERROR_CODES,
		endpoints: {
			signInWithLdap: signInWithLdap(options),
		},
		options,
	} satisfies BetterAuthPlugin
}
