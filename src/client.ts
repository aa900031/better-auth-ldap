import type { BetterAuthClientPlugin } from 'better-auth/client'
import type { ldap } from './index'
import pkg from '../package.json' with { type: 'json' }
import { LDAP_ERROR_CODES } from './error-codes'

export { LDAP_ERROR_CODES } from './error-codes'

// eslint-disable-next-line ts/explicit-function-return-type
export function ldapClient() {
	return {
		id: 'ldap',
		version: pkg.version,
		$InferServerPlugin: {} as ReturnType<typeof ldap>,
		atomListeners: [
			{
				signal: '$sessionSignal',
				matcher: path => path === '/sign-in/ldap',
			},
		],
		$ERROR_CODES: LDAP_ERROR_CODES,
	} satisfies BetterAuthClientPlugin
}
