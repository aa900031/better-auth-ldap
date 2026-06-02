import pkg from '../package.json' with { type: 'json' }
import type { BetterAuthClientPlugin } from 'better-auth/client'
import type { LdapPlugin } from './index'

export  { LDAP_ERROR_CODES } from './error'

export interface LdapClientPlugin extends BetterAuthClientPlugin {
	id: 'ldap'
	$InferServerPlugin: LdapPlugin
}

export function ldapClient(): LdapClientPlugin {
	return {
		id: 'ldap',
		version: pkg.version,
		atomListeners: [
			{
				signal: '$sessionSignal',
				matcher: (path) => path === '/sign-in/ldap',
			},
		],
		$InferServerPlugin: {} as LdapPlugin,
	} satisfies LdapClientPlugin
}
