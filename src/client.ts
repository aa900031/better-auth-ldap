import type { BetterAuthClientPlugin } from 'better-auth/client'
import type { LdapPlugin } from './index'

export interface LdapClientPlugin extends BetterAuthClientPlugin {
	id: 'ldap'
	$InferServerPlugin: LdapPlugin
}

export function ldapClient(): LdapClientPlugin {
	return {
		id: 'ldap',
		$InferServerPlugin: {} as LdapPlugin,
	} satisfies LdapClientPlugin
}
