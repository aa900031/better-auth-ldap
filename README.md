# better-auth-ldap

[![npm version](https://img.shields.io/npm/v/better-auth-ldap?style=flat&colorA=18181B&colorB=F0DB4F)](https://npmjs.com/package/better-auth-ldap)

LDAP sign-in plugin for [Better Auth](https://better-auth.com) powered by [`ldap-authentication`](https://github.com/shaozi/ldap-authentication).

## Usage

Install the package.

```shell
pnpm install better-auth-ldap ldap-authentication
```

Add the server plugin to your Better Auth config.

```ts
import { betterAuth } from 'better-auth'
import { ldap } from 'better-auth-ldap'

export const auth = betterAuth({
	plugins: [
		ldap({
			config: [
				{
					providerId: 'corp',
					ldap: {
						ldapOpts: {
							url: 'ldap://ldap.example.com',
						},
						adminDn: 'cn=read-only-admin,dc=example,dc=com',
						adminPassword: process.env.LDAP_ADMIN_PASSWORD,
						userSearchBase: 'dc=example,dc=com',
						usernameAttribute: 'uid',
						attributes: ['dn', 'uid', 'mail', 'cn', 'displayName'],
					},
				},
			],
		}),
	],
})
```

Add the client plugin when you want typed client-side calls.

```ts
import { ldapClient } from 'better-auth-ldap/client'
import { createAuthClient } from 'better-auth/client'

export const authClient = createAuthClient({
	plugins: [
		ldapClient(),
	],
})
```

Then call the sign-in endpoint.

```ts
const response = await auth.api.signInWithLdap({
	body: {
		providerId: 'corp',
		username: 'gauss',
		password: 'password',
	},
})
```

The endpoint is `POST /sign-in/ldap`. On success it authenticates against LDAP, stores the user through Better Auth's OAuth account flow, sets the session cookie, and returns:

```ts
interface LdapSignInResponse {
	user: unknown
}
```

## Multiple Providers

Use one config entry per LDAP directory. The request body selects the provider with `providerId`.

```ts
ldap({
	config: [
		{
			providerId: 'employees',
			ldap: {
				ldapOpts: { url: 'ldaps://employees.example.com' },
				adminDn: process.env.EMPLOYEES_LDAP_ADMIN_DN,
				adminPassword: process.env.EMPLOYEES_LDAP_ADMIN_PASSWORD,
				userSearchBase: 'ou=employees,dc=example,dc=com',
				usernameAttribute: 'uid',
			},
		},
		{
			providerId: 'contractors',
			ldap: {
				ldapOpts: { url: 'ldap://contractors.example.com' },
				userSearchBase: 'ou=contractors,dc=example,dc=com',
				usernameAttribute: 'uid',
				userDn: ({ username }) => `uid=${username},ou=contractors,dc=example,dc=com`,
			},
		},
	],
})
```

Dynamic callbacks receive a typed Better Auth endpoint context.

```ts
import type { LdapEndpointContext } from 'better-auth-ldap'

function resolveUserDn({ ctx, username }: { ctx: LdapEndpointContext, username: string }) {
	const peopleDn = ctx.context.baseURL.includes('staging')
		? 'ou=staging,dc=example,dc=com'
		: 'ou=people,dc=example,dc=com'

	return `uid=${username},${peopleDn}`
}
```

## User Mapping

By default, LDAP profiles are mapped with these fields:

- `id`: `dn`, `uid`, `sAMAccountName`, `userPrincipalName`, `mail`, then `username`
- `email`: `mail`, `userPrincipalName`, then `email`
- `name`: `cn`, `displayName`, `name`, `uid`, `sAMAccountName`, then `username`
- `image`: `jpegPhoto`, `thumbnailPhoto`, `jpegPhoto;binary`, then `thumbnailPhoto;binary`
- `emailVerified`: `false`

Override or extend the mapping per provider with `mapProfileToUser`.

```ts
ldap({
	config: [
		{
			providerId: 'corp',
			ldap: {
				ldapOpts: { url: 'ldap://ldap.example.com' },
				adminDn: process.env.LDAP_ADMIN_DN,
				adminPassword: process.env.LDAP_ADMIN_PASSWORD,
				userSearchBase: 'dc=example,dc=com',
				usernameAttribute: 'sAMAccountName',
			},
			mapProfileToUser: ({ profile, username }) => ({
				id: String(profile.objectGUID || profile.dn || username),
				email: String(profile.mail),
				name: String(profile.displayName || profile.cn || username),
				emailVerified: true,
			}),
		},
	],
})
```

## License

Published under the [MIT License](LICENSE).
