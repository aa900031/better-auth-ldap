# better-auth-ldap

[![npm version](https://img.shields.io/npm/v/better-auth-ldap?style=flat&colorA=18181B&colorB=F0DB4F)](https://npmjs.com/package/better-auth-ldap)

LDAP sign-in plugin for [Better Auth](https://better-auth.com) powered by `ldapts`.

## Usage

Install the package.

```shell
pnpm install better-auth-ldap
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
						connection: {
							url: 'ldap://ldap.example.com',
						},
						user: {
							search: {
								baseDn: ({ username }) => `uid=${username},ou=people,dc=example,dc=com`,
								attributes: ['dn', 'mail', 'cn', 'displayName'],
							},
						},
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

## Auth Modes

The plugin supports two config shapes:

- Admin mode: configure `admin` and `user.search`. The plugin binds as admin, searches the user entry, validates the end-user password with the resolved `user.dn`, then runs optional group lookup with the admin client.
- Self mode: omit `admin` and provide `user.dn` plus `user.search`. The plugin binds as the user first, then runs optional profile/group searches with the user client.

```ts
import { ldap } from 'better-auth-ldap'

ldap({
	config: [
		{
			providerId: 'contractors',
			ldap: {
				connection: {
					url: 'ldaps://ldap.example.com',
				},
				user: {
					dn: ({ username }) => `uid=${username},ou=contractors,dc=example,dc=com`,
					search: {
						// If baseDn is omitted, the resolved user.dn is used.
						attributes: ['dn', 'mail', 'cn'],
					},
				},
			},
		},
	],
})
```

## Search Defaults

- `user.search` is required.
- `user.search.scope` defaults to `'base'`.
- `group.search.scope` defaults to `'sub'`.
- `user.search.baseDn` may be omitted. When omitted, the plugin falls back to `user.dn`.
- `filter` is optional on both `user.search` and `group.search`. If omitted, `ldapts` falls back to `(objectclass=*)`.
- `user.search` must resolve to exactly one entry. Zero results returns `IDENTITY_NOT_FOUND`; multiple results returns `IDENTITY_AMBIGUOUS`.
- `group.search` results are attached to `profile.groups`.

## Multiple Providers

Use one config entry per LDAP directory. The request body selects the provider with `providerId`.

```ts
import { ldap } from 'better-auth-ldap'

ldap({
	config: [
		{
			providerId: 'employees',
			ldap: {
				connection: {
					url: 'ldap://employees.example.com',
					startTLS: true,
				},
				admin: {
					dn: process.env.EMPLOYEES_LDAP_ADMIN_DN!,
					password: process.env.EMPLOYEES_LDAP_ADMIN_PASSWORD!,
				},
				user: {
					search: {
						baseDn: ({ username }) => `uid=${username},ou=employees,dc=example,dc=com`,
						attributes: ['dn', 'mail', 'cn'],
					},
				},
			},
		},
		{
			providerId: 'contractors',
			ldap: {
				connection: {
					url: 'ldaps://contractors.example.com',
				},
				user: {
					dn: ({ username }) => `uid=${username},ou=contractors,dc=example,dc=com`,
					search: {
						attributes: ['dn', 'mail', 'cn'],
					},
				},
			},
		},
	],
})
```

Dynamic callbacks receive a typed Better Auth endpoint context.

```ts
import type { LdapEndpointContext, LdapUserDnResolverInput } from 'better-auth-ldap'
import { ldap } from 'better-auth-ldap'

ldap({
	config: [
		{
			providerId: 'corp',
			user: {
				dn: ({ ctx, username }) => {
					const peopleDn = ctx.context.baseURL.includes('staging')
						? 'ou=staging,dc=example,dc=com'
						: 'ou=people,dc=example,dc=com'

					return `uid=${username},${peopleDn}`
				}
			},
		}
	]
})
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
				connection: {
					url: 'ldap://ldap.example.com',
					startTLS: true,
				},
				admin: {
					dn: process.env.LDAP_ADMIN_DN!,
					password: resolveAdminPassword,
				},
				user: {
					search: {
						baseDn: ({ username }) => `uid=${username},ou=people,dc=example,dc=com`,
						attributes: ['dn', 'mail', 'cn', 'displayName', 'objectGUID'],
					},
				},
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

## Advanced Filters

If you want structured filters instead of strings, pass any `ldapts` `Filter` instance from a resolver.

```ts
import { EqualityFilter } from 'ldapts'
import { ldap } from 'better-auth-ldap'

ldap({
	config: [
		{
			providerId: 'corp',
			user: {
				dn: ({ username }) => `uid=${username},ou=contractors,dc=example,dc=com`,
				group: {
					search: {
						baseDn: 'ou=groups,dc=example,dc=com',
						filter: ({ userDn }) => new EqualityFilter({
							attribute: 'member',
							value: userDn,
						}),
					},
				}
			},
		}
	]
})
```

## License

Published under the [MIT License](LICENSE).
