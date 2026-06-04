import type {
	LdapAdminAuthConfig,
	LdapEndpointContext,
	LdapProviderConfig,
	LdapSelfAuthConfig,
} from './options'
import { describe, expect, it } from 'vitest'
import {
	createUserSearchResolverInput,
	isAdminAuthConfig,
	isSelfAuthConfig,
	LdapConfigError,
	resolveAdminDn,
	resolveAdminPassword,
	resolveBaseDN,
	resolveClientOptions,
	resolveOptionalUserDn,
	resolveRequiredUserDn,
	resolveSearchOptions,
	resolveUserSearchBaseDN,
} from './options'

type AdminProviderConfig = LdapProviderConfig & { ldap: LdapAdminAuthConfig }
type SelfProviderConfig = LdapProviderConfig & { ldap: LdapSelfAuthConfig }

const ctx = {
	context: {
		baseURL: 'https://app.example.com',
	},
} as LdapEndpointContext

describe('options helpers', () => {
	it('resolves admin credentials from static values and resolvers', async () => {
		const staticConfig = createAdminProviderConfig()
		const dynamicConfig = createAdminProviderConfig({
			ldap: {
				connection: {
					startTLS: true,
					tlsOptions: {
						rejectUnauthorized: false,
					},
					url: 'ldap://ldap.example.com',
				},
				admin: {
					dn: async (resolverCtx) => {
						expect(resolverCtx).toBe(ctx)
						return 'cn=resolved-admin,dc=example,dc=com'
					},
					password: async (resolverCtx) => {
						expect(resolverCtx).toBe(ctx)
						return 'resolved-password'
					},
				},
				user: {},
			},
		})

		expect(await resolveAdminDn(staticConfig, ctx)).toBe('cn=read-only-admin,dc=example,dc=com')
		expect(await resolveAdminPassword(staticConfig, ctx)).toBe('admin-password')
		expect(await resolveAdminDn(dynamicConfig, ctx)).toBe('cn=resolved-admin,dc=example,dc=com')
		expect(await resolveAdminPassword(dynamicConfig, ctx)).toBe('resolved-password')
	})

	it('resolves optional user.dn for admin auth and returns undefined when it is omitted', async () => {
		const providerConfig = createAdminProviderConfig()
		const providerConfigWithoutUserDn = createAdminProviderConfig({
			ldap: {
				connection: {
					startTLS: true,
					tlsOptions: {
						rejectUnauthorized: false,
					},
					url: 'ldap://ldap.example.com',
				},
				admin: {
					dn: 'cn=read-only-admin,dc=example,dc=com',
					password: 'admin-password',
				},
				user: {},
			},
		})

		expect(await resolveOptionalUserDn(providerConfig, {
			ctx,
			username: 'mark',
		})).toBe('uid=mark,ou=people,dc=example,dc=com')
		expect(await resolveOptionalUserDn(providerConfigWithoutUserDn, {
			ctx,
			username: 'mark',
		})).toBeUndefined()
	})

	it('escapes username before passing it to the admin user.dn resolver', async () => {
		let resolvedUsername: string | undefined
		const providerConfig = createAdminProviderConfig({
			ldap: {
				connection: {
					startTLS: true,
					tlsOptions: {
						rejectUnauthorized: false,
					},
					url: 'ldap://ldap.example.com',
				},
				admin: {
					dn: 'cn=read-only-admin,dc=example,dc=com',
					password: 'admin-password',
				},
				user: {
					dn: ({ username }) => {
						resolvedUsername = username
						return `uid=${username},ou=people,dc=example,dc=com`
					},
				},
			},
		})

		expect(await resolveOptionalUserDn(providerConfig, {
			ctx,
			username: 'mark,admin',
		})).toBe('uid=mark\\,admin,ou=people,dc=example,dc=com')
		expect(resolvedUsername).toBe('mark\\,admin')
	})

	it('resolves required user.dn for self auth and rejects missing results', async () => {
		const providerConfig = createSelfProviderConfig()
		const providerConfigWithoutResolvedDn = createSelfProviderConfig({
			ldap: {
				connection: {
					tlsOptions: {
						rejectUnauthorized: false,
					},
					url: 'ldaps://ldap.example.com',
				},
				user: {
					dn: async () => '',
				},
			},
		})

		expect(await resolveRequiredUserDn(providerConfig, {
			ctx,
			username: 'mark',
		})).toBe('uid=mark,ou=people,dc=example,dc=com')
		await expect(resolveRequiredUserDn(providerConfigWithoutResolvedDn, {
			ctx,
			username: 'mark',
		})).rejects.toBeInstanceOf(LdapConfigError)
		await expect(resolveRequiredUserDn(providerConfigWithoutResolvedDn, {
			ctx,
			username: 'mark',
		})).rejects.toThrow('LDAP user.dn is required')
	})

	it('escapes username before passing it to the self user.dn resolver', async () => {
		let resolvedUsername: string | undefined
		const providerConfig = createSelfProviderConfig({
			ldap: {
				connection: {
					tlsOptions: {
						rejectUnauthorized: false,
					},
					url: 'ldaps://ldap.example.com',
				},
				user: {
					dn: ({ username }) => {
						resolvedUsername = username
						return `uid=${username},ou=people,dc=example,dc=com`
					},
				},
			},
		})

		expect(await resolveRequiredUserDn(providerConfig, {
			ctx,
			username: 'mark,admin',
		})).toBe('uid=mark\\,admin,ou=people,dc=example,dc=com')
		expect(resolvedUsername).toBe('mark\\,admin')
	})

	it('resolves user search baseDn from resolver input, fallback values, and throws when missing', async () => {
		const providerConfig = createSelfProviderConfig()
		const resolverInput = createUserSearchResolverInput(
			providerConfig,
			{
				ctx,
				username: 'mark',
			},
			'uid=mark,ou=people,dc=example,dc=com',
		)
		let receivedUserDn: string | undefined

		expect(await resolveUserSearchBaseDN({
			baseDn: ({ userDn }) => {
				receivedUserDn = userDn
				return userDn ?? ''
			},
		}, resolverInput)).toBe('uid=mark,ou=people,dc=example,dc=com')
		expect(receivedUserDn).toBe('uid=mark,ou=people,dc=example,dc=com')
		expect(await resolveUserSearchBaseDN({}, resolverInput, 'ou=people,dc=example,dc=com'))
			.toBe('ou=people,dc=example,dc=com')
		await expect(resolveUserSearchBaseDN({}, resolverInput))
			.rejects
			.toBeInstanceOf(LdapConfigError)
		await expect(resolveUserSearchBaseDN({}, resolverInput))
			.rejects
			.toThrow('LDAP user.search.baseDn or user.dn is required')
	})

	it('resolves search options and omits baseDn from the final search object', async () => {
		const providerConfig = createSelfProviderConfig()
		const resolverInput = createUserSearchResolverInput(
			providerConfig,
			{
				ctx,
				username: 'mark',
			},
			'uid=mark,ou=people,dc=example,dc=com',
		)

		const searchOptions = await resolveSearchOptions(
			{
				attributes: ['dn'],
				baseDn: 'ou=people,dc=example,dc=com',
				filter: async ({ username, userDn }) => {
					expect(userDn).toBe('uid=mark,ou=people,dc=example,dc=com')
					return `(uid=${username})`
				},
				sizeLimit: 1,
			},
			resolverInput,
			'sub',
		)

		expect(searchOptions).toEqual({
			attributes: ['dn'],
			filter: '(uid=mark)',
			scope: 'sub',
			sizeLimit: 1,
		})
		expect('baseDn' in searchOptions).toBe(false)
	})

	it('builds resolver input and resolves baseDn helpers', async () => {
		const providerConfig = createSelfProviderConfig()
		const resolverInput = createUserSearchResolverInput(
			providerConfig,
			{
				ctx,
				username: 'mark',
			},
			'uid=mark,ou=people,dc=example,dc=com',
		)

		expect(resolverInput).toEqual({
			ctx,
			providerId: 'corp',
			userDn: 'uid=mark,ou=people,dc=example,dc=com',
			username: 'mark',
		})
		expect(await resolveBaseDN(
			({ providerId }) => `ou=${providerId},dc=example,dc=com`,
			resolverInput,
		)).toBe('ou=corp,dc=example,dc=com')
	})

	it('normalizes client options based on the LDAP transport', () => {
		expect(resolveClientOptions({
			startTLS: true,
			tlsOptions: {
				rejectUnauthorized: false,
			},
			url: 'ldap://ldap.example.com',
		})).toEqual({
			url: 'ldap://ldap.example.com',
		})
		expect(resolveClientOptions({
			startTLS: true,
			tlsOptions: {
				rejectUnauthorized: false,
			},
			url: 'ldaps://ldap.example.com',
		})).toEqual({
			tlsOptions: {
				rejectUnauthorized: false,
			},
			url: 'ldaps://ldap.example.com',
		})
	})

	it('discriminates admin and self auth provider configs', () => {
		const adminProviderConfig = createAdminProviderConfig()
		const selfProviderConfig = createSelfProviderConfig()

		expect(isAdminAuthConfig(adminProviderConfig)).toBe(true)
		expect(isSelfAuthConfig(adminProviderConfig)).toBe(false)
		expect(isAdminAuthConfig(selfProviderConfig)).toBe(false)
		expect(isSelfAuthConfig(selfProviderConfig)).toBe(true)
	})
})

function createAdminProviderConfig(
	overrides: Partial<AdminProviderConfig> = {},
): AdminProviderConfig {
	return {
		providerId: 'corp',
		ldap: {
			connection: {
				startTLS: true,
				tlsOptions: {
					rejectUnauthorized: false,
				},
				url: 'ldap://ldap.example.com',
			},
			admin: {
				dn: 'cn=read-only-admin,dc=example,dc=com',
				password: 'admin-password',
			},
			user: {
				dn: ({ username }) => `uid=${username},ou=people,dc=example,dc=com`,
			},
		},
		...overrides,
	}
}

function createSelfProviderConfig(
	overrides: Partial<SelfProviderConfig> = {},
): SelfProviderConfig {
	return {
		providerId: 'corp',
		ldap: {
			connection: {
				tlsOptions: {
					rejectUnauthorized: false,
				},
				url: 'ldaps://ldap.example.com',
			},
			user: {
				dn: ({ username }) => `uid=${username},ou=people,dc=example,dc=com`,
			},
		},
		...overrides,
	}
}
