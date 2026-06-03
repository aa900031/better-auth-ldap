import type {
	LdapAdminAuthConfig,
	LdapEndpointContext,
	LdapProviderConfig,
	LdapSelfAuthConfig,
} from './options'
import { APIError } from 'better-auth/api'
import { InvalidCredentialsError } from 'ldapts'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { LDAP_ERROR_CODES } from './error-codes'
import {
	authenticateLdapUserProfile,
	getDefaultUserInfo,
	mapProfileToUser,
} from './ldap'

type AdminProviderConfig = LdapProviderConfig & { ldap: LdapAdminAuthConfig }
type SelfProviderConfig = LdapProviderConfig & { ldap: LdapSelfAuthConfig }

const mocks = vi.hoisted(() => {
	return {
		bindQueue: [] as Array<{ error?: unknown }>,
		clients: [] as Array<{
			bind: ReturnType<typeof vi.fn>
			isConnected: boolean
			options: Record<string, unknown>
			search: ReturnType<typeof vi.fn>
			startTLS: ReturnType<typeof vi.fn>
			unbind: ReturnType<typeof vi.fn>
		}>,
		searchQueue: [] as Array<{
			error?: unknown
			result?: {
				searchEntries: Array<Record<string, unknown> & { dn: string }>
				searchReferences: string[]
			}
		}>,
	}
})

vi.mock('ldapts', async () => {
	const actual = await vi.importActual<typeof import('ldapts')>('ldapts')

	class MockClient {
		public bind = vi.fn(async () => {
			const next = mocks.bindQueue.shift()
			if (next?.error) {
				throw next.error
			}
		})

		public isConnected = true

		public options: Record<string, unknown>

		public search = vi.fn(async () => {
			const next = mocks.searchQueue.shift()
			if (next?.error) {
				throw next.error
			}

			return next?.result ?? {
				searchEntries: [],
				searchReferences: [],
			}
		})

		public startTLS = vi.fn(async () => undefined)

		public unbind = vi.fn(async () => {
			this.isConnected = false
		})

		public constructor(options: Record<string, unknown>) {
			this.options = options
			mocks.clients.push(this)
		}
	}

	return {
		...actual,
		Client: MockClient,
	}
})

const ctx = {
	context: {
		baseURL: 'https://app.example.com',
	},
} as LdapEndpointContext

describe('authenticateLdapUserProfile', () => {
	beforeEach(() => {
		mocks.bindQueue.length = 0
		mocks.clients.length = 0
		mocks.searchQueue.length = 0
		vi.clearAllMocks()
	})

	it('authenticates in admin mode and performs user and group searches with the expected defaults', async () => {
		mocks.bindQueue.push({}, {})
		mocks.searchQueue.push(
			{
				result: {
					searchEntries: [
						{
							cn: 'Mark Lee',
							dn: 'uid=mark,ou=people,dc=example,dc=com',
							mail: 'mark@example.com',
						},
					],
					searchReferences: [],
				},
			},
			{
				result: {
					searchEntries: [
						{
							cn: 'Engineering',
							dn: 'cn=engineering,ou=groups,dc=example,dc=com',
						},
					],
					searchReferences: [],
				},
			},
		)

		const profile = await authenticateLdapUserProfile(createAdminProviderConfig(), {
			ctx,
			password: 'password',
			username: 'mark',
		})

		expect(profile).toEqual({
			cn: 'Mark Lee',
			dn: 'uid=mark,ou=people,dc=example,dc=com',
			groups: [
				{
					cn: 'Engineering',
					dn: 'cn=engineering,ou=groups,dc=example,dc=com',
				},
			],
			mail: 'mark@example.com',
		})

		expect(mocks.clients).toHaveLength(2)
		expect(mocks.clients[0]!.options).toEqual({
			url: 'ldap://ldap.example.com',
		})
		expect(mocks.clients[0]!.startTLS).toHaveBeenCalledWith({
			rejectUnauthorized: false,
		})
		expect(mocks.clients[0]!.bind).toHaveBeenCalledWith(
			'cn=read-only-admin,dc=example,dc=com',
			'admin-password',
		)
		expect(mocks.clients[0]!.search).toHaveBeenNthCalledWith(
			1,
			'uid=mark,ou=people,dc=example,dc=com',
			expect.objectContaining({
				attributes: ['dn', 'mail', 'cn'],
				scope: 'base',
			}),
		)
		expect(mocks.clients[0]!.search).toHaveBeenNthCalledWith(
			2,
			'ou=groups,dc=example,dc=com',
			expect.objectContaining({
				filter: '(member=uid=mark,ou=people,dc=example,dc=com)',
				scope: 'sub',
			}),
		)
		expect(mocks.clients[1]!.bind).toHaveBeenCalledWith(
			'uid=mark,ou=people,dc=example,dc=com',
			'password',
		)
		expect(mocks.clients[1]!.search).not.toHaveBeenCalled()
	})

	it('authenticates in self mode and falls back to user.dn when user.search.baseDn is omitted', async () => {
		mocks.bindQueue.push({})
		mocks.searchQueue.push({
			result: {
				searchEntries: [
					{
						cn: 'Mark Lee',
						dn: 'uid=mark,ou=people,dc=example,dc=com',
						mail: 'mark@example.com',
					},
				],
				searchReferences: [],
			},
		})

		const profile = await authenticateLdapUserProfile(createSelfProviderConfig(), {
			ctx,
			password: 'password',
			username: 'mark',
		})

		expect(profile).toEqual({
			cn: 'Mark Lee',
			dn: 'uid=mark,ou=people,dc=example,dc=com',
			mail: 'mark@example.com',
		})

		expect(mocks.clients).toHaveLength(1)
		expect(mocks.clients[0]!.options).toEqual({
			tlsOptions: {
				rejectUnauthorized: false,
			},
			url: 'ldaps://ldap.example.com',
		})
		expect(mocks.clients[0]!.startTLS).not.toHaveBeenCalled()
		expect(mocks.clients[0]!.bind).toHaveBeenCalledWith(
			'uid=mark,ou=people,dc=example,dc=com',
			'password',
		)
		expect(mocks.clients[0]!.search).toHaveBeenCalledWith(
			'uid=mark,ou=people,dc=example,dc=com',
			expect.objectContaining({
				attributes: ['dn', 'mail', 'cn'],
				scope: 'base',
			}),
		)
	})

	it('authenticates in self mode when user.search is omitted', async () => {
		mocks.bindQueue.push({})
		mocks.searchQueue.push({
			result: {
				searchEntries: [
					{
						cn: 'Mark Lee',
						dn: 'uid=mark,ou=people,dc=example,dc=com',
						mail: 'mark@example.com',
					},
				],
				searchReferences: [],
			},
		})

		const profile = await authenticateLdapUserProfile(createSelfProviderConfig({
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
		}), {
			ctx,
			password: 'password',
			username: 'mark',
		})

		expect(profile).toEqual({
			cn: 'Mark Lee',
			dn: 'uid=mark,ou=people,dc=example,dc=com',
			mail: 'mark@example.com',
		})

		expect(mocks.clients[0]!.search).toHaveBeenCalledWith(
			'uid=mark,ou=people,dc=example,dc=com',
			expect.objectContaining({
				scope: 'base',
			}),
		)
	})

	it('authenticates in admin mode when user.search is omitted and falls back to user.dn', async () => {
		mocks.bindQueue.push({}, {})
		mocks.searchQueue.push({
			result: {
				searchEntries: [
					{
						cn: 'Mark Lee',
						dn: 'uid=mark,ou=people,dc=example,dc=com',
						mail: 'mark@example.com',
					},
				],
				searchReferences: [],
			},
		})

		const profile = await authenticateLdapUserProfile(createAdminProviderConfig({
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
		}), {
			ctx,
			password: 'password',
			username: 'mark',
		})

		expect(profile).toEqual({
			cn: 'Mark Lee',
			dn: 'uid=mark,ou=people,dc=example,dc=com',
			mail: 'mark@example.com',
		})

		expect(mocks.clients[0]!.search).toHaveBeenCalledWith(
			'uid=mark,ou=people,dc=example,dc=com',
			expect.objectContaining({
				scope: 'base',
			}),
		)
	})

	it('maps invalid credentials to the expected API error code', async () => {
		mocks.bindQueue.push({
			error: new InvalidCredentialsError('invalid credentials'),
		})

		await expectApiError(authenticateLdapUserProfile(createSelfProviderConfig(), {
			ctx,
			password: 'wrong-password',
			username: 'mark',
		}), {
			status: 'UNAUTHORIZED',
			body: {
				code: LDAP_ERROR_CODES.LDAP_CREDENTIAL_INVALID.code,
				message: 'Invalid LDAP credentials',
			},
		})
	})

	it('rejects ambiguous user search results', async () => {
		mocks.bindQueue.push({})
		mocks.searchQueue.push({
			result: {
				searchEntries: [
					{
						dn: 'uid=mark,ou=people,dc=example,dc=com',
					},
					{
						dn: 'uid=mark2,ou=people,dc=example,dc=com',
					},
				],
				searchReferences: [],
			},
		})

		await expectApiError(authenticateLdapUserProfile(createSelfProviderConfig(), {
			ctx,
			password: 'password',
			username: 'mark',
		}), {
			status: 'UNAUTHORIZED',
			body: {
				code: LDAP_ERROR_CODES.LDAP_IDENTITY_AMBIGUOUS.code,
				message: 'Invalid LDAP credentials',
			},
		})
	})

	it('rejects admin mode without user.search and user.dn', async () => {
		mocks.bindQueue.push({})

		await expectApiError(authenticateLdapUserProfile(createAdminProviderConfig({
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
		}), {
			ctx,
			password: 'password',
			username: 'mark',
		}), {
			status: 'BAD_REQUEST',
			body: {
				code: LDAP_ERROR_CODES.LDAP_AUTHENTICATION_FAILED.code,
				message: 'LDAP user.search.baseDn or user.dn is required',
			},
		})
	})
})

describe('getDefaultUserInfo', () => {
	it('derives default user info from preferred LDAP fields and binary photos', () => {
		const userInfo = getDefaultUserInfo(
			{
				displayName: 'Mark Lee',
				dn: 'uid=mark,ou=people,dc=example,dc=com',
				userPrincipalName: [' ', 'MARK@EXAMPLE.COM'],
			},
			'mark',
		)

		expect(userInfo).toEqual({
			email: 'MARK@EXAMPLE.COM',
			emailVerified: false,
			id: 'uid=mark,ou=people,dc=example,dc=com',
			name: 'Mark Lee',
		})
	})
})

describe('mapProfileToUser', () => {
	it('merges partial mapped fields with default user info', async () => {
		const providerConfig = createSelfProviderConfig({
			mapProfileToUser: async () => ({
				emailVerified: true,
				image: 'https://example.com/avatar.png',
			}),
		})

		const userInfo = await mapProfileToUser(providerConfig, {
			ctx,
			profile: {
				cn: 'Mark Lee',
				dn: 'uid=mark,ou=people,dc=example,dc=com',
				mail: 'MARK@EXAMPLE.COM',
			},
			providerId: 'corp',
			username: 'mark',
		})

		expect(userInfo).toEqual({
			email: 'MARK@EXAMPLE.COM',
			emailVerified: true,
			id: 'uid=mark,ou=people,dc=example,dc=com',
			image: 'https://example.com/avatar.png',
			name: 'Mark Lee',
		})
	})

	it('merges mapped fields with defaults and preserves overridden email casing', async () => {
		const providerConfig = createSelfProviderConfig({
			mapProfileToUser: async () => ({
				name: 'Mark Lee',
				id: 'directory-guid',
				email: 'Override@Example.Com',
				emailVerified: true,
				image: 'https://example.com/avatar.png',
			}),
		})

		const userInfo = await mapProfileToUser(providerConfig, {
			ctx,
			profile: {
				cn: 'Mark Lee',
				dn: 'uid=mark,ou=people,dc=example,dc=com',
				mail: 'ignored@example.com',
			},
			providerId: 'corp',
			username: 'mark',
		})

		expect(userInfo).toEqual({
			id: 'directory-guid',
			email: 'Override@Example.Com',
			name: 'Mark Lee',
			emailVerified: true,
			image: 'https://example.com/avatar.png',
		})
	})

	it('treats blank mapped values as invalid overrides', async () => {
		const providerConfig = createSelfProviderConfig({
			mapProfileToUser: async () => ({
				email: ' ',
				id: '',
				name: '   ',
			}),
		})

		await expectApiError(mapProfileToUser(providerConfig, {
			ctx,
			profile: {
				cn: 'Mark Lee',
				dn: 'uid=mark,ou=people,dc=example,dc=com',
				mail: 'mark@example.com',
			},
			providerId: 'corp',
			username: 'mark',
		}), {
			status: 'UNAUTHORIZED',
			body: {
				code: LDAP_ERROR_CODES.LDAP_USER_ID_MISSING.code,
				message: 'LDAP user id is missing',
			},
		})
	})

	it('rejects mapped users without an email address', async () => {
		await expectApiError(mapProfileToUser(createSelfProviderConfig(), {
			ctx,
			profile: {
				cn: 'Mark Lee',
				dn: 'uid=mark,ou=people,dc=example,dc=com',
				uid: 'mark',
			},
			providerId: 'corp',
			username: 'mark',
		}), {
			status: 'UNAUTHORIZED',
			body: {
				code: LDAP_ERROR_CODES.LDAP_USER_EMAIL_MISSING.code,
				message: 'LDAP user email is missing',
			},
		})
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
				search: {
					attributes: ['dn', 'mail', 'cn'],
				},
				group: {
					search: {
						baseDn: 'ou=groups,dc=example,dc=com',
						filter: ({ userDn }) => `(member=${userDn})`,
					},
				},
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
				search: {
					attributes: ['dn', 'mail', 'cn'],
				},
			},
		},
		...overrides,
	}
}

async function expectApiError(
	promise: Promise<unknown>,
	expected: {
		status: string
		body: {
			code: string
			message: string
		}
	},
): Promise<void> {
	const error = await promise.catch(cause => cause)

	expect(error).toBeInstanceOf(APIError)
	expect(error).toMatchObject(expected)
}
