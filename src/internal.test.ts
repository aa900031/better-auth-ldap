import type { LdapEndpointContext, LdapProviderConfig } from './index'
import { APIError } from 'better-auth/api'
import { AUTH_RESULT_FAILURE_CREDENTIAL_INVALID } from 'ldap-authentication'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { LDAP_ERROR_CODES } from './error'
import {
	authenticateLdapUserProfile,
	getDefaultUserInfo,
	mapProfileToUser,
	resolveAuthenticationOptions,
} from './internal'

const mocks = vi.hoisted(() => {
	return {
		authenticateResult: vi.fn(),
	}
})

vi.mock('ldap-authentication', async () => {
	const actual = await vi.importActual<typeof import('ldap-authentication')>('ldap-authentication')

	return {
		...actual,
		authenticateResult: mocks.authenticateResult,
	}
})

const ctx = {
	context: {
		baseURL: 'https://app.example.com',
	},
} as LdapEndpointContext

function createProviderConfig(
	overrides: Partial<LdapProviderConfig> = {},
): LdapProviderConfig {
	return {
		providerId: 'corp',
		ldap: {
			ldapOpts: {
				url: 'ldap://ldap.example.com',
			},
		},
		...overrides,
	}
}

describe('ldap internal helpers', () => {
	beforeEach(() => {
		vi.clearAllMocks()
	})

	it('resolves LDAP options with credentials and a dynamic userDn callback', async () => {
		const providerConfig = createProviderConfig({
			ldap: {
				ldapOpts: {
					url: 'ldap://ldap.example.com',
				},
				userDn: ({ username }) => `uid=${username},ou=people,dc=example,dc=com`,
			},
		})

		const options = await resolveAuthenticationOptions(providerConfig, {
			ctx,
			password: 'password',
			username: 'mark',
		})

		expect(options).toEqual({
			ldapOpts: {
				url: 'ldap://ldap.example.com',
			},
			userDn: 'uid=mark,ou=people,dc=example,dc=com',
			username: 'mark',
			userPassword: 'password',
		})
	})

	it('derives default user info from preferred LDAP fields and binary photos', () => {
		const userInfo = getDefaultUserInfo(
			{
				'userPrincipalName': [' ', 'MARK@EXAMPLE.COM'],
				'displayName': 'Mark Lee',
				'thumbnailPhoto;binary': Uint8Array.from([1, 2, 3]),
			},
			'mark',
		)

		expect(userInfo).toEqual({
			id: 'MARK@EXAMPLE.COM',
			email: 'MARK@EXAMPLE.COM',
			name: 'Mark Lee',
			emailVerified: false,
			image: 'AQID',
		})
	})

	it('merges mapped fields with defaults and normalizes email casing', async () => {
		const providerConfig = createProviderConfig({
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
				dn: 'uid=mark,ou=people,dc=example,dc=com',
				mail: 'ignored@example.com',
				cn: 'Mark Lee',
			},
			providerId: 'corp',
			username: 'mark',
		})

		expect(userInfo).toEqual({
			id: 'directory-guid',
			email: 'override@example.com',
			name: 'Mark Lee',
			emailVerified: true,
			image: 'https://example.com/avatar.png',
		})
	})

	it('rejects mapped users without an email address', async () => {
		await expectApiError(mapProfileToUser(createProviderConfig(), {
			ctx,
			profile: {
				uid: 'mark',
				cn: 'Mark Lee',
			},
			providerId: 'corp',
			username: 'mark',
		}), {
			status: 'UNAUTHORIZED',
			body: {
				code: LDAP_ERROR_CODES.USER_EMAIL_MISSING,
				message: 'LDAP user email is missing',
			},
		})
	})

	it('maps LDAP authentication failures to the expected API error code', async () => {
		mocks.authenticateResult.mockResolvedValue({
			code: AUTH_RESULT_FAILURE_CREDENTIAL_INVALID,
			user: null,
		})

		await expectApiError(authenticateLdapUserProfile(createProviderConfig(), {
			ctx,
			password: 'wrong-password',
			username: 'mark',
		}), {
			status: 'UNAUTHORIZED',
			body: {
				code: LDAP_ERROR_CODES.CREDENTIAL_INVALID,
				message: 'Invalid LDAP credentials',
			},
		})

		expect(mocks.authenticateResult).toHaveBeenCalledWith(expect.objectContaining({
			username: 'mark',
			userPassword: 'wrong-password',
		}))
	})

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
})
