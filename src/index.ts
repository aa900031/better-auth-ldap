import type { GenericEndpointContext } from '@better-auth/core'
import type { BetterAuthPlugin } from 'better-auth'
import type { AuthenticationOptions } from 'ldap-authentication'
import type { LdapErrorCode } from './error'
import { Buffer } from 'node:buffer'
import { APIError, createAuthEndpoint } from 'better-auth/api'
import { setSessionCookie } from 'better-auth/cookies'
import { handleOAuthUserInfo } from 'better-auth/oauth2'
import {
	AUTH_RESULT_FAILURE,
	AUTH_RESULT_FAILURE_CREDENTIAL_INVALID,
	AUTH_RESULT_FAILURE_IDENTITY_AMBIGUOUS,
	AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND,
	AUTH_RESULT_FAILURE_UNCATEGORIZED,
	AUTH_RESULT_SUCCESS,
	authenticateResult,
} from 'ldap-authentication'
import * as z from 'zod'
import { LDAP_ERROR_CODES } from './error'

export { LDAP_ERROR_CODES } from './error'

type Awaitable<T> = T | Promise<T>

export type LdapEndpointContext = GenericEndpointContext

export interface LdapUserProfile extends Record<string, unknown> {
	dn?: string | undefined
}

export interface LdapUserInfo extends Record<string, unknown> {
	id: string
	email: string
	name: string
	emailVerified?: boolean | undefined
	image?: string | null | undefined
}

export interface LdapUserDnInput {
	providerId: string
	username: string
	ctx: LdapEndpointContext
}

export type LdapAuthenticationConfig = Omit<
	AuthenticationOptions,
	'username' | 'userPassword' | 'userDn'
> & {
	userDn?: string | ((input: LdapUserDnInput) => Awaitable<string>) | undefined
}

export interface LdapMapProfileInput {
	providerId: string
	username: string
	profile: LdapUserProfile
	ctx: LdapEndpointContext
}

export interface LdapProviderConfig {
	providerId: string
	ldap: LdapAuthenticationConfig
	disableImplicitSignUp?: boolean | undefined
	disableSignUp?: boolean | undefined
	overrideUserInfo?: boolean | undefined
	mapProfileToUser?:
		| ((input: LdapMapProfileInput) => Awaitable<Partial<LdapUserInfo> | undefined>)
		| undefined
}

export interface LdapOptions {
	config: LdapProviderConfig[]
}

export interface LdapPlugin extends BetterAuthPlugin {
	id: 'ldap'
	endpoints: {
		signInWithLdap: ReturnType<typeof signInWithLdap>
	}
	options: LdapOptions
}

const signInWithLdapBodySchema = z.object({
	providerId: z.string().min(1).meta({
		description: 'The provider ID for the LDAP provider',
	}),
	username: z.string().min(1).meta({
		description: 'The LDAP username to authenticate',
	}),
	password: z.string().min(1).meta({
		description: 'The LDAP password to authenticate',
	}),
	requestSignUp: z.boolean().optional().meta({
		description: 'Explicitly request sign-up when implicit sign-up is disabled',
	}),
})

export function ldap(
	options: LdapOptions,
): LdapPlugin {
	return {
		id: 'ldap',
		endpoints: {
			signInWithLdap: signInWithLdap(options),
		},
		options,
	} satisfies LdapPlugin
}

// eslint-disable-next-line ts/explicit-function-return-type
function signInWithLdap(
	options: LdapOptions,
) {
	return createAuthEndpoint(
		'/sign-in/ldap',
		{
			method: 'POST',
			body: signInWithLdapBodySchema,
			metadata: {
				allowedMediaTypes: [
					'application/x-www-form-urlencoded',
					'application/json',
				],
				openapi: {
					operationId: 'signInWithLdap',
					description: 'Sign in with LDAP',
					responses: {
						200: {
							description: 'Successfully signed in with LDAP',
							content: {
								'application/json': {
									schema: {
										type: 'object',
										properties: {
											user: { type: 'object' },
										},
										required: ['user'],
									},
								},
							},
						},
					},
				},
			},
		},
		async (ctx) => {
			const providerConfig = options.config.find(
				config => config.providerId === ctx.body.providerId,
			)

			if (!providerConfig) {
				throw new APIError('BAD_REQUEST', {
					code: LDAP_ERROR_CODES.PROVIDER_CONFIG_NOT_FOUND,
					message: `LDAP provider config not found: ${ctx.body.providerId}`,
				})
			}

			const profile = await authenticateLdapUserProfile(providerConfig, {
				ctx,
				password: ctx.body.password,
				username: ctx.body.username,
			})

			const userInfo = await mapProfileToUser(providerConfig, {
				ctx,
				profile,
				providerId: providerConfig.providerId,
				username: ctx.body.username,
			})

			const result = await handleOAuthUserInfo(ctx, {
				userInfo: {
					id: userInfo.id,
					email: userInfo.email,
					name: userInfo.name,
					emailVerified: userInfo.emailVerified ?? false,
					image: userInfo.image ?? undefined,
				},
				account: {
					providerId: providerConfig.providerId,
					accountId: userInfo.id,
				},
				disableSignUp:
					providerConfig.disableSignUp
					|| (providerConfig.disableImplicitSignUp && !ctx.body.requestSignUp),
				overrideUserInfo: providerConfig.overrideUserInfo,
			})

			if (result.error) {
				throw new APIError('UNAUTHORIZED', {
					code: LDAP_ERROR_CODES.LINK_ERROR,
					message: result.error,
				})
			}

			const { session, user } = result.data!
			await setSessionCookie(
				ctx,
				{
					session,
					user,
				},
			)

			return ctx.json({
				user,
			})
		},
	)
}

async function authenticateLdapUserProfile(
	providerConfig: LdapProviderConfig,
	input: {
		ctx: LdapEndpointContext
		password: string
		username: string
	},
): Promise<LdapUserProfile> {
	let authenticationOptions: AuthenticationOptions

	try {
		authenticationOptions = await resolveAuthenticationOptions(providerConfig, input)
	}
	catch (error) {
		throw new APIError('BAD_REQUEST', {
			code: LDAP_ERROR_CODES.AUTHENTICATION_FAILED,
			message: getErrorMessage(error, 'Invalid LDAP authentication options'),
		})
	}

	let authenticationResult: Awaited<ReturnType<typeof authenticateResult>>
	try {
		authenticationResult = await authenticateResult(authenticationOptions)
	}
	catch (error) {
		throw new APIError('UNAUTHORIZED', {
			code: LDAP_ERROR_CODES.AUTHENTICATION_FAILED,
			message: getErrorMessage(error, 'LDAP authentication failed'),
		})
	}

	if (authenticationResult.code !== AUTH_RESULT_SUCCESS) {
		throw new APIError('UNAUTHORIZED', {
			code: getAuthenticationErrorCode(authenticationResult.code),
			message: 'Invalid LDAP credentials',
		})
	}

	if (!isProfile(authenticationResult.user)) {
		throw new APIError('UNAUTHORIZED', {
			code: LDAP_ERROR_CODES.USER_INFO_MISSING,
			message: 'LDAP user info is missing',
		})
	}

	return authenticationResult.user
}

async function resolveAuthenticationOptions(
	providerConfig: LdapProviderConfig,
	input: {
		ctx: LdapEndpointContext
		password: string
		username: string
	},
): Promise<AuthenticationOptions> {
	const { userDn, ...ldapOptions } = providerConfig.ldap
	const resolvedUserDn = typeof userDn === 'function'
		? await userDn({
				ctx: input.ctx,
				providerId: providerConfig.providerId,
				username: input.username,
			})
		: userDn

	return {
		...ldapOptions,
		...(resolvedUserDn ? { userDn: resolvedUserDn } : {}),
		username: input.username,
		userPassword: input.password,
	}
}

async function mapProfileToUser(
	providerConfig: LdapProviderConfig,
	input: LdapMapProfileInput,
): Promise<LdapUserInfo> {
	const defaultUserInfo = getDefaultUserInfo(input.profile, input.username)
	const mappedUserInfo = await providerConfig.mapProfileToUser?.(input)
	const userInfo = {
		...defaultUserInfo,
		...mappedUserInfo,
	}

	if (!userInfo.id) {
		throw new APIError('UNAUTHORIZED', {
			code: LDAP_ERROR_CODES.USER_ID_MISSING,
			message: 'LDAP user id is missing',
		})
	}

	if (!userInfo.email) {
		throw new APIError('UNAUTHORIZED', {
			code: LDAP_ERROR_CODES.USER_EMAIL_MISSING,
			message: 'LDAP user email is missing',
		})
	}

	if (!userInfo.name) {
		throw new APIError('UNAUTHORIZED', {
			code: LDAP_ERROR_CODES.USER_NAME_MISSING,
			message: 'LDAP user name is missing',
		})
	}

	return {
		...userInfo,
		email: userInfo.email.toLowerCase(),
		emailVerified: userInfo.emailVerified ?? false,
	}
}

function getDefaultUserInfo(
	profile: LdapUserProfile,
	username: string,
): LdapUserInfo {
	const id = getFirstString(profile, [
		'dn',
		'uid',
		'sAMAccountName',
		'userPrincipalName',
		'mail',
	]) ?? username
	const email = getFirstString(profile, [
		'mail',
		'userPrincipalName',
		'email',
	])
	const name = getFirstString(profile, [
		'cn',
		'displayName',
		'name',
		'uid',
		'sAMAccountName',
	]) ?? username
	const image = getFirstString(profile, [
		'jpegPhoto',
		'thumbnailPhoto',
		'jpegPhoto;binary',
		'thumbnailPhoto;binary',
	])

	return {
		id,
		email: email ?? '',
		name,
		emailVerified: false,
		...(image ? { image } : {}),
	}
}

function getFirstString(profile: LdapUserProfile, fieldNames: string[]): string | undefined {
	for (const fieldName of fieldNames) {
		const value = normalizeString(profile[fieldName])
		if (value) {
			return value
		}
	}
}

function normalizeString(value: unknown): string | undefined {
	if (typeof value === 'string') {
		return value.trim() || undefined
	}

	if (typeof value === 'number' || typeof value === 'boolean') {
		return String(value)
	}

	if (Array.isArray(value)) {
		for (const item of value) {
			const normalizedItem = normalizeString(item)
			if (normalizedItem) {
				return normalizedItem
			}
		}
	}

	if (value instanceof Uint8Array) {
		return Buffer.from(value).toString('base64')
	}
}

function isProfile(value: unknown): value is LdapUserProfile {
	return typeof value === 'object'
		&& value !== null
		&& !Array.isArray(value)
}

function getAuthenticationErrorCode(
	code: number,
): LdapErrorCode {
	switch (code) {
		case AUTH_RESULT_FAILURE_CREDENTIAL_INVALID:
			return LDAP_ERROR_CODES.CREDENTIAL_INVALID
		case AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND:
			return LDAP_ERROR_CODES.IDENTITY_NOT_FOUND
		case AUTH_RESULT_FAILURE_IDENTITY_AMBIGUOUS:
			return LDAP_ERROR_CODES.IDENTITY_AMBIGUOUS
		case AUTH_RESULT_FAILURE_UNCATEGORIZED:
		case AUTH_RESULT_FAILURE:
		default:
			return LDAP_ERROR_CODES.AUTHENTICATION_FAILED
	}
}

function getErrorMessage(
	error: unknown,
	fallback: string,
): string {
	return error instanceof Error ? error.message : fallback
}
