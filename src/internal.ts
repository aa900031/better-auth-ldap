import type { AuthenticationOptions } from 'ldap-authentication'
import type { LdapErrorCode } from './error'
import type {
	LdapEndpointContext,
	LdapMapProfileInput,
	LdapProviderConfig,
	LdapUserInfo,
	LdapUserProfile,
} from './index'
import { Buffer } from 'node:buffer'
import { APIError } from 'better-auth/api'
import {
	AUTH_RESULT_FAILURE,
	AUTH_RESULT_FAILURE_CREDENTIAL_INVALID,
	AUTH_RESULT_FAILURE_IDENTITY_AMBIGUOUS,
	AUTH_RESULT_FAILURE_IDENTITY_NOT_FOUND,
	AUTH_RESULT_FAILURE_UNCATEGORIZED,
	AUTH_RESULT_SUCCESS,
	authenticateResult,
} from 'ldap-authentication'
import { LDAP_ERROR_CODES } from './error'

export async function authenticateLdapUserProfile(
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

export async function resolveAuthenticationOptions(
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

export async function mapProfileToUser(
	providerConfig: LdapProviderConfig,
	input: LdapMapProfileInput,
): Promise<LdapUserInfo> {
	const userInfo = (typeof providerConfig.mapProfileToUser) === 'function'
		? await providerConfig.mapProfileToUser(input)
		: getDefaultUserInfo(input.profile, input.username)

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

export function getDefaultUserInfo(
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

export function normalizeString(value: unknown): string | undefined {
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

export function getAuthenticationErrorCode(
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
