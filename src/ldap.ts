import type { Entry } from 'ldapts'
import type {
	LdapConnectionConfig,
	LdapEndpointContext,
	LdapGroupProfile,
	LdapGroupSearchConfig,
	LdapGroupSearchResolverInput,
	LdapMapProfileInput,
	LdapProviderConfig,
	LdapUserInfo,
	LdapUserSearchConfig,
	LdapUserSearchResolverInput,
} from './options'
import { Buffer } from 'node:buffer'
import { APIError } from 'better-auth/api'
import { Client, InvalidCredentialsError, NoSuchObjectError } from 'ldapts'
import { LDAP_ERROR_CODES } from './error-codes'
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

export type LdapUserProfile = Entry & {
	groups?: LdapGroupProfile[] | undefined
}

export async function authenticateLdapUserProfile(
	providerConfig: LdapProviderConfig,
	input: {
		ctx: LdapEndpointContext
		password: string
		username: string
	},
): Promise<LdapUserProfile> {
	let adminClient: Client | undefined
	let userClient: Client | undefined

	try {
		if (isAdminAuthConfig(providerConfig)) {
			adminClient = await createBoundClient(
				providerConfig.ldap.connection,
				await resolveAdminDn(providerConfig, input.ctx),
				await resolveAdminPassword(providerConfig, input.ctx),
			)

			const fallbackUserDn = await resolveOptionalUserDn(providerConfig, input)
			const profile = await searchForSingleUserProfile(
				adminClient,
				providerConfig.ldap.user.search,
				createUserSearchResolverInput(providerConfig, input, fallbackUserDn),
				fallbackUserDn,
			)

			userClient = await createBoundClient(
				providerConfig.ldap.connection,
				profile.dn,
				input.password,
			)

			if (providerConfig.ldap.user.group) {
				profile.groups = await searchForGroupProfiles(
					adminClient,
					providerConfig.ldap.user.group.search,
					{
						...createUserSearchResolverInput(providerConfig, input),
						profile,
						userDn: profile.dn,
					},
				)
			}

			return profile
		}

		if (isSelfAuthConfig(providerConfig)) {
			const userDn = await resolveRequiredUserDn(providerConfig, input)
			userClient = await createBoundClient(
				providerConfig.ldap.connection,
				userDn,
				input.password,
			)

			const profile = await searchForSingleUserProfile(
				userClient,
				providerConfig.ldap.user.search,
				createUserSearchResolverInput(providerConfig, input, userDn),
				userDn,
			)

			if (providerConfig.ldap.user.group) {
				profile.groups = await searchForGroupProfiles(
					userClient,
					providerConfig.ldap.user.group.search,
					{
						...createUserSearchResolverInput(providerConfig, input),
						profile,
						userDn: profile.dn,
					},
				)
			}

			return profile
		}

		throw new LdapConfigError('Invalid LDAP authentication config')
	}
	catch (error) {
		if (error instanceof APIError) {
			throw error
		}

		if (error instanceof LdapConfigError) {
			throw APIError.from('BAD_REQUEST', {
				...LDAP_ERROR_CODES.LDAP_AUTHENTICATION_FAILED,
				message: getErrorMessage(error, 'Invalid LDAP authentication options'),
			})
		}

		if (error instanceof InvalidCredentialsError) {
			throw APIError.from('UNAUTHORIZED', LDAP_ERROR_CODES.LDAP_CREDENTIAL_INVALID)
		}

		throw APIError.from('UNAUTHORIZED', {
			...LDAP_ERROR_CODES.LDAP_AUTHENTICATION_FAILED,
			message: getErrorMessage(error, LDAP_ERROR_CODES.LDAP_AUTHENTICATION_FAILED.message),
		})
	}
	finally {
		await safeUnbind(userClient)
		await safeUnbind(adminClient)
	}
}

export async function mapProfileToUser(
	providerConfig: LdapProviderConfig,
	input: LdapMapProfileInput,
): Promise<LdapUserInfo> {
	const userInfo = (typeof providerConfig.mapProfileToUser) === 'function'
		? await providerConfig.mapProfileToUser(input)
		: getDefaultUserInfo(input.profile, input.username)

	if (!userInfo) {
		throw APIError.from('UNAUTHORIZED', LDAP_ERROR_CODES.LDAP_USER_INFO_MISSING)
	}

	if (!userInfo.id) {
		throw APIError.from('UNAUTHORIZED', LDAP_ERROR_CODES.LDAP_USER_ID_MISSING)
	}

	if (!userInfo.email) {
		throw APIError.from('UNAUTHORIZED', LDAP_ERROR_CODES.LDAP_USER_EMAIL_MISSING)
	}

	if (!userInfo.name) {
		throw APIError.from('UNAUTHORIZED', LDAP_ERROR_CODES.LDAP_USER_NAME_MISSING)
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

async function createBoundClient(
	connection: LdapConnectionConfig,
	dn: string,
	password: string,
): Promise<Client> {
	let client: Client
	try {
		client = new Client(resolveClientOptions(connection))
	}
	catch (error) {
		throw new LdapConfigError(getErrorMessage(error, 'Invalid LDAP connection config'))
	}

	try {
		if (connection.startTLS && !connection.url.startsWith('ldaps://')) {
			await client.startTLS(connection.tlsOptions)
		}

		await client.bind(dn, password)
		return client
	}
	catch (error) {
		await safeUnbind(client)
		throw error
	}
}

async function searchForSingleUserProfile(
	client: Client,
	searchConfig: LdapUserSearchConfig | undefined,
	input: LdapUserSearchResolverInput,
	fallbackBaseDN?: string,
): Promise<LdapUserProfile> {
	const resolvedSearchConfig = searchConfig ?? {}
	const baseDn = await resolveUserSearchBaseDN(resolvedSearchConfig, input, fallbackBaseDN)
	const searchOptions = await resolveSearchOptions(resolvedSearchConfig, input, 'base')

	let searchEntries
	try {
		({ searchEntries } = await client.search(baseDn, searchOptions))
	}
	catch (error) {
		if (error instanceof NoSuchObjectError) {
			throw APIError.from('UNAUTHORIZED', LDAP_ERROR_CODES.LDAP_IDENTITY_NOT_FOUND)
		}

		throw error
	}

	if (!searchEntries.length || !searchEntries[0]?.dn) {
		throw APIError.from('UNAUTHORIZED', LDAP_ERROR_CODES.LDAP_IDENTITY_NOT_FOUND)
	}

	if (searchEntries.length > 1) {
		throw APIError.from('UNAUTHORIZED', LDAP_ERROR_CODES.LDAP_IDENTITY_AMBIGUOUS)
	}

	return searchEntries[0]
}

async function searchForGroupProfiles(
	client: Client,
	searchConfig: LdapGroupSearchConfig,
	input: LdapGroupSearchResolverInput,
): Promise<LdapGroupProfile[]> {
	const baseDn = await resolveBaseDN(searchConfig.baseDn, input)
	const searchOptions = await resolveSearchOptions(searchConfig, input, 'sub')
	const { searchEntries } = await client.search(baseDn, searchOptions)

	return searchEntries.map(group => ({ ...group }))
}

async function safeUnbind(client: Client | undefined): Promise<void> {
	if (!client?.isConnected) {
		return
	}

	await client.unbind().catch(() => undefined)
}

function getFirstString(profile: LdapUserProfile, fieldNames: string[]): string | undefined {
	for (const fieldName of fieldNames) {
		const value = normalizeString(profile[fieldName])
		if (value) {
			return value
		}
	}
}

function getErrorMessage(
	error: unknown,
	fallback: string,
): string {
	return error instanceof Error ? error.message : fallback
}
