import type { ClientOptions, SearchOptions } from 'ldapts'
import type {
	LdapAdminAuthConfig,
	LdapConnectionConfig,
	LdapEndpointContext,
	LdapFilterResolver,
	LdapGroupProfile,
	LdapGroupSearchConfig,
	LdapGroupSearchResolverInput,
	LdapMapProfileInput,
	LdapProviderConfig,
	LdapSelfAuthConfig,
	LdapUserInfo,
	LdapUserProfile,
	LdapUserSearchConfig,
	LdapUserSearchResolverInput,
} from './index'
import { Buffer } from 'node:buffer'
import { APIError } from 'better-auth/api'
import { Client, InvalidCredentialsError, NoSuchObjectError } from 'ldapts'
import { LDAP_ERROR_CODES } from './error'

class LdapConfigError extends Error {}

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
				createRuntimeCredentials(providerConfig, input),
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
						...createRuntimeCredentials(providerConfig, input),
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
				createRuntimeCredentials(providerConfig, input),
				userDn,
			)

			if (providerConfig.ldap.user.group) {
				profile.groups = await searchForGroupProfiles(
					userClient,
					providerConfig.ldap.user.group.search,
					{
						...createRuntimeCredentials(providerConfig, input),
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
			throw new APIError('BAD_REQUEST', {
				code: LDAP_ERROR_CODES.AUTHENTICATION_FAILED,
				message: getErrorMessage(error, 'Invalid LDAP authentication options'),
			})
		}

		if (error instanceof InvalidCredentialsError) {
			throw new APIError('UNAUTHORIZED', {
				code: LDAP_ERROR_CODES.CREDENTIAL_INVALID,
				message: 'Invalid LDAP credentials',
			})
		}

		throw new APIError('UNAUTHORIZED', {
			code: LDAP_ERROR_CODES.AUTHENTICATION_FAILED,
			message: getErrorMessage(error, 'LDAP authentication failed'),
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

async function resolveAdminDn(
	providerConfig: LdapProviderConfig & { ldap: LdapAdminAuthConfig },
	ctx: LdapEndpointContext,
): Promise<string> {
	return typeof providerConfig.ldap.admin.dn === 'function'
		? await providerConfig.ldap.admin.dn(ctx)
		: providerConfig.ldap.admin.dn
}

async function resolveAdminPassword(
	providerConfig: LdapProviderConfig & { ldap: LdapAdminAuthConfig },
	ctx: LdapEndpointContext,
): Promise<string> {
	return typeof providerConfig.ldap.admin.password === 'function'
		? await providerConfig.ldap.admin.password(ctx)
		: providerConfig.ldap.admin.password
}

async function resolveOptionalUserDn(
	providerConfig: LdapProviderConfig & { ldap: LdapAdminAuthConfig },
	input: {
		ctx: LdapEndpointContext
		username: string
	},
): Promise<string | undefined> {
	const userDn = providerConfig.ldap.user.dn
	if (!userDn) {
		return
	}

	return typeof userDn === 'function'
		? await userDn({
			ctx: input.ctx,
			providerId: providerConfig.providerId,
			username: input.username,
		})
		: userDn
}

async function resolveRequiredUserDn(
	providerConfig: LdapProviderConfig & { ldap: LdapSelfAuthConfig },
	input: {
		ctx: LdapEndpointContext
		username: string
	},
): Promise<string> {
	const userDn = typeof providerConfig.ldap.user.dn === 'function'
		? await providerConfig.ldap.user.dn({
			ctx: input.ctx,
			providerId: providerConfig.providerId,
			username: input.username,
		})
		: providerConfig.ldap.user.dn

	if (!userDn) {
		throw new LdapConfigError('LDAP user.dn is required')
	}

	return userDn
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
		if (connection.startTLS && !isLdaps(connection.url)) {
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
	searchConfig: LdapUserSearchConfig,
	input: LdapUserSearchResolverInput,
	fallbackBaseDN?: string,
): Promise<LdapUserProfile> {
	const baseDn = await resolveUserSearchBaseDN(searchConfig, input, fallbackBaseDN)
	const searchOptions = await resolveSearchOptions(searchConfig, input, 'base')

	let searchEntries
	try {
		({ searchEntries } = await client.search(baseDn, searchOptions))
	}
	catch (error) {
		if (error instanceof NoSuchObjectError) {
			throw new APIError('UNAUTHORIZED', {
				code: LDAP_ERROR_CODES.IDENTITY_NOT_FOUND,
				message: 'Invalid LDAP credentials',
			})
		}

		throw error
	}

	if (!searchEntries.length || !searchEntries[0]?.dn) {
		throw new APIError('UNAUTHORIZED', {
			code: LDAP_ERROR_CODES.IDENTITY_NOT_FOUND,
			message: 'Invalid LDAP credentials',
		})
	}

	if (searchEntries.length > 1) {
		throw new APIError('UNAUTHORIZED', {
			code: LDAP_ERROR_CODES.IDENTITY_AMBIGUOUS,
			message: 'Invalid LDAP credentials',
		})
	}

	return toUserProfile(searchEntries[0])
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

async function resolveUserSearchBaseDN(
	searchConfig: LdapUserSearchConfig,
	input: LdapUserSearchResolverInput,
	fallbackBaseDN?: string,
): Promise<string> {
	if (searchConfig.baseDn !== undefined) {
		return resolveBaseDN(searchConfig.baseDn, input)
	}

	if (fallbackBaseDN) {
		return fallbackBaseDN
	}

	throw new LdapConfigError('LDAP user.search.baseDn or user.dn is required')
}

async function resolveBaseDN<TInput>(
	baseDn: string | ((input: TInput) => Promise<string> | string),
	input: TInput,
): Promise<string> {
	return typeof baseDn === 'function'
		? await baseDn(input)
		: baseDn
}

async function resolveSearchOptions<TInput>(
	searchConfig: Omit<SearchOptions, 'filter'> & {
		baseDn?: unknown
		filter?: LdapFilterResolver<TInput> | undefined
	},
	input: TInput,
	defaultScope: NonNullable<SearchOptions['scope']>,
): Promise<SearchOptions> {
	const {
		baseDn: _baseDN,
		filter,
		scope,
		...searchOptions
	} = searchConfig

	const resolvedFilter = await resolveFilter(filter, input)

	return {
		...searchOptions,
		...(resolvedFilter ? { filter: resolvedFilter } : {}),
		scope: scope ?? defaultScope,
	}
}

async function resolveFilter<TInput>(
	filter: LdapFilterResolver<TInput> | undefined,
	input: TInput,
): Promise<SearchOptions['filter'] | undefined> {
	if (typeof filter === 'function') {
		return filter(input)
	}

	return filter
}

function createRuntimeCredentials(
	providerConfig: LdapProviderConfig,
	input: {
		ctx: LdapEndpointContext
		password: string
		username: string
	},
): LdapUserSearchResolverInput {
	return {
		ctx: input.ctx,
		password: input.password,
		providerId: providerConfig.providerId,
		username: input.username,
	}
}

function toUserProfile(
	profile: Record<string, unknown> & { dn: string },
): LdapUserProfile {
	return {
		...profile,
		dn: profile.dn,
	}
}

function resolveClientOptions(connection: LdapConnectionConfig): ClientOptions {
	const {
		startTLS: _startTLS,
		...clientOptions
	} = connection

	if (isLdaps(connection.url)) {
		return clientOptions
	}

	const { tlsOptions: _tlsOptions, ...plainOptions } = clientOptions
	return plainOptions
}

function isLdaps(url: string): boolean {
	return url.startsWith('ldaps://')
}

function isAdminAuthConfig(
	providerConfig: LdapProviderConfig,
): providerConfig is LdapProviderConfig & { ldap: LdapAdminAuthConfig } {
	return providerConfig.ldap.admin !== undefined
}

function isSelfAuthConfig(
	providerConfig: LdapProviderConfig,
): providerConfig is LdapProviderConfig & { ldap: LdapSelfAuthConfig } {
	return providerConfig.ldap.admin === undefined
}

async function safeUnbind(client: Client | undefined): Promise<void> {
	if (!client?.isConnected) {
		return
	}

	await client.unbind().catch(() => undefined)
}

function getErrorMessage(
	error: unknown,
	fallback: string,
): string {
	return error instanceof Error ? error.message : fallback
}
