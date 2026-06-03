import type { GenericEndpointContext } from 'better-auth'
import type { ClientOptions, Entry, Filter, SearchOptions } from 'ldapts'
import type { LdapUserProfile } from './ldap'

type Awaitable<T> = T | Promise<T>

export type LdapEndpointContext = GenericEndpointContext

export interface LdapGroupProfile extends Entry {}

export interface LdapUserInfo extends Record<string, unknown> {
	id: string
	email: string
	name: string
	emailVerified?: boolean | undefined
	image?: string | null | undefined
}

export interface LdapRuntimeCredentials {
	providerId: string
	username: string
	password: string
	ctx: LdapEndpointContext
}

export interface LdapUserDnResolverInput extends Omit<LdapRuntimeCredentials, 'password'> {}

export interface LdapUserSearchResolverInput extends LdapRuntimeCredentials {
	userDn?: string | undefined
}

export interface LdapGroupSearchResolverInput extends LdapRuntimeCredentials {
	userDn: string
	profile: LdapUserProfile
}

export type LdapBaseDnResolver<TInput> = string | ((input: TInput) => Awaitable<string>)

export type LdapFilterResolver<TInput> = string | Filter | ((input: TInput) => Awaitable<string | Filter>)

export interface LdapConnectionConfig extends ClientOptions {
	startTLS?: boolean | undefined
}

export interface LdapAdminConfig {
	dn: string | ((ctx: LdapEndpointContext) => Awaitable<string>)
	password: string | ((ctx: LdapEndpointContext) => Awaitable<string>)
}

export interface LdapUserSearchConfig extends Omit<SearchOptions, 'filter'> {
	baseDn?: LdapBaseDnResolver<LdapUserSearchResolverInput> | undefined
	filter?: LdapFilterResolver<LdapUserSearchResolverInput> | undefined
}

export interface LdapGroupSearchConfig extends Omit<SearchOptions, 'filter'> {
	baseDn: LdapBaseDnResolver<LdapGroupSearchResolverInput>
	filter?: LdapFilterResolver<LdapGroupSearchResolverInput> | undefined
}

export interface LdapUserGroupConfig {
	search: LdapGroupSearchConfig
}

export interface LdapUserConfigBase {
	search?: LdapUserSearchConfig
	group?: LdapUserGroupConfig
}

export interface LdapAdminUserConfig extends LdapUserConfigBase {
	dn?: string | ((input: LdapUserDnResolverInput) => Awaitable<string>) | undefined
}

export interface LdapSelfUserConfig extends LdapUserConfigBase {
	dn: string | ((input: LdapUserDnResolverInput) => Awaitable<string>)
}

export interface LdapAuthConfigBase {
	connection: LdapConnectionConfig
}

export interface LdapAdminAuthConfig extends LdapAuthConfigBase {
	admin: LdapAdminConfig
	user: LdapAdminUserConfig
}

export interface LdapSelfAuthConfig extends LdapAuthConfigBase {
	admin?: never
	user: LdapSelfUserConfig
}

export type LdapAuthConfig = LdapAdminAuthConfig | LdapSelfAuthConfig

export interface LdapMapProfileInput {
	providerId: string
	username: string
	profile: LdapUserProfile
	ctx: LdapEndpointContext
}

export interface LdapProviderConfig {
	providerId: string
	ldap: LdapAuthConfig
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

export class LdapConfigError extends Error {}

export async function resolveAdminDn(
	providerConfig: LdapProviderConfig & { ldap: LdapAdminAuthConfig },
	ctx: LdapEndpointContext,
): Promise<string> {
	return typeof providerConfig.ldap.admin.dn === 'function'
		? await providerConfig.ldap.admin.dn(ctx)
		: providerConfig.ldap.admin.dn
}

export async function resolveAdminPassword(
	providerConfig: LdapProviderConfig & { ldap: LdapAdminAuthConfig },
	ctx: LdapEndpointContext,
): Promise<string> {
	return typeof providerConfig.ldap.admin.password === 'function'
		? await providerConfig.ldap.admin.password(ctx)
		: providerConfig.ldap.admin.password
}

export async function resolveOptionalUserDn(
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

export async function resolveRequiredUserDn(
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

export async function resolveUserSearchBaseDN(
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

export async function resolveBaseDN<TInput>(
	baseDn: LdapBaseDnResolver<TInput>,
	input: TInput,
): Promise<string> {
	return typeof baseDn === 'function'
		? await baseDn(input)
		: baseDn
}

export async function resolveSearchOptions<TInput>(
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

export function createUserSearchResolverInput(
	providerConfig: LdapProviderConfig,
	input: {
		ctx: LdapEndpointContext
		password: string
		username: string
	},
	userDn?: string,
): LdapUserSearchResolverInput {
	return {
		ctx: input.ctx,
		password: input.password,
		providerId: providerConfig.providerId,
		username: input.username,
		userDn,
	}
}

export function resolveClientOptions(connection: LdapConnectionConfig): ClientOptions {
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

export function isAdminAuthConfig(
	providerConfig: LdapProviderConfig,
): providerConfig is LdapProviderConfig & { ldap: LdapAdminAuthConfig } {
	return providerConfig.ldap.admin !== undefined
}

export function isSelfAuthConfig(
	providerConfig: LdapProviderConfig,
): providerConfig is LdapProviderConfig & { ldap: LdapSelfAuthConfig } {
	return providerConfig.ldap.admin === undefined
}

async function resolveFilter<TInput>(
	filter: LdapFilterResolver<TInput> | undefined,
	input: TInput,
): Promise<SearchOptions['filter'] | undefined> {
	if (typeof filter === 'function') {
		return await filter(input)
	}

	return filter
}

function isLdaps(url: string): boolean {
	return url.startsWith('ldaps://')
}
