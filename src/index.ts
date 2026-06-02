import type { GenericEndpointContext } from '@better-auth/core'
import type { BetterAuthPlugin } from 'better-auth'
import type { ClientOptions, Entry, Filter, SearchOptions } from 'ldapts'
import { APIError, createAuthEndpoint } from 'better-auth/api'
import { setSessionCookie } from 'better-auth/cookies'
import { handleOAuthUserInfo } from 'better-auth/oauth2'
import * as z from 'zod'
import { LDAP_ERROR_CODES } from './error'
import { authenticateLdapUserProfile, mapProfileToUser } from './internal'

export { LDAP_ERROR_CODES } from './error'

type Awaitable<T> = T | Promise<T>

export type LdapEndpointContext = GenericEndpointContext

export interface LdapGroupProfile extends Entry {}

export interface LdapUserProfile extends Record<string, unknown> {
	dn: string
	groups?: LdapGroupProfile[] | undefined
}

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

export interface LdapUserSearchResolverInput extends LdapRuntimeCredentials {}

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
	search: LdapUserSearchConfig
	group?: LdapUserGroupConfig | undefined
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
		| ((input: LdapMapProfileInput) => Awaitable<LdapUserInfo>)
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
