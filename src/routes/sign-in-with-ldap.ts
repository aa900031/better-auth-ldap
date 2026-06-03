import type { LdapOptions } from '../options'
import { APIError } from 'better-auth'
import { createAuthEndpoint } from 'better-auth/api'
import { setSessionCookie } from 'better-auth/cookies'
import { handleOAuthUserInfo } from 'better-auth/oauth2'
import * as z from 'zod'
import { LDAP_ERROR_CODES } from '../error-codes'
import { authenticateLdapUserProfile, mapProfileToUser } from '../ldap'
import { escapeRdnValue } from '../utils/escape'

// eslint-disable-next-line ts/explicit-function-return-type
export function signInWithLdap(
	options: LdapOptions,
) {
	const BodySchema = z.object({
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

	return createAuthEndpoint(
		'/sign-in/ldap',
		{
			method: 'POST',
			body: BodySchema,
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
				throw APIError.from('BAD_REQUEST', {
					...LDAP_ERROR_CODES.LDAP_PROVIDER_CONFIG_NOT_FOUND,
					message: `LDAP provider config not found: ${ctx.body.providerId}`,
				})
			}

			const username = escapeRdnValue(ctx.body.username)
			const password = ctx.body.password

			const profile = await authenticateLdapUserProfile(providerConfig, {
				ctx,
				username,
				password,
			})

			const userInfo = await mapProfileToUser(providerConfig, {
				ctx,
				profile,
				username,
				providerId: providerConfig.providerId,
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
				throw APIError.from('UNAUTHORIZED', {
					...LDAP_ERROR_CODES.LDAP_LINK_ERROR,
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
