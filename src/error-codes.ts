import { defineErrorCodes } from 'better-auth'

export const LDAP_ERROR_CODES = defineErrorCodes({
	LDAP_PROVIDER_CONFIG_NOT_FOUND: 'LDAP provider config not found',
	LDAP_AUTHENTICATION_FAILED: 'LDAP authentication failed',
	LDAP_CREDENTIAL_INVALID: 'Invalid LDAP credentials',
	LDAP_IDENTITY_NOT_FOUND: 'Invalid LDAP credentials',
	LDAP_IDENTITY_AMBIGUOUS: 'Invalid LDAP credentials',
	LDAP_USER_INFO_MISSING: 'LDAP user info is missing',
	LDAP_USER_EMAIL_MISSING: 'LDAP user email is missing',
	LDAP_USER_ID_MISSING: 'LDAP user id is missing',
	LDAP_USER_NAME_MISSING: 'LDAP user name is missing',
	LDAP_LINK_ERROR: 'Failed to link LDAP account',
})
