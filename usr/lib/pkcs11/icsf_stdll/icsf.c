/*
 * Licensed materials, Property of IBM Corp.
 *
 * OpenCryptoki ICSF token - LDAP functions
 *
 * (C) COPYRIGHT International Business Machines Corp. 2012
 *
 * Author: Marcelo Cerri (mhcerri@br.ibm.com)
 *
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "icsf.h"

/* For logging functions: */
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"


/*
 * Perform a simple bind to `uri` using `dn` and `password` as credentials.
 */
int
icsf_login(LDAP **ld, const char *uri, const char *dn, const char *password)
{
	int rc;
	struct berval cred;

	/* Connect to LDAP server */
	OCK_LOG_DEBUG("Connecting to: %s\n", uri);
	rc = ldap_initialize(ld, uri);
	if (rc != LDAP_SUCCESS) {
		OCK_LOG_DEBUG("Failed to connect to \"%s\": %s (%d)\n", uri,
			      ldap_err2string(rc), rc);
		return -1;
	}

	OCK_LOG_DEBUG("Binding with DN: %s\n", dn);
	cred.bv_len = strlen(password);
	cred.bv_val = (char *) password;
	rc = ldap_sasl_bind_s(*ld, dn, LDAP_SASL_SIMPLE, &cred, NULL, NULL,
			      NULL);
	if (rc != LDAP_SUCCESS) {
		OCK_LOG_DEBUG("LDAP bind failed: %s (%d)\n",
			      ldap_err2string(rc), rc);
		return -1;
	}

	return 0;
}

/*
 * Disconnect from the server.
 */
int icsf_logout(LDAP *ld)
{
	int rc;

	rc = ldap_unbind_ext_s(ld, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		OCK_LOG_DEBUG("Failed to unbind: %s (%d)\n",
			      ldap_err2string(rc), rc);
		return -1;
	}

	return 0;
}
