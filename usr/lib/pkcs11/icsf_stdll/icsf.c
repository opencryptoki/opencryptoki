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
 * Ensure that LDAPv3 is used. V3 is needed for extended operations.
 */
static int
icsf_force_ldap_v3(LDAP *ld)
{
	int rc;
	int version = 0;

	rc = ldap_get_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
	if (rc != LDAP_OPT_SUCCESS) {
		OCK_LOG_DEBUG("Failed to get LDAP version: %s (%d)\n",
			      ldap_err2string(rc), rc);
		return -1;
	}
	if (version < LDAP_VERSION3) {
		OCK_LOG_DEBUG("Changing version from %d to %d.\n",
			      version, LDAP_VERSION3);
		version = LDAP_VERSION3;
		rc = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
		if (rc != LDAP_OPT_SUCCESS) {
			OCK_LOG_DEBUG("Failed to set LDAP version: %s (%d)\n",
				      ldap_err2string(rc), rc);
			return -1;
		}
	}

	return 0;
}

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

	if (icsf_force_ldap_v3(*ld))
		return -1;

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

/*
 * Check if the ICSF LDAP extension is supported by the server.
 */
int icsf_check_pkcs_extension(LDAP *ld)
{
	int rc = -1;
	int ret;
	LDAPMessage *res = NULL;
	LDAPMessage *entry = NULL;
	BerElement *ber = NULL;
	char *attr = NULL;
	char expected_attr[] = "supportedextension";
	char *attr_list[] = { expected_attr, NULL };
	const char *expected_oid = ICSF_REQ_OID;

	/* Search root DSE. */
	ret = ldap_search_ext_s(ld, "",			/* Base DN */
				LDAP_SCOPE_BASE,	/* Scope */
				"(objectclass=*)",	/* Filter */
				attr_list,		/* Attribute list */
				0,			/* Attributes only */
				NULL,			/* Server controls */
				NULL,			/* Client controls */
				NULL,			/* Timeout */
				0,			/* Size limit */
				&res);
	if (ret)
		goto cleanup;

	/* It should contain just one entry */
	entry = ldap_first_entry(ld, res);
	if (entry == NULL)
		goto cleanup;

	/* Loop through attributes */
	attr = ldap_first_attribute(ld, entry, &ber);
	while (attr) {
		if (!strcmp(expected_attr, attr)) {
			/* Get the value for each attribute */
			struct berval **it;
			struct berval **values =
			    ldap_get_values_len(ld, entry, attr);
			if (values == NULL)
				goto cleanup;

			/* Print each value */
			for (it = values; *it; it++)
				if (!strncmp(expected_oid, (*it)->bv_val,
					     sizeof(expected_oid))) {
					/* It's supported */
					rc = 0;
				}

			ldap_value_free_len(values);

			if (rc == 0)
				goto cleanup;
		}

		/* Get next attribute */
		ldap_memfree(attr);
		attr = ldap_next_attribute(ld, entry, ber);
	}

	/* Not supported. */
	rc = 1;

cleanup:
	if (attr)
		ldap_memfree(attr);
	if (ber)
		ber_free(ber, 0);
	if (res)
		ldap_msgfree(res);

	return rc;
}
