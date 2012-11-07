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

#ifndef ICSF_H
#define ICSF_H

#include <ldap.h>
#include "pkcs11types.h"

/* OIDs used for PKCS extension */
#define ICSF_REQ_OID "1.3.18.0.2.12.83"
#define ICSF_RES_OID "1.3.18.0.2.12.84"

int
icsf_login(LDAP **ld, const char *uri, const char *dn,
	   const char *password);

int
icsf_sasl_login(LDAP **ld, const char *uri, const char *cert,
	        const char *key, const char *ca, const char *ca_dir);

int
icsf_logout(LDAP *ld);

int
icsf_check_pkcs_extension(LDAP *ld);

#endif
