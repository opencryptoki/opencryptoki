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

int
icsf_login(LDAP **ld, const char *uri, const char *dn,
	   const char *password);

#endif
