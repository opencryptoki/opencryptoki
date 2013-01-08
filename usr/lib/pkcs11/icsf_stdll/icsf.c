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
 * Note about ICSF callable services:
 *
 * Any ICSF service uses a base data structure containing some common fields.
 * This base structure is described by the following ASN.1 definition:
 *
 * requestValue ::= SEQUENCE {
 * 	version		INTEGER,
 * 	exitData	OCTET STRING,
 * 	handle		OCTET STRING,
 * 	ruleArraySeq	RuleArraySeq,
 * 	requestData	CSFPInput
 * }
 *
 * RuleArraySeq ::= SEQUENCE {
 * 	ruleArrayCount	INTEGER,
 * 	ruleArray	OCTET STRING
 * }
 *
 * CSFPInput ::= CHOICE {
 * 	IQF	[CSFIQF]	IQFInput,
 * 	DMK	[CSFPDMK]	DMKInput,
 * 	DVK	[CSFPDVK]	DVKInput,
 * 	GAV	[CSFPGAV]	GAVInput,
 * 	GKP	[CSFPGKP]	GKPInput,
 * 	GSK	[CSFPGSK]	GSKInput,
 * 	HMG	[CSFPHMG]	HMGInput,
 * 	HMV	[CSFPHMV]	HMVInput,
 * 	OWH	[CSFPOWH]	OWHInput,
 * 	PKS	[CSFPPKS]	PKSInput,
 * 	PKV	[CSFPPKV]	PKVInput,
 * 	SAV	[CSFPSAV]	SAVInput,
 * 	SKD	[CSFPSKD]	SKDInput,
 * 	SKE	[CSFPSKE]	SKEInput,
 * 	TRC	[CSFPTRC]	TRCInput,
 * 	TRD	[CSFPTRD]	TRDInput,
 * 	TRL	[CSFPTRL]	TRLInput,
 * 	UWK	[CSFPUWK]	UWKInput,
 * 	WPK	[CSFPWPK]	WPKInput,
 * 	GLDTRD	[GLDTRD]	GLDTRDInput,
 * 	IQA	[CSFIQA]	IQAInput
 * }
 *
 * CSFPInput defines which service is being called. A different tag number
 * and data structure is defined for each service.
 *
 * In the same way, the output is also based on a common data structure.
 *
 * responseValue ::= SEQUENCE {
 * 	version		INTEGER,
 * 	ICSFRc		INTEGER (0 .. MaxCSFPInteger),
 * 	ICSFRsnCode	INTEGER (0 .. MaxCSFPInteger),
 * 	exitData	OCTET STRING,
 * 	handle		OCTET STRING,
 * 	responseData	CSFPOutput
 * }
 *
 * CSFPOutput ::= CHOICE {
 * 	IQF	[CSFIQF]	IQFOutput,
 * 	DMK	[CSFPDMK]	DMKOutput,
 * 	DVK	[CSFPDVK]	DVKOutput,
 * 	GAV	[CSFPGAV]	GAVOutput,
 * 	GKP	[CSFPGKP]	GKPOutput,
 * 	GSK	[CSFPGSK]	GSKOutput,
 * 	HMG	[CSFPHMG]	HMGOutput,
 * 	HMV	[CSFPHMV]	HMVOutput,
 * 	OWH	[CSFPOWH]	OWHOutput,
 * 	PKS	[CSFPPKS]	PKSOutput,
 * 	PKV	[CSFPPKV]	PKVOutput,
 * 	SAV	[CSFPSAV]	SAVOutput,
 * 	SKD	[CSFPSKD]	SKDOutput,
 * 	SKE	[CSFPSKE]	SKEOutput,
 * 	TRC	[CSFPTRC]	TRCOutput,
 * 	TRD	[CSFPTRD]	TRDOutput,
 * 	TRL	[CSFPTRL]	TRLOutput,
 * 	UWK	[CSFPUWK]	UWKOutput,
 * 	WPK	[CSFPWPK]	WPKOutput,
 * 	GLDTRD	[GLDTRD]	GLDTRDOutput,
 * 	IQA	[CSFIQA]	IQAOutput
 * }
 *
 * ICSFRc is the return code: 0 indicates success, 4 partial success and
 * values greater than 4 indicates an error. ICSFRsnCode is the reason code
 * that provides further details about an error.
 */

/* Macros for argument checking */
#define CHECK_ARG_NON_NULL(_arg) 					\
	if (_arg == NULL) { 						\
		OCK_LOG_DEBUG("Null argument \"%s\".\n", #_arg); 	\
		return -1; 						\
	}

#define CHECK_ARG_MAX_LEN(_arg, _length) 				\
	if (_arg && (strlen(_arg) > _length)) {				\
		OCK_LOG_DEBUG("String too long %s=\"%s\"\n",		\
			      #_arg, _arg);				\
		return -1;						\
	}

#define CHECK_ARG_NON_NULL_AND_MAX_LEN(_arg, _length) 			\
	CHECK_ARG_NON_NULL(_arg);					\
	CHECK_ARG_MAX_LEN(_arg, _length);

/*
 * Copy a null terminated string from `orig` to the buffer `dest` of length
 * `len` and fill the remaining bytes with `padding_char`. The result string is
 * not null terminated.
 */
static void
strpad(char *dest, const char *orig, size_t len, int padding_char)
{
	size_t str_len = strlen(orig);

	if (str_len > len)
		str_len = len;

	memcpy(dest, orig, str_len);
	if ((len - str_len) > 0)
		memset(dest + str_len, ' ', len - str_len);
}

/* Copy a string `orig` of length `len` and padded with `padding_char` to a null
 * terminated string `dest`. `dest` should be at least `len` + 1 bytes long.
 */
static void
strunpad(char *dest, const char *orig, size_t len, int padding_char)
{
	size_t i;

	for (i = len - 1; i; i--)
		if (orig[i - 1] != padding_char)
			break;

	strncpy(dest, orig, i);
	dest[i] = '\0';
}

/*
 * Ensure that LDAPv3 is used. V3 is needed for extended operations.
 */
static int
icsf_force_ldap_v3(LDAP *ld)
{
	int rc;
	int version = 0;

	CHECK_ARG_NON_NULL(ld);

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

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL(uri);
	CHECK_ARG_NON_NULL(dn);
	CHECK_ARG_NON_NULL(password);

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
 * Set the paths for private key, certificate and CA, which are used for
 * SASL authentication using external certificate.
 *
 * TODO: check why these options just work as globals (ld == NULL)
 */
static int
icsf_set_sasl_params(LDAP *ld, const char *cert, const char *key,
		     const char *ca, const char *ca_dir)
{
	int rc;

	CHECK_ARG_NON_NULL(ld);

	OCK_LOG_DEBUG("Preparing environment for TLS\n");
	if (cert) {
		OCK_LOG_DEBUG("Using certificate: %s\n", cert);
		rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_CERTFILE, cert);
		if (rc != LDAP_SUCCESS) {
			OCK_LOG_DEBUG("Failed to set certificate file for TLS: "
				      "%s (%d)\n", ldap_err2string(rc), rc);
			return -1;
		}
	}

	if (key) {
		OCK_LOG_DEBUG("Using private key: %s\n", key);
		rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_KEYFILE, key);
		if (rc != LDAP_SUCCESS) {
			OCK_LOG_DEBUG("Failed to set key file for TLS: "
				      "%s (%d)\n", ldap_err2string(rc), rc);
			return -1;
		}
	}

	if (ca) {
		OCK_LOG_DEBUG("Using CA certificate file: %s\n", ca);
		rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE, ca);
		if (rc != LDAP_SUCCESS) {
			OCK_LOG_DEBUG
			    ("Failed to set CA certificate file for TLS: "
			     "%s (%d)\n", ldap_err2string(rc), rc);
			return -1;
		}
	}

	if (ca_dir) {
		OCK_LOG_DEBUG("Using CA certificate dir: %s\n", ca_dir);
		rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTDIR, ca_dir);
		if (rc != LDAP_SUCCESS) {
			OCK_LOG_DEBUG
			    ("Failed to set CA certificate dir for TLS: "
			     "%s (%d)\n", ldap_err2string(rc), rc);
			return -1;
		}
	}

	return 0;
}

/*
 * Perform a SASL bind to `uri` using the given certificate, private key
 * and CA paths.
 */
int
icsf_sasl_login(LDAP **ld, const char *uri, const char *cert,
		const char *key, const char *ca, const char *ca_dir)
{
	int rc;

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL(uri);

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

	/* Initialize TLS */
	if (icsf_set_sasl_params(*ld, cert, key, ca, ca_dir))
		return -1;

	OCK_LOG_DEBUG("Binding\n");
	rc = ldap_sasl_bind_s(*ld, NULL, "EXTERNAL", NULL, NULL, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		char *ext_msg = NULL;
		ldap_get_option(*ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, &ext_msg);
		OCK_LOG_DEBUG("LDAP bind failed: %s (%d)%s%s\n",
			      ldap_err2string(rc), rc,
			      ext_msg ? "\nDetailed message: " : "",
			      ext_msg ? ext_msg : "");
		if (ext_msg)
			ldap_memfree(ext_msg);
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

	CHECK_ARG_NON_NULL(ld);

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

	CHECK_ARG_NON_NULL(ld);

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

/*
 * `icsf_create` is a helper function for CSFPTRC service, which is used for
 * token and object creation.
 *
 * `handle` identifies the token that will be created or the token in which a
 * object will be created. It should be always 44 bytes long, and its 32 first
 * bytes should the token name padded with blanks.
 *
 * `rule_array` should be a sequence of 8 bytes strings padded with blanks.
 * It indicates if a token or a object will be created, it can also change the
 * behaviour of the call (please refer to `icsf_create_token` and
 * `icsf_create_object` for details).
 *
 * `attribute_list_tag` identifies the format of the given attribute list. It
 * must be a context specific tag with tag number zero for tokens and tag
 * number 1 for objects.
 *
 * `attribute_list` is a sequence of bytes and its format differs for tokens and
 * objects (please refer to `icsf_create_token` and  `icsf_create_object` for
 * details).
 */
static int
icsf_create(LDAP *ld, char *handle, size_t *handle_len,
	    const char *rule_array, size_t rule_array_len,
	    ber_tag_t attribute_list_tag, const char *attribute_list,
	    size_t attribute_list_len)
{
	int rc = -1;
	BerElement *ber_req = NULL;
	BerElement *ber_res = NULL;
	struct berval *raw_req = NULL;
	struct berval *raw_res = NULL;
	char *response_oid = NULL;

	/* Variables used as input */
	int version = 1;
	char *exit_data = "";	/* Ignored */
	int rule_array_count;

	/* Variables used as output */
	int return_code = 0;
	int reason_code = 0;
	ber_tag_t tag = 0;
	struct berval *out_handle = NULL;

	/* Check sizes */
	if (handle_len == NULL || *handle_len != ICSF_HANDLE_LEN) {
		if (handle_len)
			OCK_LOG_DEBUG("Invalid handle length: %lu\n",
				      *handle_len);
		else
			OCK_LOG_DEBUG("Invalid handle length: (null)\n");
		OCK_LOG_ERR(ERR_ARGUMENTS_BAD);
		return -1;
	}

	if ((rule_array_len % ICSF_RULE_ITEM_LEN)) {
		OCK_LOG_DEBUG("Invalid rule array length: %lu\n",
			      rule_array_len);
		OCK_LOG_ERR(ERR_ARGUMENTS_BAD);
		return -1;
	}
	rule_array_count = rule_array_len / ICSF_RULE_ITEM_LEN;

	/* Allocate ber_req to encode message. */
	ber_req = ber_alloc_t(LBER_USE_DER);
	if (ber_req == NULL) {
		OCK_LOG_ERR(ERR_HOST_MEMORY);
		goto cleanup;
	}

	/* Encode message:
	 *
	 * TRCInput ::= SEQUENCE {
	 *     trcAttrs ::= CHOICE {
	 *         tokenAttrString   [0] OCTET STRING,
	 *         objectAttrList    [1] Attributes
	 *     }
	 * }
	 *
	 * Attributes ::= SEQUENCE OF SEQUENCE {
	 *    attrName          INTEGER,
	 *    attrValue         AttributeValue
	 * }
	 *
	 * AttributeValue ::= CHOICE {
	 *    charValue         [0] OCTET STRING,
	 *    intValue          [1] INTEGER
	 * }
	 *
	 */
	rc = ber_printf(ber_req, "{iso{io}t{to}}", version, exit_data,
			handle, *handle_len,
			rule_array_count, rule_array, rule_array_len,
			ICSF_TAG_CSFPTRC | LBER_CONSTRUCTED |
			LBER_CLASS_CONTEXT, attribute_list_tag, attribute_list,
			attribute_list_len);
	if (rc < 0) {
		OCK_LOG_DEBUG("Failed to encode message.\n");
		OCK_LOG_ERR(ERR_FUNCTION_FAILED);
		goto cleanup;
	}

	rc = ber_flatten(ber_req, &raw_req);
	if (rc) {
		OCK_LOG_DEBUG("Failed to flat BER data.\n");
		OCK_LOG_ERR(ERR_FUNCTION_FAILED);
		goto cleanup;
	}

	/* Call ICSF service */
	rc = ldap_extended_operation_s(ld, ICSF_REQ_OID, raw_req, NULL, NULL,
				       &response_oid, &raw_res);
	if (rc != LDAP_SUCCESS) {
		char *ext_msg = NULL;
		ldap_get_option(ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, &ext_msg);
		OCK_LOG_DEBUG("ICSF call failed: %s (%d)%s%s\n",
			      ldap_err2string(rc), rc,
			      ext_msg ? "\nDetailed message: " : "",
			      ext_msg ? ext_msg : "");
		if (ext_msg)
			ldap_memfree(ext_msg);
		OCK_LOG_ERR(ERR_FUNCTION_FAILED);
		goto cleanup;
	}

	/* Decode result */
	ber_res = ber_init(raw_res);
	if (ber_res == NULL) {
		OCK_LOG_DEBUG("Failed to create a response buffer\n");
		OCK_LOG_ERR(ERR_FUNCTION_FAILED);
		goto cleanup;
	}

	/*
	 * TRCOutput ::= NULL
	 */
	rc = ber_scanf(ber_res, "{iiixOtn}", &version, &return_code,
		       &reason_code, &out_handle, &tag);
	if (rc < 0) {
		OCK_LOG_DEBUG("Failed to decode message.\n");
		OCK_LOG_ERR(ERR_FUNCTION_FAILED);
		goto cleanup;
	}

	/* Copy handle */
	if (out_handle == NULL) {
		*handle_len = 0;
	} else {
		size_t len = (*handle_len < out_handle->bv_len) ? *handle_len
		    : out_handle->bv_len;
		memcpy(handle, out_handle->bv_val, len);
		*handle_len = len;
	}

	OCK_LOG_DEBUG("ICSF call result: %d (%d)\n", return_code, reason_code);

	if (ICSF_RC_IS_ERROR(return_code)) {
		OCK_LOG_DEBUG("ICSF call failed: %d (%d)\n", return_code,
			      reason_code);
		OCK_LOG_ERR(ERR_FUNCTION_FAILED);
		goto cleanup;
	}

	rc = 0;

cleanup:
	if (ber_req)
		ber_free(ber_req, 1);
	if (ber_res)
		ber_free(ber_res, 1);
	if (raw_req)
		ber_bvfree(raw_req);
	if (raw_res)
		ber_bvfree(raw_res);
	if (response_oid)
		ldap_memfree(response_oid);
	if (out_handle)
		ber_bvfree(out_handle);

	return rc;
}

/*
 * Create a new token. All parameters must be null terminated strings.
 */
int
icsf_create_token(LDAP *ld, const char *token_name,
		  const char *manufacturer, const char *model,
		  const char *serial)
{
	int rc = -1;
	char handle[ICSF_HANDLE_LEN];
	size_t handle_len = sizeof(handle);
	char rule_array[2 * ICSF_RULE_ITEM_LEN];
	char attribute_list[68] = { 0, };

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL_AND_MAX_LEN(token_name, ICSF_TOKEN_NAME_LEN);
	CHECK_ARG_NON_NULL_AND_MAX_LEN(manufacturer, ICSF_MANUFACTURER_LEN);
	CHECK_ARG_NON_NULL_AND_MAX_LEN(model, ICSF_MODEL_LEN);
	CHECK_ARG_NON_NULL_AND_MAX_LEN(serial, ICSF_SERIAL_LEN);

	/* The first 32 bytes of `handle` contains the token's name, The
	 * remaining bytes should be blank.
	 */
	strpad(handle, token_name, ICSF_TOKEN_NAME_LEN, ' ');
	memset(handle + ICSF_TOKEN_NAME_LEN, ' ',
	       sizeof(handle) - ICSF_TOKEN_NAME_LEN);

	/* Should be 8 bytes padded. It's a token creation and if the token
	 * already exists it is recreated.
	 */
	strpad(rule_array, "TOKEN", ICSF_RULE_ITEM_LEN, ' ');
	strpad(rule_array + ICSF_RULE_ITEM_LEN, "RECREATE", ICSF_RULE_ITEM_LEN,
	       ' ');

	/* For token creation, handle is composed by 32 bytes for manufacturer
	 * id, 16 bytes for model, 16 bytes for serial number, and 4 trailing
	 * bytes with zeros.
	 */
	strpad(attribute_list, manufacturer, ICSF_MANUFACTURER_LEN, ' ');
	strpad(attribute_list + ICSF_MANUFACTURER_LEN, model, ICSF_MODEL_LEN,
	       ' ');
	strpad(attribute_list + ICSF_MANUFACTURER_LEN + ICSF_MODEL_LEN, serial,
	       ICSF_SERIAL_LEN, ' ');

	rc = icsf_create(ld, handle, &handle_len,
			 rule_array, sizeof(rule_array),
			 0 | LBER_CLASS_CONTEXT,
			 attribute_list, sizeof(attribute_list));

	return rc;
}

int
icsf_destroy(LDAP *ld, char *handle, size_t handle_len,
	     const char *rule_array, size_t rule_array_len)
{
	int rc = -1;
	BerElement *ber_req = NULL;
	BerElement *ber_res = NULL;
	struct berval *raw_req = NULL;
	struct berval *raw_res = NULL;
	char *response_oid = NULL;

	/* Variables used as input */
	int version = 1;
	char *exit_data = "";	/* Ignored */
	int rule_array_count = 1;

	/* Variables used as output */
	int return_code = 0;
	int reason_code = 0;
	ber_tag_t tag = 0;

	/* Check sizes */
	if (handle_len != ICSF_HANDLE_LEN) {
		if (handle_len)
			OCK_LOG_DEBUG("Invalid handle length: %lu\n",
				      handle_len);
		else
			OCK_LOG_DEBUG("Invalid handle length: (null)\n");
		OCK_LOG_ERR(ERR_ARGUMENTS_BAD);
		return -1;
	}

	if ((rule_array_len % ICSF_RULE_ITEM_LEN)) {
		OCK_LOG_DEBUG("Invalid rule array length: %lu\n",
			      rule_array_len);
		OCK_LOG_ERR(ERR_ARGUMENTS_BAD);
		return -1;
	}
	rule_array_count = rule_array_len / ICSF_RULE_ITEM_LEN;

	/* Allocate ber_req to encode message. */
	ber_req = ber_alloc_t(LBER_USE_DER);
	if (ber_req == NULL) {
		OCK_LOG_ERR(ERR_HOST_MEMORY);
		goto cleanup;
	}

	/* Encode message:
	 *
	 * TRDInput ::= NULL
	 */
	rc = ber_printf(ber_req, "{iso{io}tn}", version, exit_data, handle,
			handle_len, rule_array_count, rule_array, rule_array_len,
			ICSF_TAG_CSFPTRD | LBER_PRIMITIVE | LBER_CLASS_CONTEXT);
	if (rc < 0) {
		OCK_LOG_DEBUG("Failed to encode message.\n");
		goto cleanup;
	}

	/* Get raw bytes */
	rc = ber_flatten(ber_req, &raw_req);
	if (rc) {
		OCK_LOG_DEBUG("Failed to flat BER data.\n");
		goto cleanup;
	}

	/* Call ICSF service */
	rc = ldap_extended_operation_s(ld, ICSF_REQ_OID, raw_req, NULL, NULL,
				       &response_oid, &raw_res);
	if (rc != LDAP_SUCCESS) {
		OCK_LOG_DEBUG("ICSF call failed: %s (%d)\n",
			      ldap_err2string(rc), rc);
		goto cleanup;
	}

	/* Decode result */
	ber_res = ber_init(raw_res);
	if (ber_res == NULL) {
		OCK_LOG_DEBUG("Failed to create a response buffer\n");
		goto cleanup;
	}

	/*
	 * TRDOutput ::= NULL
	 */
	rc = ber_scanf(ber_res, "{iiixxtn}", &version, &return_code,
		       &reason_code, &tag);
	if (rc < 0) {
		OCK_LOG_DEBUG("Failed to decode message.\n");
		goto cleanup;
	}

	OCK_LOG_DEBUG("ICSF call result: %d (%d)\n", return_code, reason_code);

	if (!ICSF_RC_IS_ERROR(return_code))
		rc = 0;

cleanup:
	if (ber_req)
		ber_free(ber_req, 1);
	if (ber_res)
		ber_free(ber_res, 1);
	if (raw_req)
		ber_bvfree(raw_req);
	if (raw_res)
		ber_bvfree(raw_res);
	if (response_oid)
		ldap_memfree(response_oid);

	return rc;

}

/*
 * Destroy a token.
 */
int icsf_destroy_token(LDAP *ld, char *token_name)
{
	/* Variables used as input */
	char handle[ICSF_HANDLE_LEN];
	char rule_array[1 * ICSF_RULE_ITEM_LEN];

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL_AND_MAX_LEN(token_name, ICSF_TOKEN_NAME_LEN);

	/* The first 32 bytes of `handle` contains the token's name, The
	 * remaining bytes should be blank.
	 */
	strpad(handle, token_name, ICSF_TOKEN_NAME_LEN, ' ');
	memset(handle + ICSF_TOKEN_NAME_LEN, ' ',
	       sizeof(handle) - ICSF_TOKEN_NAME_LEN);

	/* Should be 8 bytes padded. */
	strpad(rule_array, "TOKEN", ICSF_RULE_ITEM_LEN, ' ');

	return icsf_destroy(ld, handle, sizeof(handle), rule_array,
			    sizeof(rule_array));
}

/*
 * Parse a sequence of bytes `data` returned by a CSFPTRL call containing the
 * attributes of a token and store the parsed value in the structure `record`.
 *
 * The data is formated as the following:
 *   - 32 bytes for token name;
 *   - 32 bytes for manufacturer name;
 *   - 16 bytes for model identification;
 *   - 16 bytes for serial number;
 *   - 8 bytes for date in UTC of the last change encoded as a string in the
 *     format "yyyymmdd".
 *   - 8 bytes for time in UTC of the last change encoded as a string in the
 *     format "hhmmssth".
 *   - 4 bytes of flags (the first bit of the first byte indicate that the
 *     token is write protected).
 */
static void
parse_token_record(struct icsf_token_record *record, const char *data)
{
	size_t offset = 0;

	strunpad(record->name, data + offset, ICSF_TOKEN_NAME_LEN + 1, ' ');
	offset += ICSF_TOKEN_NAME_LEN;

	strunpad(record->manufacturer, data + offset, ICSF_MANUFACTURER_LEN + 1,
		 ' ');
	offset += ICSF_MANUFACTURER_LEN;

	strunpad(record->model, data + offset, ICSF_MODEL_LEN + 1, ' ');
	offset += ICSF_MODEL_LEN;

	strunpad(record->serial, data + offset, ICSF_SERIAL_LEN + 1, ' ');
	offset += ICSF_SERIAL_LEN;

	strunpad(record->date, data + offset, ICSF_DATE_LEN + 1, ' ');
	offset += ICSF_DATE_LEN;

	strunpad(record->time, data + offset, ICSF_TIME_LEN + 1, ' ');
	offset += ICSF_TIME_LEN;

	/* Flags are not a string, just a bunch of flags. So it doesn't need
	 * to be null terminated.
	 */
	memcpy(record->flags, data + offset, ICSF_FLAGS_LEN);
}

/*
 *
 * `icsf_list` is a helper function for CSFPTRL service, which is used for token
 * and object listing.
 *
 * `handle` identifies the last token or object returned by a previous call of
 * `icsf_list`. It should be always 44 bytes long and be in the following
 * format:
 *
 *    - For tokens:
 *      * 32 bytes containing the token name padded with blanks;
 *      * remaining bytes filled with blanks.
 *
 *    - For objects:
 *      * 32 bytes containing the token name padded with blanks;
 *      * 8 bytes containing the object's sequence number encoded int
 *        hexadecimal.
 *      * 1 byte with the character 'T' for token objects or 'S' for session
 *        objects.
 *      * remaining bytes filled with blanks.
 *
 * `rule_array` should be a sequence of 8 bytes strings padded with blanks.
 * It indicates if a list of tokens or a objects will be returned (please refer
 * to `icsf_create_token` and `icsf_create_object` for details).
 *
 * `bv_list` is an output buffer for the raw data and should be freed by the
 * caller.
 *
 * `list_len` is used as input to indicate the number of bytes of the buffer to
 * be returned, and it's updated with the number of bytes returned.
 *
 * `list_count` indicates how many items should be returned.
 */
static int
icsf_list(LDAP * ld, char *handle, size_t handle_len,
	  const char *rule_array, size_t rule_array_len,
	  struct berval **bv_list, size_t *list_len, size_t list_count)
{
	int rc = -1;
	BerElement *ber_req = NULL;
	BerElement *ber_res = NULL;
	struct berval *raw_req = NULL;
	struct berval *raw_res = NULL;
	char *response_oid = NULL;

	/* Variables used as input */
	int version = 1;
	char *exit_data = "";	/* Ignored */
	int rule_array_count;

	/* Variables used as output */
	int return_code = 0;
	int reason_code = 0;
	ber_tag_t tag = 0;
	int out_list_len = 0;

	/* Check sizes */
	if (handle_len != ICSF_HANDLE_LEN) {
		if (handle_len) {
			OCK_LOG_DEBUG("Invalid handle length: %lu\n",
				      handle_len);
		} else {
			OCK_LOG_DEBUG("Invalid handle length: (null)\n");
		}
		OCK_LOG_ERR(ERR_ARGUMENTS_BAD);
		return -1;
	}

	if ((rule_array_len % ICSF_RULE_ITEM_LEN)) {
		OCK_LOG_DEBUG("Invalid rule array length: %lu\n",
			      rule_array_len);
		OCK_LOG_ERR(ERR_ARGUMENTS_BAD);
		return -1;
	}
	rule_array_count = rule_array_len / ICSF_RULE_ITEM_LEN;

	/* Allocate ber_req to encode message. */
	ber_req = ber_alloc_t(LBER_USE_DER);
	if (ber_req == NULL) {
		OCK_LOG_ERR(ERR_HOST_MEMORY);
		goto cleanup;
	}

	/* Encode message:
	 *
	 * TRLInput ::= SEQUENCE {
	 * 	inListLen		INTEGER (0 .. MaxCSFPInteger),
	 * 	maxHandleCount		INTEGER (0 .. MaxCSFPInteger),
	 * 	searchTemplate	[0]	Attributes OPTIONAL
	 * }
	 *
	 */
	rc = ber_printf(ber_req, "{iso{io}t{ii}}", version, exit_data,
			handle, handle_len,
			rule_array_count, rule_array, rule_array_len,
			ICSF_TAG_CSFPTRL | LBER_CONSTRUCTED |
			LBER_CLASS_CONTEXT, *list_len, list_count);
	if (rc < 0) {
		OCK_LOG_DEBUG("Failed to encode message.\n");
		goto cleanup;
	}

	rc = ber_flatten(ber_req, &raw_req);
	if (rc) {
		OCK_LOG_DEBUG("Failed to flat BER data.\n");
		goto cleanup;
	}

	/* Call ICSF service */
	rc = ldap_extended_operation_s(ld, ICSF_REQ_OID, raw_req, NULL, NULL,
				       &response_oid, &raw_res);
	if (rc != LDAP_SUCCESS) {
		OCK_LOG_DEBUG("ICSF call failed: %s (%d)\n",
			      ldap_err2string(rc), rc);
		goto cleanup;
	}

	/* Decode result */
	ber_res = ber_init(raw_res);
	if (ber_res == NULL) {
		OCK_LOG_DEBUG("Failed to create a response buffer\n");
		goto cleanup;
	}

	/*
	 * TRLOutput ::= SEQUENCE {
	 * 	outList		CHOICE {
	 * 		tokenList	[0] OCTET STRING,
	 * 		handleList	[1] OCTET STRING
	 * 	},
	 * 	outListLen	INTEGER (0 .. MaxCSFPInteger)
	 * }
	 */
	rc = ber_scanf(ber_res, "{iiixxt{Oi}}", &version, &return_code,
		       &reason_code, &tag, bv_list, &out_list_len);
	if (rc < 0) {
		OCK_LOG_DEBUG("Failed to decode message.\n");
		goto cleanup;
	}

	OCK_LOG_DEBUG("ICSF call result: %d (%d)\n", return_code, reason_code);

	if (ICSF_RC_IS_ERROR(return_code))
		goto cleanup;

	rc = 0;
	*list_len = out_list_len;

cleanup:
	if (ber_req)
		ber_free(ber_req, 1);
	if (ber_res)
		ber_free(ber_res, 1);
	if (raw_req)
		ber_bvfree(raw_req);
	if (raw_res)
		ber_bvfree(raw_res);
	if (response_oid)
		ldap_memfree(response_oid);

	return rc;
}

/*
 * List tokens on the server.
 *
 * `previous` must point to the last token returned by a previous call of
 * `icsf_list_tokens` or should be NULL for the first call.
 *
 * `records` must point to a buffer of token records with `records_len`
 * elements. `records_len` is updated with the number of tokens returned
 * and it's zero when there's no more records left.
 */
int
icsf_list_tokens(LDAP *ld, struct icsf_token_record *previous,
		 struct icsf_token_record *records, size_t *records_len)
{
	int rc = -1;
	char handle[44];
	char rule_array[ICSF_RULE_ITEM_LEN];
	struct berval *bv_list = NULL;
	size_t list_len;
	size_t i;

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL(records);
	CHECK_ARG_NON_NULL(records_len);

	/* The first record that must be returned in `records` is the next one
	 * after `previous`, and for that the `previous` handle must be
	 * provided. When `previous` is null a blank handle should be used
	 * instead.
	 */
	if (previous) {
		/* The first 32 bytes of `handle` contains the token's name,
		 * the remaining bytes should be blank.
		 */
		strpad(handle, previous->name, ICSF_TOKEN_NAME_LEN, ' ');
		memset(handle + ICSF_TOKEN_NAME_LEN, ' ',
		       sizeof(handle) - ICSF_TOKEN_NAME_LEN);
	} else {
		memset(handle, ' ', sizeof(handle));
	}

	/* Should be 8 bytes padded. */
	strpad(rule_array, "TOKEN", ICSF_RULE_ITEM_LEN, ' ');

	list_len = ICSF_TOKEN_RECORD_LEN * *records_len;
	rc = icsf_list(ld, handle, sizeof(handle), rule_array,
		       sizeof(rule_array), &bv_list, &list_len, *records_len);
	if (rc)
		goto cleanup;

	/* Parse result */
	*records_len = list_len / ICSF_TOKEN_RECORD_LEN;
	for (i = 0; i < *records_len; i++) {
		size_t offset = i * ICSF_TOKEN_RECORD_LEN;
		parse_token_record(&records[i], bv_list->bv_val + offset);
	}

	rc = 0;

cleanup:
	if (bv_list)
		ber_bvfree(bv_list);

	return rc;
}

/*
 * This function indicates if an attribute should be BER encoded as a number or
 * not, based on its type.
 */
static int is_numeric_attr(CK_ULONG type)
{
	switch (type) {
	case CKA_KEY_TYPE:
	case CKA_CERTIFICATE_TYPE:
	case CKA_CLASS:
		return 1;
	}
	return 0;
}

/*
 * This helper functions receives a list of attributes containing type, length
 * and value and encode it in BER encoding. Numeric and non numeric attributes
 * are encoded using different rules. `bv_attrs` is returned with the BER
 * encoded data and should be freed by caller.
 *
 * The attributes are encoded following rules (as described for CSFPTRC in
 * `icsf_create` function):
 *
 * Attributes ::= SEQUENCE OF SEQUENCE {
 *    attrName          INTEGER,
 *    attrValue         AttributeValue
 * }
 *
 * AttributeValue ::= CHOICE {
 *    charValue         [0] OCTET STRING,
 *    intValue          [1] INTEGER
 * }
 *
 */
static int
icsf_attribute_list_flatten(CK_ATTRIBUTE * attrs, CK_ULONG attrs_len,
			    struct berval **bv_attrs)
{
	size_t i;
	BerElement *ber;

	ber = ber_alloc_t(LBER_USE_DER);
	if (ber == NULL) {
		OCK_LOG_ERR(ERR_HOST_MEMORY);
		goto error;
	}

	for (i = 0; i < attrs_len; i++) {
		if (!is_numeric_attr(attrs[i].type)) {
			/* Non numeric attributes are encode as octet strings */
			if (ber_printf(ber, "{ito}", attrs[i].type,
				       0 | LBER_CLASS_CONTEXT, attrs[i].pValue,
				       attrs[i].ulValueLen) < 0) {
				goto encode_error;
			}
		} else {
			long value;
			unsigned long mask;

			/* `long` is used here to support any size of integer,
			 * however if the value is shorter than a `long` then
			 * just the significant bits should be used.
			 */
			if (attrs[i].ulValueLen > sizeof(long)) {
				OCK_LOG_DEBUG
				    ("Integer value too long for attribute\n");
				goto encode_error;
			}

			/* Calculate a mask to get just the bits in the range of
			 * the given length.
			 */
			mask = (1UL << (8 * attrs[i].ulValueLen)) - 1;
			if (mask == 0)
				mask = (unsigned long) -1;

			value = *((unsigned long *) attrs[i].pValue) & mask;

			/* Encode integer attribute. */
			if (ber_printf(ber, "{iti}", attrs[i].type,
				       1 | LBER_CLASS_CONTEXT, value) < 0) {
				goto encode_error;
			}
		}
	}

	if (ber_flatten(ber, bv_attrs)) {
		OCK_LOG_DEBUG("Failed to flat BER data.\n");
		goto error;
	}

	ber_free(ber, 1);

	return 0;

encode_error:
	OCK_LOG_DEBUG("Failed to encode message.\n");

error:
	if (ber)
		ber_free(ber, 1);
	return -1;
}

/*
 * Parse a raw object handle into token name, sequence and object type.
 */
void
handle_to_object_record(struct icsf_object_record *record, const char *data)
{
	size_t offset = 0;
	char hex_seq[ICSF_SEQUENCE_LEN + 1];

	strunpad(record->token_name, data + offset, ICSF_TOKEN_NAME_LEN + 1,
		 ' ');
	offset += ICSF_TOKEN_NAME_LEN;

	memcpy(hex_seq, data + offset, ICSF_SEQUENCE_LEN);
	hex_seq[ICSF_SEQUENCE_LEN] = '\0';
	sscanf(hex_seq, "%lx", &record->sequence);
	offset += ICSF_SEQUENCE_LEN;

	record->id = data[offset];
}

/*
 * Parse a structure object record to a handle.
 *
 * `data` must be at least ICSF_HANDLE_LEN long.
 */
void
object_record_to_handle(char *data, const struct icsf_object_record *record)
{
	size_t offset = 0;
	char hex_seq[ICSF_SEQUENCE_LEN + 1];

	strpad(data + offset, record->token_name, ICSF_TOKEN_NAME_LEN, ' ');
	offset += ICSF_TOKEN_NAME_LEN;

	snprintf(hex_seq, sizeof(hex_seq), "%0*lX", ICSF_SEQUENCE_LEN,
		 record->sequence);
	memcpy(data + offset, hex_seq, ICSF_SEQUENCE_LEN);
	offset += ICSF_SEQUENCE_LEN;

	memset(data + offset, ' ', ICSF_HANDLE_LEN - offset);
	data[offset] = record->id;
}

/*
 * Create an object in the token defined by the given `token_name`.
 *
 * `attrs` is a list of attributes each one consisting in a type, a length and a
 * value (a sequence of bytes). `attrs_len` indicates how many attributes the
 * input list has.
 *
 * `obj_handle` is the buffer that will receive the handler for the new object.
 * And it should be at least 44 bytes long (indicated by `obj_handle_len`).
 */
int
icsf_create_object(LDAP *ld, const char *token_name,
		   CK_ATTRIBUTE *attrs, CK_ULONG attrs_len,
		   struct icsf_object_record *object)
{
	int rc = -1;
	char handle[ICSF_HANDLE_LEN];
	size_t handle_len = sizeof(handle);
	char rule_array[ICSF_RULE_ITEM_LEN];
	struct berval *bv_attrs = NULL;

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL_AND_MAX_LEN(token_name, ICSF_TOKEN_NAME_LEN);
	CHECK_ARG_NON_NULL(attrs);

	/* The first 32 bytes of `handle` specifies the token's name, the
	 * remaining bytes should be blank.
	 */
	strpad(handle, token_name, ICSF_TOKEN_NAME_LEN, ' ');
	memset(handle + ICSF_TOKEN_NAME_LEN, ' ',
	       sizeof(handle) - ICSF_TOKEN_NAME_LEN);

	/* Should be 8 bytes padded. */
	strpad(rule_array, "OBJECT", sizeof(rule_array), ' ');

	if (icsf_attribute_list_flatten(attrs, attrs_len, &bv_attrs)) {
		OCK_LOG_DEBUG("Failed to flat attribute list\n");
		OCK_LOG_ERR(ERR_FUNCTION_FAILED);
		return -1;
	}

	rc = icsf_create(ld, handle, &handle_len,
			 rule_array, sizeof(rule_array),
			 1 | LBER_CLASS_CONTEXT | LBER_CONSTRUCTED,
			 bv_attrs->bv_val, bv_attrs->bv_len);

	if (!rc && object)
		handle_to_object_record(object, handle);

	if (bv_attrs)
		ber_bvfree(bv_attrs);

	return rc;
}

/*
 * List objects for a token indicated by `token_name`.
 *
 * `previous` must point to the last object returned by a previous call of
 * `icsf_list_objects` or should be NULL for the first call.
 *
 * `records` must point to a buffer of object records with `records_len`
 * elements. `records_len` is updated with the number of objects returned
 * and it's zero when there's no more records left.
 */
int
icsf_list_objects(LDAP *ld, const char *token_name,
		  struct icsf_object_record *previous,
		  struct icsf_object_record *records, size_t *records_len,
		  int all)
{
	int rc = -1;
	char handle[ICSF_HANDLE_LEN];
	char rule_array[2 * ICSF_RULE_ITEM_LEN];
	size_t rule_array_count = 1;
	struct berval *bv_list = NULL;
	size_t list_len;
	size_t offset = 0;
	size_t i;

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL_AND_MAX_LEN(token_name, ICSF_TOKEN_NAME_LEN);
	CHECK_ARG_NON_NULL(records);
	CHECK_ARG_NON_NULL(records_len);

	/* The first record that must be returned in `records` is the next one
	 * after `previous`, and for that the `previous` handle must be
	 * provided. When `previous` is null a blank handle should be used
	 * instead.
	 */
	if (previous) {
		/*
		 * Object handle is composed by token name, sequence number
		 * converted to hexadecimal and ID padded with blanks.
		 */
		char hex_seq[ICSF_SEQUENCE_LEN + 1];

		strpad(handle, previous->token_name, ICSF_TOKEN_NAME_LEN, ' ');
		offset += ICSF_TOKEN_NAME_LEN;

		snprintf(hex_seq, sizeof(hex_seq), "%0*lX", ICSF_SEQUENCE_LEN,
			 previous->sequence);
		memcpy(handle + offset, hex_seq, ICSF_SEQUENCE_LEN);
		offset += ICSF_SEQUENCE_LEN;

		memset(handle + offset, ' ', sizeof(handle) - offset);
		handle[offset] = previous->id;

	} else {
		strpad(handle, token_name, ICSF_TOKEN_NAME_LEN, ' ');
		memset(handle + ICSF_TOKEN_NAME_LEN, ' ',
		       sizeof(handle) - ICSF_TOKEN_NAME_LEN);
	}

	/* Should be 8 bytes padded. */
	strpad(rule_array, "OBJECT", ICSF_RULE_ITEM_LEN, ' ');
	if (all) {
		strpad(rule_array + ICSF_RULE_ITEM_LEN, "ALL",
		       ICSF_RULE_ITEM_LEN, ' ');
		rule_array_count += 1;
	}

	list_len = ICSF_HANDLE_LEN * *records_len;
	rc = icsf_list(ld, handle, sizeof(handle), rule_array,
		       rule_array_count * ICSF_RULE_ITEM_LEN,
		       &bv_list, &list_len, *records_len);
	if (rc)
		goto cleanup;

	/* Parse result */
	*records_len = list_len / ICSF_HANDLE_LEN;
	for (i = 0; i < *records_len; i++) {
		size_t offset = i * ICSF_HANDLE_LEN;
		handle_to_object_record(&records[i], bv_list->bv_val + offset);
	}

	rc = 0;

cleanup:
	if (bv_list)
		ber_bvfree(bv_list);

	return rc;
}

/*
 * Destroy an object.
 */
int
icsf_destroy_object(LDAP *ld, struct icsf_object_record *obj)
{
	/* Variables used as input */
	char handle[ICSF_HANDLE_LEN];
	char rule_array[1 * ICSF_RULE_ITEM_LEN];

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL(obj);

	object_record_to_handle(handle, obj);

	/* Should be 8 bytes padded. */
	strpad(rule_array, "OBJECT", ICSF_RULE_ITEM_LEN, ' ');

	return icsf_destroy(ld, handle, sizeof(handle), rule_array,
			    sizeof(rule_array));
}

