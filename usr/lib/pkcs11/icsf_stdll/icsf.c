/*
 * Licensed materials, Property of IBM Corp.
 *
 * OpenCryptoki ICSF token - LDAP functions
 *
 * (C) COPYRIGHT International Business Machines Corp. 2012
 *
 * Author: Marcelo Cerri (mhcerri@br.ibm.com)
 *         Eduardo Otubo (eotubo@br.ibm.com)
 *
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <lber.h>
#include "icsf.h"

/* For logging functions: */
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "trace.h"

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
		TRACE_ERROR("Null argument \"%s\".\n", #_arg);		\
		return -1; 						\
	}

#define CHECK_ARG_MAX_LEN(_arg, _length) 				\
	if (_arg && (strlen(_arg) > _length)) {				\
		TRACE_ERROR("String too long %s=\"%s\"\n",		\
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
 * Build a token handle based on token name.
 *
 * `handle` must be at least ICSF_HANDLE_LEN long.
 */
static void
token_name_to_handle(char *handle, const char *token_name)
{
	/* The first 32 bytes of `handle` specifies the token's name, the
	 * remaining bytes should be blank.
	 */
	strpad(handle, token_name, ICSF_TOKEN_NAME_LEN, ' ');
	memset(handle + ICSF_TOKEN_NAME_LEN, ' ',
	       ICSF_HANDLE_LEN - ICSF_TOKEN_NAME_LEN);
}

/*
 * Parse a structure object record to a handle.
 *
 * `data` must be at least ICSF_HANDLE_LEN long.
 */
void
object_record_to_handle(char *data, const struct icsf_object_record *record)
{
	/*
	 * Object handle is composed by token name, sequence number
	 * converted to hexadecimal and ID padded with blanks.
	 */
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
		TRACE_ERROR("Failed to get LDAP version: %s (%d)\n",
			    ldap_err2string(rc), rc);
		return -1;
	}
	if (version < LDAP_VERSION3) {
		TRACE_INFO("Changing version from %d to %d.\n",
			   version, LDAP_VERSION3);
		version = LDAP_VERSION3;
		rc = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
		if (rc != LDAP_OPT_SUCCESS) {
			TRACE_ERROR("Failed to set LDAP version: %s (%d)\n",
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
	CHECK_ARG_NON_NULL(password);

	/* Handle empty and null string in the same way */
	uri = (uri && uri[0]) ? uri : NULL;
	dn = (dn && dn[0]) ? dn : NULL;

	/* Connect to LDAP server */
	TRACE_DEVEL("Connecting to: %s\n", uri ? uri : "(null)");
	rc = ldap_initialize(ld, uri);
	if (rc != LDAP_SUCCESS) {
		TRACE_ERROR("Failed to connect to \"%s\": %s (%d)\n",
			      uri ? uri : "(null)", ldap_err2string(rc), rc);
		return -1;
	}

	if (icsf_force_ldap_v3(*ld))
		return -1;

	TRACE_DEVEL("Binding with DN: %s\n", dn ? dn : "(null)");
	cred.bv_len = strlen(password);
	cred.bv_val = (char *) password;
	rc = ldap_sasl_bind_s(*ld, dn, LDAP_SASL_SIMPLE, &cred, NULL, NULL,
			      NULL);
	if (rc != LDAP_SUCCESS) {
		TRACE_ERROR("LDAP bind failed: %s (%d)\n",
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

	TRACE_DEVEL("Preparing environment for TLS\n");
	if (cert && *cert) {
		TRACE_DEVEL("Using certificate: %s\n", cert);
		rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_CERTFILE, cert);
		if (rc != LDAP_SUCCESS) {
			TRACE_ERROR("Failed to set certificate file for TLS: "
				      "%s (%d)\n", ldap_err2string(rc), rc);
			return -1;
		}
	}

	if (key && *key) {
		TRACE_DEVEL("Using private key: %s\n", key);
		rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_KEYFILE, key);
		if (rc != LDAP_SUCCESS) {
			TRACE_ERROR("Failed to set key file for TLS: "
				    "%s (%d)\n", ldap_err2string(rc), rc);
			return -1;
		}
	}

	if (ca && *ca) {
		TRACE_DEVEL("Using CA certificate file: %s\n", ca);
		rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE, ca);
		if (rc != LDAP_SUCCESS) {
			TRACE_ERROR("Failed to set CA certificate file for TLS:"
				    " %s (%d)\n", ldap_err2string(rc), rc);
			return -1;
		}
	}

	if (ca_dir && *ca_dir) {
		TRACE_DEVEL("Using CA certificate dir: %s\n", ca_dir);
		rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTDIR, ca_dir);
		if (rc != LDAP_SUCCESS) {
			TRACE_ERROR("Failed to set CA certificate dir for TLS: "
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

	/* Handle empty and null string in the same way */
	uri = (uri && uri[0]) ? uri : NULL;

	/* Connect to LDAP server */
	TRACE_DEVEL("Connecting to: %s\n", uri ? uri : "(null)");
	rc = ldap_initialize(ld, uri);
	if (rc != LDAP_SUCCESS) {
		TRACE_ERROR("Failed to connect to \"%s\": %s (%d)\n",
			      uri ? uri : "(null)", ldap_err2string(rc), rc);
		return -1;
	}

	if (icsf_force_ldap_v3(*ld))
		return -1;

	/* Initialize TLS */
	if (icsf_set_sasl_params(*ld, cert, key, ca, ca_dir))
		return -1;

	TRACE_DEVEL("Binding\n");
	rc = ldap_sasl_bind_s(*ld, NULL, "EXTERNAL", NULL, NULL, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		char *ext_msg = NULL;
		ldap_get_option(*ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, &ext_msg);
		TRACE_ERROR("LDAP bind failed: %s (%d)%s%s\n",
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
		TRACE_ERROR("Failed to unbind: %s (%d)\n",
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
					     strlen(expected_oid))) {
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
 * `icsf_call` is a generic helper function for ICSF services.
 *
 * Every request message to an ICSF service has some common fields and a
 * specific field that depends on the service that is called. The structure of
 * this field differs for each service and it's also marked with a specific tag
 * that identifies the service.
 *
 * `handle` identifies a token or object. It should be always 44 bytes long.
 *
 * `reason` returns the ICSF reason code. It's ignored when NULL.
 *
 * `rule_array` should be a sequence of 8 bytes strings padded with blanks. Each
 * 8 bytes is an item and can change the behaviour of a call.
 *
 * `tag` identifies the ICSF service.
 *
 * `specific` is the service-specific field of the request message. A NULL value
 * indicates an empty field.
 *
 * `result` points to the service-specific part of the response message. If a
 * non-NULL value is given, the caller must free it.
 */
static int
icsf_call(LDAP *ld, int *reason, char *handle, size_t handle_len,
	  const char *rule_array, size_t rule_array_len,
	  ber_tag_t tag, BerElement *specific, BerElement **result)
{
	int rc;
	BerElement *ber_req = NULL;
	BerElement *ber_res = NULL;
	struct berval *raw_req = NULL;
	struct berval *raw_res = NULL;
	struct berval *raw_specific = NULL;
	char *response_oid = NULL;

	/* Variables used as input */
	int version = 1;
	char *exit_data = "";	/* Ignored */
	int rule_array_count;

	/* Variables used as output */
	int return_code = 0;
	int reason_code = 0;
	struct berval *out_handle = NULL;

	/* Check sizes */
	if (handle_len != ICSF_HANDLE_LEN) {
		TRACE_ERROR("Invalid handle length: %lu\n", handle_len);
		return -1;
	}

	if ((rule_array_len % ICSF_RULE_ITEM_LEN)) {
		TRACE_ERROR("Invalid rule array length: %lu\n",
			      rule_array_len);
		return -1;
	}
	rule_array_count = rule_array_len / ICSF_RULE_ITEM_LEN;

	/* Allocate ber_req to encode message. */
	ber_req = ber_alloc_t(LBER_USE_DER);
	if (ber_req == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		rc = -1;
		goto cleanup;
	}

	if (specific) {
		rc = ber_flatten(specific, &raw_specific);
		if (rc) {
			TRACE_ERROR("Failed to flatten specific data.\n");
			rc = -1;
			goto cleanup;
		}
	}

	/* Encode message:
	 *
	 * requestValue ::= SEQUENCE {
	 * 	version		INTEGER,
	 * 	exitData	OCTET STRING,
	 * 	handle_len	OCTET STRING,
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
	 */
	tag |= LBER_CLASS_CONTEXT | LBER_CONSTRUCTED;
	rc = ber_printf(ber_req, "{iso{io}to}", version, exit_data, handle,
			handle_len, rule_array_count, rule_array,
			rule_array_len,tag,
			(raw_specific) ? raw_specific->bv_val : "",
			(raw_specific) ? raw_specific->bv_len : 0);
	if (rc < 0) {
		TRACE_ERROR("Failed to encode message.\n");
		rc = -1;
		goto cleanup;
	}

	rc = ber_flatten(ber_req, &raw_req);
	if (rc) {
		TRACE_ERROR("Failed to flatten BER data.\n");
		rc = -1;
		goto cleanup;
	}

	/* Call ICSF service */
	rc = ldap_extended_operation_s(ld, ICSF_REQ_OID, raw_req, NULL, NULL,
				       &response_oid, &raw_res);
	if (rc != LDAP_SUCCESS) {
		char *ext_msg = NULL;
		ldap_get_option(ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, &ext_msg);
		TRACE_ERROR("ICSF call failed: %s (%d)%s%s\n",
			      ldap_err2string(rc), rc,
			      ext_msg ? "\nDetailed message: " : "",
			      ext_msg ? ext_msg : "");
		if (ext_msg)
			ldap_memfree(ext_msg);
		rc = -1;
		goto cleanup;
	}

	/* Decode result */
	ber_res = ber_init(raw_res);
	if (ber_res == NULL) {
		TRACE_ERROR("Failed to create a response buffer\n");
		rc = -1;
		goto cleanup;
	}

	/* Decode common response fields: */
	rc = ber_scanf(ber_res, "{iiixO", &version, &return_code,
		       &reason_code, &out_handle);
	if (rc < 0) {
		TRACE_ERROR("Failed to decode message.\n");
		rc = -1;
		goto cleanup;
	}

	/* Copy handle */
	if (out_handle == NULL) {
		memset(handle, 0, handle_len);
	} else {
		size_t len = (handle_len < out_handle->bv_len)
			? handle_len : out_handle->bv_len;
		memcpy(handle, out_handle->bv_val, len);
		memset(handle + len, 0, handle_len - len);
	}

	TRACE_DEVEL("ICSF call result: %d (%d)\n", return_code, reason_code);

	if (ICSF_RC_IS_ERROR(return_code)) {
		TRACE_ERROR("ICSF call failed: %d (%d)\n", return_code,
			      reason_code);
	}

	rc = return_code;

cleanup:
	if (reason)
		*reason = reason_code;
	if (result)
		*result = ber_res;
	else if (ber_res)
		ber_free(ber_res, 1);
	if (ber_req)
		ber_free(ber_req, 1);
	if (raw_req)
		ber_bvfree(raw_req);
	if (raw_res)
		ber_bvfree(raw_res);
	if (response_oid)
		ldap_memfree(response_oid);
	if (out_handle)
		ber_bvfree(out_handle);
	if (raw_specific)
		ber_bvfree(raw_specific);

	return rc;
}

/*
 * Create a new token. All parameters must be null terminated strings.
 */
int
icsf_create_token(LDAP *ld, int *reason, const char *token_name,
		  const char *manufacturer, const char *model,
		  const char *serial)
{
	int rc = -1;
	char handle[ICSF_HANDLE_LEN];
	char rule_array[2 * ICSF_RULE_ITEM_LEN];
	char attribute_list[68] = { 0, };
	BerElement *msg= NULL;

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL_AND_MAX_LEN(token_name, ICSF_TOKEN_NAME_LEN);
	CHECK_ARG_NON_NULL_AND_MAX_LEN(manufacturer, ICSF_MANUFACTURER_LEN);
	CHECK_ARG_NON_NULL_AND_MAX_LEN(model, ICSF_MODEL_LEN);
	CHECK_ARG_NON_NULL_AND_MAX_LEN(serial, ICSF_SERIAL_LEN);

	token_name_to_handle(handle, token_name);

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

	/* Allocate ber_req to encode message. */
	msg = ber_alloc_t(LBER_USE_DER);
	if (msg == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		goto cleanup;
	}

	/* Encode message:
	 *
	 * TRCInput ::= SEQUENCE {
	 *     trcAttrs ::= CHOICE {
	 *         tokenAttrString   [0] OCTET STRING,
	 *     }
	 * }
	 */
	rc = ber_printf(msg, "to", 0 | LBER_CLASS_CONTEXT, attribute_list,
			sizeof(attribute_list));
	if (rc < 0) {
		TRACE_ERROR("Failed to encode message.\n");
		goto cleanup;
	}

	rc = icsf_call(ld, reason, handle, sizeof(handle),
			rule_array, sizeof(rule_array),
			ICSF_TAG_CSFPTRC, msg, NULL);

cleanup:
	if (msg)
		ber_free(msg, 1);

	return rc;
}

/*
 * Destroy a token.
 */
int icsf_destroy_token(LDAP *ld, int *reason, char *token_name)
{
	/* Variables used as input */
	char handle[ICSF_HANDLE_LEN];
	char rule_array[1 * ICSF_RULE_ITEM_LEN];

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL_AND_MAX_LEN(token_name, ICSF_TOKEN_NAME_LEN);

	token_name_to_handle(handle, token_name);

	/* Should be 8 bytes padded. */
	strpad(rule_array, "TOKEN", ICSF_RULE_ITEM_LEN, ' ');

	/*
	 * CSFPTRD service is used to destroy a token or an object. Handle
	 * indicates the token or object that must be destroyed and no
	 * additional data is needed.
	 */
	return icsf_call(ld, reason, handle, sizeof(handle), rule_array,
			    sizeof(rule_array), ICSF_TAG_CSFPTRD, NULL, NULL);
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

/* helper function to determine if a specific keyword is in the rule array */
int
in_rulearray(const char *keyword, const char *rulearray, int count)
{
	int i = 0;

	while(count) {
		if (memcmp(keyword, rulearray + i, 8) == 0)
			return 1;
		i += 8;
		count--;
	}
	return 0;
}

/*
 * This function indicates if an attribute should be BER encoded as a number or
 * not, based on its type.
 */
static int is_numeric_attr(CK_ULONG type)
{
	switch (type) {
	case CKA_CLASS:
	case CKA_KEY_TYPE:
	case CKA_CERTIFICATE_TYPE:
	case CKA_KEY_GEN_MECHANISM:
	case CKA_VALUE_LEN:
	case CKA_MODULUS_BITS:
		return 1;
	}
	return 0;
}

/*
 * This helper functions receives a list of attributes containing type, length
 * and value and encode it in BER encoding. Numeric and non numeric attributes
 * are encoded using different rules.
 *
 * The attributes are encoded following rules:
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
icsf_ber_put_attribute_list(BerElement *ber, CK_ATTRIBUTE * attrs,
			    CK_ULONG attrs_len)
{
	size_t i;

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
				TRACE_ERROR
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

	return 0;

encode_error:
	TRACE_ERROR("Failed to encode message.\n");

	return -1;
}

/*
 *
 * `icsf_list` is a helper function for CSFPTRL service,
 *  which is used for token and object listing.
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
icsf_list(LDAP *ld, int *reason, char *handle, size_t handle_len,
	  CK_ULONG attrs_len, CK_ATTRIBUTE *attrs,
	  const char *rule_array, size_t rule_array_len,
	  struct berval **bv_list, size_t *list_len, size_t list_count)
{
	int rc = -1;
	BerElement *msg = NULL;
	BerElement *result = NULL;
	int out_list_len = 0;
	int objectInRuleArray = 0;

	/* Allocate request message. */
	msg = ber_alloc_t(LBER_USE_DER);
	if (msg == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
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
	if (ber_printf(msg, "ii", *list_len, list_count) < 0) {
		TRACE_ERROR("Failed to encode message.\n");
		goto cleanup;
	}

	objectInRuleArray = in_rulearray("OBJECT  ", rule_array,
					 rule_array_len / ICSF_RULE_ITEM_LEN);

	if ((objectInRuleArray) && (attrs != NULL)) {
		if (ber_printf(msg, "t{", 0|LBER_CLASS_CONTEXT|LBER_CONSTRUCTED) < 0) {
			TRACE_ERROR("Failed to flatten attribute list\n");
			goto cleanup;
		}

		if (icsf_ber_put_attribute_list(msg, attrs, attrs_len) < 0) {
			TRACE_ERROR("Failed to flatten attribute list\n");
			goto cleanup;
		}

		if (ber_printf(msg, "}") < 0) {
			TRACE_ERROR("Failed to encode message.\n");
			goto cleanup;
		}
	}

	rc = icsf_call(ld, reason, handle, handle_len, rule_array,
		       rule_array_len, ICSF_TAG_CSFPTRL, msg, &result);
	if (ICSF_RC_IS_ERROR(rc))
		goto cleanup;

	/* Decode result:
	 *
	 * TRLOutput ::= SEQUENCE {
	 * 	outList		CHOICE {
	 * 		tokenList	[0] OCTET STRING,
	 * 		handleList	[1] OCTET STRING
	 * 	},
	 * 	outListLen	INTEGER (0 .. MaxCSFPInteger)
	 * }
	 */
	if (ber_scanf(result, "{Oi}", bv_list, &out_list_len) < 0) {
		TRACE_ERROR("Failed to decode message.\n");
		rc = -1;
		goto cleanup;
	}

	*list_len = out_list_len;

cleanup:
	if (msg)
		ber_free(msg, 1);
	if (result)
		ber_free(result, 1);

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
icsf_list_tokens(LDAP *ld, int *reason, struct icsf_token_record *previous,
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
	if (previous)
		token_name_to_handle(handle, previous->name);
	else
		memset(handle, ' ', sizeof(handle));

	/* Should be 8 bytes padded. */
	strpad(rule_array, "TOKEN", ICSF_RULE_ITEM_LEN, ' ');

	list_len = ICSF_TOKEN_RECORD_LEN * *records_len;
	rc = icsf_list(ld, reason, handle, sizeof(handle), 0, NULL, rule_array,
		       sizeof(rule_array), &bv_list, &list_len, *records_len);
	if (ICSF_RC_IS_ERROR(rc))
		goto cleanup;

	/* Parse result */
	*records_len = list_len / ICSF_TOKEN_RECORD_LEN;
	for (i = 0; i < *records_len; i++) {
		size_t offset = i * ICSF_TOKEN_RECORD_LEN;
		parse_token_record(&records[i], bv_list->bv_val + offset);
	}

cleanup:
	if (bv_list)
		ber_bvfree(bv_list);

	return rc;
}

int
icsf_copy_object(LDAP * ld, int *reason,
		 CK_ATTRIBUTE * attrs, CK_ULONG attrs_len,
		 struct icsf_object_record *src, struct icsf_object_record *dst)
{
	int rc = -1;
	char handle[ICSF_HANDLE_LEN];
	char rule_array[2 * ICSF_RULE_ITEM_LEN];
	BerElement *msg = NULL;

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL(src);
	CHECK_ARG_NON_NULL(attrs);

	object_record_to_handle(handle, src);

	/* Allocate ber_req to encode message. */
	msg = ber_alloc_t(LBER_USE_DER);
	if (msg == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		goto cleanup;
	}

	if (attrs_len != 0) {
		rc = ber_printf(msg, "t{", 1 | LBER_CLASS_CONTEXT | LBER_CONSTRUCTED);
		if (rc < 0) {
			TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
			goto cleanup;
		}

		if (icsf_ber_put_attribute_list(msg, attrs, attrs_len) < 0) {
			TRACE_DEVEL("icsf_ber_put_attribute_list failed\n");
			goto cleanup;
		}

		if (ber_printf(msg, "}") < 0) {
			TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
			goto cleanup;
		}
	} else {
		rc = ber_printf(msg, "tn", 1 | LBER_CLASS_CONTEXT | LBER_CONSTRUCTED);
		if (rc < 0) {
			TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
			goto cleanup;
		}
	}

	/* Should be 8 bytes padded. */
	strpad(rule_array, "OBJECT", ICSF_RULE_ITEM_LEN, ' ');
	strpad(rule_array + ICSF_RULE_ITEM_LEN, "COPY", ICSF_RULE_ITEM_LEN,
			' ');

	rc = icsf_call(ld, reason, handle, sizeof(handle),
		       rule_array, sizeof(rule_array),
		       ICSF_TAG_CSFPTRC, msg, NULL);

	if (!rc && dst)
		handle_to_object_record(dst, handle);

cleanup:
	if (msg)
		ber_free(msg, 1);

	return rc;
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
icsf_create_object(LDAP *ld, int *reason, const char *token_name,
		   CK_ATTRIBUTE *attrs, CK_ULONG attrs_len,
		   struct icsf_object_record *object)
{
	int rc = -1;
	char handle[ICSF_HANDLE_LEN];
	char rule_array[ICSF_RULE_ITEM_LEN];
	BerElement *msg = NULL;

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL_AND_MAX_LEN(token_name, ICSF_TOKEN_NAME_LEN);
	CHECK_ARG_NON_NULL(attrs);

	token_name_to_handle(handle, token_name);

	/* Should be 8 bytes padded. */
	strpad(rule_array, "OBJECT", sizeof(rule_array), ' ');

	/* Allocate ber_req to encode message. */
	msg = ber_alloc_t(LBER_USE_DER);
	if (msg == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		goto cleanup;
	}

	/* Encode message:
	 *
	 * TRCInput ::= SEQUENCE {
	 *     trcAttrs ::= CHOICE {
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
	if (ber_printf(msg, "t{", 1 | LBER_CLASS_CONTEXT | LBER_CONSTRUCTED) < 0) {
		TRACE_ERROR("Failed to encode message.\n");
		goto cleanup;
	}

	if (icsf_ber_put_attribute_list(msg, attrs, attrs_len) < 0) {
		TRACE_ERROR("Failed to flatten attribute list\n");
		goto cleanup;
	}

	if (ber_printf(msg, "}") < 0) {
		TRACE_ERROR("Failed to encode message.\n");
		goto cleanup;
	}

	rc = icsf_call(ld, reason, handle, sizeof(handle),
			rule_array, sizeof(rule_array),
			ICSF_TAG_CSFPTRC, msg, NULL);

cleanup:
	if (msg)
		ber_free(msg, 1);

	if (!rc && object)
		handle_to_object_record(object, handle);

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
icsf_list_objects(LDAP *ld, int *reason, const char *token_name,
		  CK_ULONG attrs_len, CK_ATTRIBUTE *attrs,
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
	size_t i;

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL_AND_MAX_LEN(token_name, ICSF_TOKEN_NAME_LEN);
	CHECK_ARG_NON_NULL(records);
	CHECK_ARG_NON_NULL(records_len);

	/* The first record that must be returned in `records` is the next one
	 * after `previous`, and for that the `previous` handle must be
	 * provided. When `previous` is null, the token handle should be used
	 * instead.
	 */
	if (previous)
		object_record_to_handle(handle, previous);
	else
		token_name_to_handle(handle, token_name);

	/* Should be 8 bytes padded. */
	strpad(rule_array, "OBJECT", ICSF_RULE_ITEM_LEN, ' ');
	if (all) {
		strpad(rule_array + ICSF_RULE_ITEM_LEN, "ALL",
		       ICSF_RULE_ITEM_LEN, ' ');
		rule_array_count += 1;
	}

	list_len = ICSF_HANDLE_LEN * *records_len;
	rc = icsf_list(ld, reason, handle, sizeof(handle), attrs_len, attrs,			      rule_array, rule_array_count * ICSF_RULE_ITEM_LEN,
		       &bv_list, &list_len, *records_len);
	if (ICSF_RC_IS_ERROR(rc))
		goto cleanup;

	/* Parse result */
	*records_len = list_len / ICSF_HANDLE_LEN;
	for (i = 0; i < *records_len; i++) {
		size_t offset = i * ICSF_HANDLE_LEN;
		handle_to_object_record(&records[i], bv_list->bv_val + offset);
	}

cleanup:
	if (bv_list)
		ber_bvfree(bv_list);

	return rc;
}

/*
 * Destroy an object.
 */
int
icsf_destroy_object(LDAP *ld, int *reason, struct icsf_object_record *obj)
{
	/* Variables used as input */
	char handle[ICSF_HANDLE_LEN];
	char rule_array[1 * ICSF_RULE_ITEM_LEN];

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL(obj);

	object_record_to_handle(handle, obj);

	/* Should be 8 bytes padded. */
	strpad(rule_array, "OBJECT", ICSF_RULE_ITEM_LEN, ' ');

	/*
	 * CSFPTRD service is used to destroy a token or an object. Handle
	 * indicates the token or object that must be destroyed and no
	 * additional data is needed.
	 */
	return icsf_call(ld, reason, handle, sizeof(handle), rule_array,
			    sizeof(rule_array), ICSF_TAG_CSFPTRD, NULL, NULL);
}

/*
 * Generate an asymmetric key pair.
 */
int
icsf_generate_key_pair(LDAP *ld, int *reason, const char *token_name,
		       CK_ATTRIBUTE *pub_attrs, CK_ULONG pub_attrs_len,
		       CK_ATTRIBUTE *priv_attrs, CK_ULONG priv_attrs_len,
		       struct icsf_object_record *pub_key_object,
		       struct icsf_object_record *priv_key_object)
{
	int rc = -1;
	char handle[ICSF_HANDLE_LEN];
	BerElement *msg = NULL;
	BerElement *result = NULL;
	struct berval bv_priv_handle = { 0, NULL };

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL_AND_MAX_LEN(token_name, ICSF_TOKEN_NAME_LEN);
	CHECK_ARG_NON_NULL(pub_attrs);
	CHECK_ARG_NON_NULL(priv_attrs);
	CHECK_ARG_NON_NULL(pub_key_object);
	CHECK_ARG_NON_NULL(priv_key_object);

	token_name_to_handle(handle, token_name);

	if (!(msg = ber_alloc_t(LBER_USE_DER))) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return rc;
	}

	/* Encode message:
	 *
	 * GKPInput ::= SEQUENCE {
	 *     publicKeyAttrList Attributes,
	 *     privateKeyAttrList Attributes
	 * }
	 *
	 * Attribute lists are built by icsf_ber_put_attribute_list()
	 */
	if (ber_printf(msg, "{") < 0 ||
	    icsf_ber_put_attribute_list(msg, pub_attrs, pub_attrs_len) < 0 ||
	    ber_printf(msg, "}{") < 0 ||
	    icsf_ber_put_attribute_list(msg, priv_attrs, priv_attrs_len) < 0 ||
	    ber_printf(msg, "}") < 0) {
		TRACE_ERROR("Failed to encode message.\n");
		goto cleanup;
	}

	rc = icsf_call(ld, reason, handle, sizeof(handle), "", 0,
			ICSF_TAG_CSFPGKP, msg, &result);
	if (rc)
		goto cleanup;

	/* Get private key handle from GKP response */
	if (ber_scanf(result, "m", &bv_priv_handle) < 0) {
		TRACE_ERROR("Failed to decode the response.\n");
		rc = -1;
		goto cleanup;
	}
	if (bv_priv_handle.bv_len != ICSF_HANDLE_LEN) {
		TRACE_ERROR("Invalid length for handle: %lu\n",
			    (unsigned long) bv_priv_handle.bv_len);
		rc = -1;
		goto cleanup;
	}
	handle_to_object_record(priv_key_object, bv_priv_handle.bv_val);

	/* Get public key handle from common ICSF header */
	handle_to_object_record(pub_key_object, handle);

cleanup:
	if (result)
		ber_free(result, 1);
	if (msg)
		ber_free(msg, 1);

	return rc;
}

/*
 * Generate a symmetric key.
 */
int
icsf_generate_secret_key(LDAP *ld, int *reason, const char *token_name,
			CK_MECHANISM_PTR mech,
			CK_ATTRIBUTE *attrs, CK_ULONG attrs_len,
			struct icsf_object_record *object)
{
	int rc = -1;
	char handle[ICSF_HANDLE_LEN];
	char rule_array[1 * ICSF_RULE_ITEM_LEN];
	char param[2];
	size_t param_len;
	CK_VERSION_PTR version;
	BerElement *msg = NULL;

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL_AND_MAX_LEN(token_name, ICSF_TOKEN_NAME_LEN);
	CHECK_ARG_NON_NULL(mech);
	CHECK_ARG_NON_NULL(attrs);

	token_name_to_handle(handle, token_name);

	/* Map mechanism into the rule array */
	switch (mech->mechanism) {
	case CKM_TLS_PRE_MASTER_KEY_GEN:
		strpad(rule_array, "TLS", sizeof(rule_array), ' ');
		break;
	case CKM_SSL3_PRE_MASTER_KEY_GEN:
		strpad(rule_array, "SSL", sizeof(rule_array), ' ');
		break;
	case CKM_DSA_PARAMETER_GEN:
	case CKM_DH_PKCS_PARAMETER_GEN:
		strpad(rule_array, "PARMS", sizeof(rule_array), ' ');
		break;
	default:
		strpad(rule_array, "KEY", sizeof(rule_array), ' ');
	}

	/* Fill parameters if necessary */
	switch (mech->mechanism) {
	case CKM_TLS_PRE_MASTER_KEY_GEN:
	case CKM_SSL3_PRE_MASTER_KEY_GEN:
		/* Check expected length */
		if (mech->ulParameterLen != sizeof(*version)) {
			TRACE_ERROR("Invalid mechanism parameter length: "
				"%lu\n", (unsigned long) mech->ulParameterLen);
			return -1;
		}

		/* Fill parameter with version numbers */
		version = (CK_VERSION_PTR) mech->pParameter;
		param[0] = version->major;
		param[1] = version->minor;
		param_len = 2;

		break;
	default:
		/* Parameter should be empty */
		param_len = 0;
	}

	if (!(msg = ber_alloc_t(LBER_USE_DER))) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return rc;
	}

	/* Encode message:
	 *
	 * GSKInput ::= SEQUENCE {
	 *     attrList         Attributes,
	 *     parmsList        OCTET STRING
	 * }
	 *
	 * attrList is built by icsf_ber_put_attribute_list()
	 */
	if (ber_printf(msg, "{") < 0) {
		TRACE_ERROR("Failed to encode message.\n");
		goto cleanup;
	}

	if (icsf_ber_put_attribute_list(msg, attrs, attrs_len) < 0 ||
	    ber_printf(msg, "}o", param, param_len) < 0) {
		TRACE_ERROR("Failed to encode message.\n");
		goto cleanup;
	}

	rc = icsf_call(ld, reason, handle, sizeof(handle), rule_array,
			sizeof(rule_array), ICSF_TAG_CSFPGSK, msg, NULL);
	if (!rc)
		handle_to_object_record(object, handle);

cleanup:
	if (msg)
		ber_free(msg, 1);

	return rc;
}

/*
 * Return the rule array element for the given mechanism.
 */
static const char *
get_algorithm_rule(CK_MECHANISM_PTR mech, int arg)
{
	switch (mech->mechanism) {
	case CKM_DES_ECB:
	case CKM_DES_CBC:
	case CKM_DES_CBC_PAD:
		return "DES";
	case CKM_DES3_ECB:
	case CKM_DES3_CBC:
	case CKM_DES3_CBC_PAD:
		return "DES3";
	case CKM_AES_ECB:
	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
	case CKM_AES_CTR:
		return "AES";
	case CKM_DSA:
		return "DSA";
	case CKM_ECDSA:
		return "ECDSA";
	case CKM_RSA_X_509:
		return "RSA-ZERO";
	case CKM_RSA_PKCS:
		return "RSA-PKCS";
	case CKM_SHA_1_HMAC:
		return "SHA-1";
	case CKM_SHA256_HMAC:
		return "SHA-256";
	case CKM_SHA384_HMAC:
		return "SHA-384";
	case CKM_SHA512_HMAC:
		return "SHA-512";
	case CKM_MD5_HMAC:
		return "MD5";
	case CKM_SSL3_MD5_MAC:
		return "SSL3-MD5";
	case CKM_SSL3_SHA1_MAC:
		return "SSL3-SHA";
	case CKM_SHA1_RSA_PKCS:
		if (arg)
			return "SHA-1   VER-RSA";
		else
			return "SHA-1   SIGN-RSA";
	case CKM_SHA256_RSA_PKCS:
		if (arg)
			return "SHA-256 VER-RSA";
		else
			return "SHA-256 SIGN-RSA";
	case CKM_SHA384_RSA_PKCS:
		if (arg)
			return "SHA-384 VER-RSA";
		else
			return "SHA-384 SIGN-RSA";
	case CKM_SHA512_RSA_PKCS:
		if (arg)
			return "SHA-512 VER-RSA";
		else
			return "SHA-512 SIGN-RSA";
	case CKM_MD5_RSA_PKCS:
		if (arg)
			return "MD5     VER-RSA";
		else
			return "MD5     SIGN-RSA";
	case CKM_DSA_SHA1:
		if (arg)
			return "SHA-1   VER-DSA";
		else
			return "SHA-1   SIGN-DSA";
	case CKM_ECDSA_SHA1:
		if (arg)
			return "SHA-1   VER-EC";
		else
			return "SHA-1   SIGN-EC";
	case CKM_SSL3_KEY_AND_MAC_DERIVE:
		return "SSL-KM";
	case CKM_TLS_KEY_AND_MAC_DERIVE:
		return "TLS-KM";
	}

	return NULL;
}

/*
 * Return the rule array element for the cipher mode based on the given
 * mechanism.
 */
static const char *
get_cipher_mode(CK_MECHANISM_PTR mech)
{
	switch (mech->mechanism) {
	case CKM_DES_ECB:
	case CKM_DES3_ECB:
	case CKM_AES_ECB:
		return "ECB";
	case CKM_DES_CBC:
	case CKM_DES3_CBC:
	case CKM_AES_CBC:
		return "CBC";
	case CKM_DES_CBC_PAD:
	case CKM_DES3_CBC_PAD:
	case CKM_AES_CBC_PAD:
		return "CBC-PAD";
	}
	return NULL;
}

/*
 * Get the block size of supported algorithms/mechanism.
 */
CK_RV
icsf_block_size(CK_MECHANISM_TYPE mech_type, CK_ULONG_PTR p_block_size)
{
	CK_ULONG block_size;

	switch (mech_type) {
	case CKM_DES_CBC:
	case CKM_DES_CBC_PAD:
	case CKM_DES3_CBC:
	case CKM_DES3_CBC_PAD:
	case CKM_DES_ECB:
	case CKM_DES3_ECB:
		block_size = DES_BLOCK_SIZE;
		break;

	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
	case CKM_AES_ECB:
		block_size = AES_BLOCK_SIZE;
		break;

	case CKM_MD5_RSA_PKCS:
		block_size = MD5_BLOCK_SIZE;
		break;

	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
		block_size = SHA1_BLOCK_SIZE;
		break;

	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
		block_size = SHA3_BLOCK_SIZE;
		break;

	default:
		return CKR_MECHANISM_INVALID;
	}

	if (p_block_size)
		*p_block_size = block_size;

	return CKR_OK;
}

/*
 * Extract and check the initialization vector contained in the given mechanism.
 */
static CK_RV
icsf_encrypt_initial_vector(CK_MECHANISM_PTR mech, char *iv, size_t *iv_len)
{
	CK_RV rc;
	int use_iv = 0;
	size_t expected_iv_len = 0;

	if ((rc = icsf_block_size(mech->mechanism, &expected_iv_len)))
		return rc;

	switch (mech->mechanism) {
	case CKM_DES_CBC:
	case CKM_DES_CBC_PAD:
	case CKM_DES3_CBC:
	case CKM_DES3_CBC_PAD:
	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
		use_iv = 1;
	}

	if (iv_len && *iv_len < expected_iv_len) {
		TRACE_ERROR("IV too small.\n");
		return CKR_FUNCTION_FAILED;
	}

	/* Set the Initialization vector */
	if (iv)
		memset(iv, 0, expected_iv_len);
	if (use_iv) {
		/*
		 * Otherwise use the mechanism parameter as the IV.
		 */
		if (mech->ulParameterLen != expected_iv_len) {
			TRACE_ERROR("Invalid mechanism parameter length: %lu "
					"(expected %lu)\n",
					(unsigned long) mech->ulParameterLen,
					(unsigned long) expected_iv_len);
			return CKR_MECHANISM_PARAM_INVALID;
		}
		if (iv)
			memcpy(iv, mech->pParameter, expected_iv_len);
	}
	if (iv_len)
		*iv_len = expected_iv_len;

	return 0;
}

/*
 * Symmetric key encrypt.
 */
int
icsf_secret_key_encrypt(LDAP *ld, int *p_reason, struct icsf_object_record *key,
			CK_MECHANISM_PTR mech, int chaining,
			const char *clear_text, size_t clear_text_len,
			char *cipher_text, size_t *p_cipher_text_len,
			char *chaining_data, size_t *p_chaining_data_len)
{
	int rc = 0;
	char handle[ICSF_HANDLE_LEN];
	char rule_array[3 * ICSF_RULE_ITEM_LEN];
	BerElement *msg = NULL;
	BerElement *result = NULL;
	char init_vector[32];
	size_t init_vector_len = sizeof(init_vector);
	struct berval bv_cipher_data = { 0UL, NULL };
	struct berval bv_chaining_data = { 0UL, NULL };
	const char *rule_alg, *rule_cipher;
	int reason = 0, length = 0;

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL(key);
	CHECK_ARG_NON_NULL(mech);
	CHECK_ARG_NON_NULL(clear_text);
	CHECK_ARG_NON_NULL(p_cipher_text_len);

	if (!ICSF_CHAINING_IS_VALID(chaining)) {
		TRACE_ERROR("Invalid value for chaining: %d\n", chaining);
		return -1;
	}

	object_record_to_handle(handle, key);

	/*
	 * Add to rule array the algorithm, the cipher mode and the
	 * chaining mode.
	 */
	if (!(rule_alg = get_algorithm_rule(mech, 0))) {
		TRACE_ERROR("Invalid algorithm: %lu\n",
			    (unsigned long) mech->mechanism);
		return -1;
	}

	if (!(rule_cipher = get_cipher_mode(mech))) {
		TRACE_ERROR("Invalid cipher mode: %lu\n",
			    (unsigned long) mech->mechanism);
		return -1;
	}

	strpad(rule_array + 0 * ICSF_RULE_ITEM_LEN, rule_alg,
	       ICSF_RULE_ITEM_LEN, ' ');
	strpad(rule_array + 1 * ICSF_RULE_ITEM_LEN, rule_cipher,
	       ICSF_RULE_ITEM_LEN, ' ');
	strpad(rule_array + 2 * ICSF_RULE_ITEM_LEN, ICSF_CHAINING(chaining),
	       ICSF_RULE_ITEM_LEN, ' ');

	/* Set the IV based on the given mechanism */
	if (chaining != ICSF_CHAINING_INITIAL &&
	    chaining != ICSF_CHAINING_ONLY) {
		rc = icsf_encrypt_initial_vector(mech, NULL, NULL);
		memset(init_vector, 0, init_vector_len);
	} else {
		rc = icsf_encrypt_initial_vector(mech, init_vector,
						 &init_vector_len);
	}
	if (rc)
		return -1;

	/* Build request */
	if (!(msg = ber_alloc_t(LBER_USE_DER))) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return -1;
	}

	if (ber_printf(msg, "toooi",
		       0 | LBER_CLASS_CONTEXT, init_vector, init_vector_len,
		       (chaining_data) ? chaining_data : "",
		       (p_chaining_data_len) ? *p_chaining_data_len : 0UL,
		       clear_text, clear_text_len,
		       (cipher_text) ? *p_cipher_text_len : 0UL) < 0) {
		rc = -1;
		TRACE_ERROR("Failed to encode message: %d.\n", rc);
		goto done;
	}

	/* Call service */
	rc = icsf_call(ld, &reason, handle, sizeof(handle),
			rule_array, sizeof(rule_array),
			ICSF_TAG_CSFPSKE, msg, &result);
	if (p_reason)
		*p_reason = reason;
	if (ICSF_RC_IS_ERROR(rc)
			&& reason != ICSF_REASON_OUTPUT_PARAMETER_TOO_SHORT)
		goto done;

	/* Parse response */
	if (ber_scanf(result, "{mmi", &bv_chaining_data, &bv_cipher_data,
		       &length) < 0) {
		rc = -1;
		TRACE_ERROR("Failed to decode the response.\n");
		goto done;
	}

	*p_cipher_text_len = length;
	/* Copy encrypted data */
	if (bv_cipher_data.bv_len > *p_cipher_text_len) {
		TRACE_ERROR("Cipher data longer than expected: %lu "
			    "(expected %lu)\n",
			    (unsigned long) bv_cipher_data.bv_len,
			    (unsigned long) *p_cipher_text_len);
		rc = -1;
		goto done;
	}
	if (cipher_text)
		memcpy(cipher_text, bv_cipher_data.bv_val, bv_cipher_data.bv_len);

	/* Copy chaining data */
	if (p_chaining_data_len) {
		if (bv_chaining_data.bv_len > *p_chaining_data_len) {
			TRACE_ERROR("Chaining data longer than expected: %lu "
					"(expected %lu)\n",
					(unsigned long) bv_chaining_data.bv_len,
					(unsigned long) *p_chaining_data_len);
			rc = -1;
			goto done;
		}
		*p_chaining_data_len = bv_chaining_data.bv_len;
		if (chaining_data) {
			memcpy(chaining_data, bv_chaining_data.bv_val,
					*p_chaining_data_len);
		}
	}

done:
	if (result)
		ber_free(result, 1);
	if (msg)
		ber_free(msg, 1);
	return rc;
}

/*
 * Symmetric key decrypt.
 */
int
icsf_secret_key_decrypt(LDAP *ld, int *p_reason, struct icsf_object_record *key,
			CK_MECHANISM_PTR mech, int chaining,
			const char *cipher_text, size_t cipher_text_len,
			char *clear_text, size_t *p_clear_text_len,
			char *chaining_data, size_t *p_chaining_data_len)
{
	int rc = 0;
	char handle[ICSF_HANDLE_LEN];
	char rule_array[3 * ICSF_RULE_ITEM_LEN];
	BerElement *msg = NULL;
	BerElement *result = NULL;
	char init_vector[32];
	size_t init_vector_len = sizeof(init_vector);
	struct berval bv_clear_data = { 0UL, NULL };
	struct berval bv_chaining_data = { 0UL, NULL };
	const char *rule_alg, *rule_cipher;
	int reason = 0, length = 0;

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL(key);
	CHECK_ARG_NON_NULL(mech);
	CHECK_ARG_NON_NULL(cipher_text);
	CHECK_ARG_NON_NULL(p_clear_text_len);

	if (!ICSF_CHAINING_IS_VALID(chaining)) {
		TRACE_ERROR("Invalid value for chaining: %d\n", chaining);
		return -1;
	}

	object_record_to_handle(handle, key);

	/*
	 * Add to rule array the algorithm, the cipher mode and the
	 * chaining mode.
	 */
	if (!(rule_alg = get_algorithm_rule(mech, 0))) {
		TRACE_ERROR("Invalid algorithm: %lu\n",
			    (unsigned long) mech->mechanism);
		return -1;
	}

	if (!(rule_cipher = get_cipher_mode(mech))) {
		TRACE_ERROR("Invalid cipher mode: %lu\n",
			    (unsigned long) mech->mechanism);
		return -1;
	}

	strpad(rule_array + 0 * ICSF_RULE_ITEM_LEN, rule_alg,
	       ICSF_RULE_ITEM_LEN, ' ');
	strpad(rule_array + 1 * ICSF_RULE_ITEM_LEN, rule_cipher,
	       ICSF_RULE_ITEM_LEN, ' ');
	strpad(rule_array + 2 * ICSF_RULE_ITEM_LEN, ICSF_CHAINING(chaining),
	       ICSF_RULE_ITEM_LEN, ' ');

	/* Set the IV based on the given mechanism */
	if (chaining != ICSF_CHAINING_INITIAL &&
	    chaining != ICSF_CHAINING_ONLY) {
		rc = icsf_encrypt_initial_vector(mech, NULL, NULL);
		memset(init_vector, 0, init_vector_len);
	} else {
		rc = icsf_encrypt_initial_vector(mech, init_vector,
						 &init_vector_len);
	}
	if (rc)
		return -1;

	/* Build request */
	if (!(msg = ber_alloc_t(LBER_USE_DER))) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return -1;
	}

	if (ber_printf(msg, "totototi",
		       0 | LBER_CLASS_CONTEXT | LBER_PRIMITIVE,
		       init_vector, init_vector_len,
		       2 | LBER_CLASS_CONTEXT | LBER_PRIMITIVE,
		       (chaining_data) ? chaining_data : "",
		       (p_chaining_data_len) ? *p_chaining_data_len : 0UL,
		       3 | LBER_CLASS_CONTEXT | LBER_PRIMITIVE,
		       cipher_text, cipher_text_len,
		       4 | LBER_CLASS_CONTEXT | LBER_PRIMITIVE,
		       (clear_text) ? *p_clear_text_len : 0UL) < 0) {
		rc = -1;
		TRACE_ERROR("Failed to encode message: %d.\n", rc);
		goto done;
	}

	/* Call service */
	rc = icsf_call(ld, &reason, handle, sizeof(handle),
		       rule_array, sizeof(rule_array),
		       ICSF_TAG_CSFPSKD, msg, &result);
	if (p_reason)
		*p_reason = reason;
	if (ICSF_RC_IS_ERROR(rc) &&
			reason != ICSF_REASON_OUTPUT_PARAMETER_TOO_SHORT)
		goto done;

	/* Parse response */
	if (ber_scanf(result, "{mmi", &bv_chaining_data, &bv_clear_data,
		      &length) < 0) {
		rc = -1;
		TRACE_ERROR("Failed to decode the response.\n");
		goto done;
	}

	*p_clear_text_len = length;
	/* Copy encrypted data */
	if (bv_clear_data.bv_len > *p_clear_text_len) {
		TRACE_ERROR("Clear data longer than expected: %lu "
			    "(expected %lu)\n",
				(unsigned long) bv_clear_data.bv_len,
				(unsigned long) *p_clear_text_len);
		rc = -1;
		goto done;
	}
	if (clear_text)
		memcpy(clear_text, bv_clear_data.bv_val, bv_clear_data.bv_len);

	/* Copy chaining data */
	if (p_chaining_data_len) {
		if (bv_chaining_data.bv_len > *p_chaining_data_len) {
			TRACE_ERROR("Chaining data longer than expected: %lu "
					"(expected %lu)\n",
					(unsigned long) bv_chaining_data.bv_len,
					(unsigned long) *p_chaining_data_len);
			rc = -1;
			goto done;
		}
		*p_chaining_data_len = bv_chaining_data.bv_len;
		if (chaining_data) {
			memcpy(chaining_data, bv_chaining_data.bv_val,
					*p_chaining_data_len);
		}
	}

	rc = 0;
done:
	if (result)
		ber_free(result, 1);
	if (msg)
		ber_free(msg, 1);

	return rc;
}

static int
icsf_ber_decode_get_attribute_list(BerElement *berbuf, CK_ATTRIBUTE *attrs,
				   CK_ULONG attrs_len)
{
	int attrtype;
	struct berval attrbval = {0, NULL};
	ber_int_t intval;
	int i, found = 0;
	ber_tag_t tag;
	CK_RV rc = CKR_OK;

	if (ber_scanf(berbuf, "{{") == LBER_ERROR)
		goto decode_error;

	while (1) {

		/* get tag preceding sequence */
		if (ber_scanf(berbuf, "t", &tag) == LBER_ERROR)
			goto decode_error;

		/* is it a sequence (thus attribute) */
		if (tag != (LBER_CLASS_UNIVERSAL | LBER_CONSTRUCTED
			    | LBER_SEQUENCE))
			break;

		/* sequence, so get attribute info */
		if (ber_scanf(berbuf, "{it", &attrtype, &tag) == LBER_ERROR)
			goto decode_error;
		if ((tag & LBER_BIG_TAG_MASK) == 0) {
			if (ber_scanf(berbuf, "o}", &attrbval) == LBER_ERROR)
				goto decode_error;
		} else {
			if (ber_scanf(berbuf, "i}", &intval) == LBER_ERROR)
				goto decode_error;
			attrbval.bv_len = sizeof(CK_ULONG);
		}

		/* see if this type matches any that we need to
		 * get value for. if so, then get the value, otherwise
		 * continue until we have found all of them or there
		 * are no  more attributes to search
		 */
		for (i = 0; i < attrs_len; i++) {
			if (attrs[i].type != attrtype)
				continue;

			/* we have decoded attribute, now add the values */
			if (attrs[i].pValue == NULL) {
				attrs[i].ulValueLen = attrbval.bv_len;
			} else if (attrs[i].ulValueLen >= attrbval.bv_len) {
				if ((tag & LBER_BIG_TAG_MASK) == 0) {
					memcpy(attrs[i].pValue, attrbval.bv_val,
						attrbval.bv_len);
				} else {
					*((CK_ULONG *) attrs[i].pValue) = intval;
				}
				attrs[i].ulValueLen = attrbval.bv_len;
			} else {
				rc = CKR_BUFFER_TOO_SMALL;
				attrs[i].ulValueLen = -1;
				goto decode_error;
			}

			/* keep count of how many are found. */
			found++;
		}

		/* if we have found all the values for our list, then
		 * we are done.
		 */
		if (found == attrs_len)
			break;
	}

	/* if we have gone through the entire loop and could not find
	 * all of the attributes in our list, mark this as an error.
	 */
	if (found < attrs_len) {
		TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_TYPE_INVALID));
		rc = CKR_ATTRIBUTE_TYPE_INVALID;
		goto decode_error;
	}

	return rc;

decode_error:
	TRACE_ERROR("Failed to decode message.\n");

	if (!rc)
		rc = CKR_FUNCTION_FAILED;

	return rc;
}

int
icsf_get_attribute(LDAP *ld, int *reason, struct icsf_object_record *object,
		   CK_ATTRIBUTE *attrs, CK_ULONG attrs_len)
{

	char handle[ICSF_HANDLE_LEN];
	BerElement *msg = NULL;
	BerElement *result = NULL;
	int rc = 0;
	int i;

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL(attrs);
	CHECK_ARG_NON_NULL(object);

	object_record_to_handle(handle, object);

	if (!(msg = ber_alloc_t(LBER_USE_DER))) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return CKR_HOST_MEMORY;
	}

	/* Encode message:
	 *
	 * GAVInput ::= attrListLen
	 *
	 * attrListLen ::= INTEGER (0 .. MaxCSFPInteger)
	 *
	 */

	rc = ber_printf(msg, "i", attrs_len);
	if (rc < 0)
		goto cleanup;

	rc = icsf_call(ld, reason, handle, sizeof(handle), "", 0,
			ICSF_TAG_CSFPGAV, msg, &result);
	if (rc != 0) {
		TRACE_DEVEL("icsf_call failed.\n");
		goto cleanup;
	}

	/* Before decoding the result, initialize the attribute values length.
	 * This will help to indicate which attributes were not found
	 * or not enough storage was allocated for the value.
	 */
	for (i = 0; i < attrs_len; i++)
		attrs[i].ulValueLen = (CK_ULONG)-1;

	/* Decode the result:
	 *
	 * GAVOutput ::= SEQUENCE {
	 *    attrList		Attributes,
	 *    attrListLen	INTEGER (0 .. MaxCSFPInteger)
	 * }
	 *
	 * asn.1 {{{ito|i} {ito|i} ...}i}
	 */
	rc = icsf_ber_decode_get_attribute_list(result, attrs, attrs_len);
	if (rc < 0) {
		TRACE_ERROR("Failed to decode message.\n");
		goto cleanup;
	}

cleanup:
	if (msg)
		ber_free(msg, 1);

	if (result)
		ber_free(result, 1);

	return rc;
}

int
icsf_set_attribute(LDAP *ld, int *reason, struct icsf_object_record *object,
		   CK_ATTRIBUTE *attrs, CK_ULONG attrs_len)
{
	int rc = -1;
	char handle[ICSF_HANDLE_LEN];
	BerElement *msg = NULL;

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL(attrs);

	object_record_to_handle(handle, object);

	if (!(msg = ber_alloc_t(LBER_USE_DER))) {
		return rc;
	}

	/* Encode message:
	 *
	 * SAVInput ::=  Attributes
	 *
	 * attrList is built by icsf_ber_put_attribute_list()
	 */
	if (icsf_ber_put_attribute_list(msg, attrs, attrs_len) < 0) {
		TRACE_ERROR("Failed to encode message.\n");
		goto cleanup;
	}

	rc = icsf_call(ld, reason, handle, sizeof(handle), "", 0,
			ICSF_TAG_CSFPSAV, msg, NULL);
	if (rc < 0) {
		TRACE_ERROR("icsf_call failed.\n");
		goto cleanup;
	}

	/* Decode message:
	 *
	 * SAVOutput ::=  NULL
	 *
	 */

cleanup:
	if (msg)
		ber_free(msg, 1);


	return rc;
}

/*
 * Sign or decrypt data using a private key.
 */
int
icsf_private_key_sign(LDAP *ld, int *p_reason, int decrypt,
		      struct icsf_object_record *key, CK_MECHANISM_PTR mech,
		      const char *cipher_text, size_t cipher_text_len,
		      char *clear_text, size_t *p_clear_text_len)
{
	int rc;
	int reason = 0;
	char handle[ICSF_HANDLE_LEN];
	char rule_array[2 * ICSF_RULE_ITEM_LEN];
	size_t rule_array_count = 0;
	const char *rule_alg;
	BerElement *msg = NULL;
	BerElement *result = NULL;
	struct berval bv_clear_text = { 0, NULL };
	int length = 0;

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL(key);
	CHECK_ARG_NON_NULL(mech);
	CHECK_ARG_NON_NULL(cipher_text);
	CHECK_ARG_NON_NULL(p_clear_text_len);

	object_record_to_handle(handle, key);

	/* Build rule array based on mechanism */
	if (!(rule_alg = get_algorithm_rule(mech, 0))) {
		TRACE_ERROR("Invalid algorithm: %lu\n",
			(unsigned long) mech->mechanism);
		return -1;
	}

	strpad(rule_array, rule_alg, ICSF_RULE_ITEM_LEN, ' ');
	rule_array_count += 1;
	if (decrypt) {
		strpad(rule_array + (rule_array_count * ICSF_RULE_ITEM_LEN),
			"DECRYPT", ICSF_RULE_ITEM_LEN, ' ');
		rule_array_count += 1;
	}

	/* Build request */
	if (!(msg = ber_alloc_t(LBER_USE_DER)))
	{
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return -1;
	}

	if (ber_printf(msg, "oi", cipher_text, (ber_int_t) cipher_text_len,
		       (!clear_text) ? 0 : ((ber_int_t) *p_clear_text_len)) < 0) {
		rc = -1;
		TRACE_ERROR("Failed to encode message: %d.\n", rc);
		goto done;
	}

	/* Call service */
	rc = icsf_call(ld, &reason, handle, sizeof(handle), rule_array,
			rule_array_count * ICSF_RULE_ITEM_LEN, ICSF_TAG_CSFPPKS,
			msg, &result);
	if (p_reason)
		*p_reason = reason;
	if (ICSF_RC_IS_ERROR(rc)
			&& reason != ICSF_REASON_OUTPUT_PARAMETER_TOO_SHORT)
		goto done;

	if (ber_scanf(result, "{mi}", &bv_clear_text, &length) < 0) {
		rc = -1;
		TRACE_ERROR("Failed to decode the response.\n");
		goto done;
	}

	/* Copy clear data */
	*p_clear_text_len = length;
	if (bv_clear_text.bv_len > *p_clear_text_len) {
		TRACE_ERROR("Clear data longer than expected: %lu "
				"(expected %lu)\n",
				(unsigned long) bv_clear_text.bv_len,
				(unsigned long) *p_clear_text_len);
		rc = -1;
		goto done;
	}
	if (clear_text)
		memcpy(clear_text, bv_clear_text.bv_val, *p_clear_text_len);

done:
	if (result)
		ber_free(result, 1);
	if (msg)
		ber_free(msg, 1);
	return rc;
}

/*
 * Verify or encrypt using a public. key.
 */
int
icsf_public_key_verify(LDAP *ld, int *p_reason, int encrypt,
		       struct icsf_object_record *key, CK_MECHANISM_PTR mech,
		       const char *clear_text, size_t clear_text_len,
		       char *cipher_text, size_t *p_cipher_text_len)
{
	int rc;
	int reason = 0;
	char handle[ICSF_HANDLE_LEN];
	char rule_array[2 * ICSF_RULE_ITEM_LEN];
	size_t rule_array_count = 0;
	const char *rule_alg;
	BerElement *msg = NULL;
	BerElement *result = NULL;
	struct berval bv_cipher_text = { 0, NULL };
	int length = 0;

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL(key);
	CHECK_ARG_NON_NULL(mech);
	CHECK_ARG_NON_NULL(clear_text);
	CHECK_ARG_NON_NULL(p_cipher_text_len);

	object_record_to_handle(handle, key);

	/* Build rule array based on mechanism */
	if (!(rule_alg = get_algorithm_rule(mech, 0))) {
		TRACE_ERROR("Invalid algorithm: %lu\n",
			(unsigned long) mech->mechanism);
		return -1;
	}

	strpad(rule_array, rule_alg, ICSF_RULE_ITEM_LEN, ' ');
	rule_array_count += 1;
	if (encrypt) {
		strpad(rule_array + (rule_array_count * ICSF_RULE_ITEM_LEN),
			"ENCRYPT", ICSF_RULE_ITEM_LEN, ' ');
		rule_array_count += 1;
	}

	/* Build request */
	if (!(msg = ber_alloc_t(LBER_USE_DER)))
	{
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return -1;
	}

	if (encrypt) {
		rc = ber_printf(msg, "oti", clear_text, clear_text_len,
				0 | LBER_CLASS_CONTEXT, *p_cipher_text_len);
	} else {
		rc = ber_printf(msg, "oto", cipher_text, *p_cipher_text_len,
				1 | LBER_CLASS_CONTEXT, clear_text,
				clear_text_len);
	}
	if (rc < 0) {
		rc = -1;
		TRACE_ERROR("Failed to encode message: %d.\n", rc);
		goto done;
	}

	/* Call request */
	rc = icsf_call(ld, &reason, handle, sizeof(handle), rule_array,
			rule_array_count * ICSF_RULE_ITEM_LEN, ICSF_TAG_CSFPPKV,
			msg, &result);
	if (p_reason)
		*p_reason = reason;
	if (ICSF_RC_IS_ERROR(rc)
			&& reason != ICSF_REASON_OUTPUT_PARAMETER_TOO_SHORT)
		goto done;

	/* There's no output data when verifying */
	if (!encrypt)
		goto done;

	if (ber_scanf(result, "{mi}", &bv_cipher_text, &length) < 0) {
		rc = -1;
		TRACE_ERROR("Failed to decode the response.\n");
		goto done;
	}

	/* Copy clear data */
	*p_cipher_text_len = length;
	if (bv_cipher_text.bv_len != *p_cipher_text_len) {
		TRACE_ERROR("Cipher data length different that expected: %lu "
				"(expected %lu)\n",
				(unsigned long) bv_cipher_text.bv_len,
				(unsigned long) *p_cipher_text_len);
		rc = -1;
		goto done;
	}
	if (cipher_text)
		memcpy(cipher_text, bv_cipher_text.bv_val, *p_cipher_text_len);

done:
	if (result)
		ber_free(result, 1);
	if (msg)
		ber_free(msg, 1);
	return rc;
}

int icsf_hmac_sign(LDAP *ld, int *reason, struct icsf_object_record *key,
		   CK_MECHANISM_PTR mech, const char *chain_rule,
		   const char *clear_text, size_t clear_text_len, char *hmac,
		   size_t *hmac_len, char *chain_data, size_t *chain_data_len)
{
	int rc = 0;
	char handle[ICSF_HANDLE_LEN];
	char rule_array[2 * ICSF_RULE_ITEM_LEN];
	BerElement *msg = NULL;
	BerElement *result = NULL;
	struct berval bvHmac = { 0, NULL };
	struct berval bvChain = { 0, NULL };
	int hmac_length;
	const char *rule_alg;

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL(key);
	CHECK_ARG_NON_NULL(mech);

	object_record_to_handle(handle, key);

	/* Add to rule array, the algorithm and chaining mode */

	if (!(rule_alg = get_algorithm_rule(mech, 0))) {
		TRACE_ERROR("Invalid algorithm: %lu\n",
			    (unsigned long) mech->mechanism);
		return -1;
	}

	strpad(rule_array + 0 * ICSF_RULE_ITEM_LEN, rule_alg,
		ICSF_RULE_ITEM_LEN, ' ');
	strpad(rule_array + 1 * ICSF_RULE_ITEM_LEN, chain_rule,
		ICSF_RULE_ITEM_LEN, ' ');

	/* Build the request */
	if (!(msg = ber_alloc_t(LBER_USE_DER))) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return -1;
	}

	/* Input ASN.1 for CSFPHMG.
	 * HMGInput ::= SEQUENCE {
	 *	text		OCTET STRING,
	 *	chainData	OCTET STRING,
	 *	hmacLength	INTEGER (0 .. MaxCSFPInteger)
	 * }
	 */

	if (ber_printf(msg, "ooi", clear_text, clear_text_len, chain_data,
			*chain_data_len, *hmac_len) < 0) {
		rc = -1;
		TRACE_ERROR("Failed to encode message: %d.\n", rc);
		goto done;
	}

	/* Call service */
	rc = icsf_call(ld, reason, handle, sizeof(handle), rule_array,
			sizeof(rule_array), ICSF_TAG_CSFPHMG, msg, &result);

	if (ICSF_RC_IS_ERROR(rc)) {
		TRACE_DEVEL("icsf_call failed\n");
		goto done;
	}

	/* Parse the response.
	 * HMGOutput ::= SEQUENCE {
	 *	chainData	OCTET STRING,
	 *      hmac		OCTET STRING,
	 *	hmacLength	INTEGER (0 .. MaxCSFPInteger)
	 * }
	 *
	 * Where,
	 * chainData - A string that specifies the chaining data returned
	 * during multi-part HMAC hashing in the CSFPHMG callable service.
	 * This chainData must be specified on subsequent calls to
	 * the CSFPHMG callable service.
	 * hmac	      - A string containing the HMAC value
	 * hmacLength - ignored by ICSF
	 *
	 * NOTE:
	 * - chainData is always blindly returned, whether it is pertinent
	 *   or not.
	 * - For a FIRST or MIDDLE request, hmac is returned as a zero length
	 *   string.
	 * - For a LAST or ONLY request, hmac is returned as a string of
	 *   appropriate length based on the mechanism. The validity of the hmac
	 *   contents are subject to ICSF behavior, based on the ICSF return
	 *   code and ICSF reason code.
	 * - The hmacLength is ignored by ICSF and has no affect on how we
	 *   encode the returned hmac. The hmacLength is passed along through
	 *   the BER encoded messages and in and out of the ICSF call in case
	 *   this changes in the future.
	 */

	if (ber_scanf(result, "{ooi}", &bvChain, &bvHmac, &hmac_length) < 0) {
		rc = -1;
		TRACE_ERROR("Failed to decode the response.\n");
		goto done;
	}

	/* copy the chained data even if not using it*/
	*chain_data_len = bvChain.bv_len;
	memcpy(chain_data, bvChain.bv_val, bvChain.bv_len);

	/* copy the hmac when needed */
	if (*hmac_len) {
		if (*hmac_len >= bvHmac.bv_len) {
			memcpy(hmac, bvHmac.bv_val, bvHmac.bv_len);
			*hmac_len = bvHmac.bv_len;
		} else
			/* supplied buffer is too small */
			*reason = 3003;
	}
done:
	if (result)
		ber_free(result, 1);

	if (msg)
		ber_free(msg, 1);
	if (bvHmac.bv_val)
		ber_memfree(bvHmac.bv_val);
	if (bvChain.bv_val)
		ber_memfree(bvChain.bv_val);

	return rc;
}

int icsf_hmac_verify(LDAP *ld, int *reason, struct icsf_object_record *key,
		   CK_MECHANISM_PTR mech, const char *chain_rule,
		   const char *clear_text, size_t clear_text_len,
		   char *hmac, size_t hmac_len, char *chain_data,
		   size_t *chain_data_len)
{
	int rc = 0;
	char handle[ICSF_HANDLE_LEN];
	char rule_array[2 * ICSF_RULE_ITEM_LEN];
	BerElement *msg = NULL;
	BerElement *result = NULL;
	struct berval bvChain = { 0UL, NULL };
	const char *rule_alg;

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL(key);
	CHECK_ARG_NON_NULL(mech);

	object_record_to_handle(handle, key);

	/* Add to rule array, the algorithm and chaining mode */

	if (!(rule_alg = get_algorithm_rule(mech, 0))) {
		TRACE_ERROR("Invalid algorithm: %lu\n",
			    (unsigned long) mech->mechanism);
		return -1;
	}

	strpad(rule_array + 0 * ICSF_RULE_ITEM_LEN, rule_alg,
		ICSF_RULE_ITEM_LEN, ' ');
        strpad(rule_array + 1 * ICSF_RULE_ITEM_LEN, chain_rule,
		ICSF_RULE_ITEM_LEN, ' ');

	/* Build the request */
	if (!(msg = ber_alloc_t(LBER_USE_DER))) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return -1;
	}

	/*
	 * Input ASN.1 for CSFPHMV.
	 * HMVInput ::= SEQUENCE {
	 *	text		OCTET STRING,
	 *	chainData	OCTET STRING,
	 *	hmac		OCTET STRING
	 * }
	 *
	 * Where,
	 * text	     - A string that identifies the text to test an HMAC hash
	 *             in the CSFPHMV callable service.
	 * chainData - A string that specifies the chaining data maintained
	 *             during multi-part HMAC hashing in the CSFPHMV callable
	 *             service.
	 * hmac      - A string that identifies the HMAC hash to verify
	 *             against the text in the CSFPHMV callable service.
	 * NOTE:
	 * - chainData is always required, even on a FIRST call (where it is
	 *   not really an input) and even on an ONLY call (where there is no
	 *   chaining).  An HMV ONLY call fails with reason_code=11000 when
	 *   chain_data_length is 0.
	 * - For an ONLY call or LAST call, hmac MUST be at least as
	 *   many bytes in length as required based on the mechanism.
	 * - For a FIRST or MIDDLE call, hmac is ignored.
	 */
	if (ber_printf(msg, "ooo", clear_text, clear_text_len, chain_data,
			*chain_data_len, hmac, hmac_len) < 0) {
		rc = -1;
		TRACE_ERROR("Failed to encode message: %d.\n", rc);
		goto done;
	}

	/* Call service */
	rc = icsf_call(ld, reason, handle, sizeof(handle), rule_array,
			sizeof(rule_array), ICSF_TAG_CSFPHMV, msg, &result);

	if (ICSF_RC_IS_ERROR(rc)) {
		TRACE_DEVEL("icsf_call failed\n");
		goto done;
	}

	/* Parse the response.
	 * HMVOutput ::= chainData	OCTET STRING
	 *
	 * Where,
	 * chainData - A string that specifies the chaining data returned
	 * during multi-part HMAC hashing in the CSFPHMV callable service.
	 * This chainData must be specified on subsequent calls to
	 * the CSFPHMV callable service.
	 *
	 * NOTE:
	 * - chainData is always blindly returned, whether it is pertinent
	 *   or not.
	 */
	if (ber_scanf(result, "m", &bvChain) < 0) {
		rc = -1;
		TRACE_ERROR("Failed to decode the response.\n");
		goto done;
	}

	/* if chaining, copy the chained data */
	*chain_data_len = bvChain.bv_len;
	memcpy(chain_data, bvChain.bv_val, bvChain.bv_len);

done:
	if (result)
		ber_free(result, 1);

	if (msg)
		ber_free(msg, 1);

	return rc;
}

/*
 * Wrap a key.
 */
int
icsf_wrap_key(LDAP *ld, int *p_reason, CK_MECHANISM_PTR mech,
	      struct icsf_object_record *wrapping_key,
	      struct icsf_object_record *key, CK_BYTE_PTR wrapped_key,
	      CK_ULONG_PTR p_wrapped_key_len)
{
	int rc = 0;
	int reason = 0;
	char handle[ICSF_HANDLE_LEN];
	char wrapping_handle[ICSF_HANDLE_LEN];
	char rule_array[2 * ICSF_RULE_ITEM_LEN];
	size_t rule_array_count = 0;
	const char *rule_fmt = NULL;
	const char *rule_alg = NULL;
	BerElement *msg = NULL;
	BerElement *result = NULL;
	struct berval bv_wrapped_key = { 0, NULL };
	ber_int_t wrapped_key_len = 0;

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL(mech);
	CHECK_ARG_NON_NULL(wrapping_key);
	CHECK_ARG_NON_NULL(key);
	CHECK_ARG_NON_NULL(p_wrapped_key_len);

	object_record_to_handle(handle, key);
	object_record_to_handle(wrapping_handle, wrapping_key);

	/* Build rule array based on mechanism */
	switch (mech->mechanism) {
	case CKM_RSA_PKCS:
		rule_fmt= "PKCS-1.2";
		break;
	case CKM_DES_CBC_PAD:
	case CKM_DES3_CBC_PAD:
	case CKM_AES_CBC_PAD:
		rule_fmt = "PKCS-8";
		if (!(rule_alg = get_algorithm_rule(mech, 0))) {
			TRACE_ERROR("Invalid algorithm: %lu\n",
				    (unsigned long) mech->mechanism);
			return -1;
		}
		break;
	default:
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return -1;
	}

	strpad(rule_array, rule_fmt, ICSF_RULE_ITEM_LEN, ' ');
	rule_array_count += 1;
	if (rule_alg) {
		strpad(rule_array + (rule_array_count * ICSF_RULE_ITEM_LEN),
			rule_alg, ICSF_RULE_ITEM_LEN, ' ');
		rule_array_count += 1;
	}

	/* Build request */
	if (!(msg = ber_alloc_t(LBER_USE_DER))) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return -1;
	}

	/* Encode message:
	 *
	 * WPKInput ::= SEQUENCE {
	 *  	wrappingHandle		OCTET STRING,
	 * 	wrappedKeyMaxLen	INTEGER (0 .. MaxCSFPInteger),
	 * 	initialValue		OCTET STRING
	 * }
	 */
	rc = ber_printf(msg, "ois", wrapping_handle, sizeof(wrapping_handle),
			(ber_int_t) *p_wrapped_key_len, "");
	if (rc < 0) {
		rc = -1;
		TRACE_ERROR("Failed to encode message: %d.\n", rc);
		goto done;
	}

	/* Call request */
	rc = icsf_call(ld, &reason, handle, sizeof(handle), rule_array,
			rule_array_count * ICSF_RULE_ITEM_LEN, ICSF_TAG_CSFPWPK,
			msg, &result);
	if (p_reason)
		*p_reason = reason;
	if (ICSF_RC_IS_ERROR(rc)
			&& reason != ICSF_REASON_OUTPUT_PARAMETER_TOO_SHORT)
		goto done;

	/* Decode message:
	 *
	 * WPKOutput ::= SEQUENCE {
	 * 	wrappedKey	OCTET STRING,
	 * 	wrappedKeyLen	INTEGER
	 * }
	 */
	if (ber_scanf(result, "{mi}", &bv_wrapped_key, &wrapped_key_len) < 0) {
		rc = -1;
		TRACE_ERROR("Failed to decode the response.\n");
		goto done;
	}
	*p_wrapped_key_len = wrapped_key_len;

	/* Copy wrapped key*/
	if (bv_wrapped_key.bv_len > *p_wrapped_key_len) {
		TRACE_ERROR("Wrapped key length different that expected: %lu "
				"(expected %lu)\n",
				(unsigned long) bv_wrapped_key.bv_len,
				(unsigned long) *p_wrapped_key_len);
		rc = -1;
		goto done;
	}
	if (wrapped_key)
		memcpy(wrapped_key, bv_wrapped_key.bv_val, *p_wrapped_key_len);

done:
	if (result)
		ber_free(result, 1);
	if (msg)
		ber_free(msg, 1);
	return rc;
}

/*
 * Unwrap a key.
 */
int
icsf_unwrap_key(LDAP *ld, int *p_reason, CK_MECHANISM_PTR mech,
		struct icsf_object_record *unwrapping_key,
		CK_BYTE_PTR wrapped_key, CK_ULONG wrapped_key_len,
		CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len,
		struct icsf_object_record *key)
{
	int rc = 0;
	int reason = 0;
	char handle[ICSF_HANDLE_LEN];
	char rule_array[2 * ICSF_RULE_ITEM_LEN];
	size_t rule_array_count = 0;
	const char *rule_fmt = NULL;
	const char *rule_alg = NULL;
	BerElement *msg = NULL;

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL(mech);
	CHECK_ARG_NON_NULL(unwrapping_key);
	CHECK_ARG_NON_NULL(wrapped_key);
	CHECK_ARG_NON_NULL(key);

	object_record_to_handle(handle, unwrapping_key);

	/* Build rule array based on mechanism */
	switch (mech->mechanism) {
	case CKM_RSA_PKCS:
		rule_fmt= "PKCS-1.2";
		break;
	case CKM_DES_CBC_PAD:
	case CKM_DES3_CBC_PAD:
	case CKM_AES_CBC_PAD:
		rule_fmt = "PKCS-8";
		if (!(rule_alg = get_algorithm_rule(mech, 0))) {
			TRACE_ERROR("Invalid algorithm: %lu\n",
				    (unsigned long) mech->mechanism);
			return -1;
		}
		break;
	default:
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return -1;
	}

	strpad(rule_array, rule_fmt, ICSF_RULE_ITEM_LEN, ' ');
	rule_array_count += 1;
	if (rule_alg) {
		strpad(rule_array + (rule_array_count * ICSF_RULE_ITEM_LEN),
			rule_alg, ICSF_RULE_ITEM_LEN, ' ');
		rule_array_count += 1;
	}

	/* Build request */
	if (!(msg = ber_alloc_t(LBER_USE_DER))) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return -1;
	}

	/* Encode message:
	 *
	 * UWKInput ::= SEQUENCE {
	 * 	wrappedKey	OCTET STRING,
	 * 	initialValue	OCTET STRING,
	 * 	attrList	Attributes
	 * }
	 */
	if (ber_printf(msg, "os", wrapped_key, wrapped_key_len, "") < 0 ||
			ber_printf(msg, "{") < 0 ||
			icsf_ber_put_attribute_list(msg, attrs, attrs_len) ||
			ber_printf(msg, "}") < 0) {
		rc = -1;
		TRACE_ERROR("Failed to encode message: %d.\n", rc);
		goto done;
	}

	/* Call request */
	rc = icsf_call(ld, &reason, handle, sizeof(handle), rule_array,
			rule_array_count * ICSF_RULE_ITEM_LEN, ICSF_TAG_CSFPUWK,
			msg, NULL);
	if (p_reason)
		*p_reason = reason;
	if (ICSF_RC_IS_ERROR(rc))
		goto done;

	handle_to_object_record(key, handle);

done:
	if (msg)
		ber_free(msg, 1);
	return rc;
}

int icsf_hash_signverify(LDAP *ld, int *reason, struct icsf_object_record *key,
			 CK_MECHANISM_PTR mech, const char *chain_rule,
			 const char *clear_text, unsigned long clear_text_len,
			 char *sig, unsigned long *sig_len, char *chain_data,
			 size_t *chain_data_len, int verify)
{
	int rc = 0;
	char handle[ICSF_HANDLE_LEN];
	char rule_array[3 * ICSF_RULE_ITEM_LEN];
	BerElement *msg = NULL;
	BerElement *result = NULL;
	struct berval bvSig = { 0, NULL };
	struct berval bvChain = { 0, NULL };
	int length, reason_code;
	const char *rule_alg;

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL(key);
	CHECK_ARG_NON_NULL(mech);

	object_record_to_handle(handle, key);

	/* Add to rule array, the algorithm and chaining mode */
	if (!(rule_alg = get_algorithm_rule(mech, verify))) {
		TRACE_ERROR("Invalid algorithm: %lu\n",
			    (unsigned long) mech->mechanism);
		return -1;
	}

	strpad(rule_array + 0 * ICSF_RULE_ITEM_LEN, rule_alg,
	       2 * ICSF_RULE_ITEM_LEN, ' ');
	strpad(rule_array + 2 * ICSF_RULE_ITEM_LEN, chain_rule,
	       ICSF_RULE_ITEM_LEN, ' ');

	/* Build the request */
	if (!(msg = ber_alloc_t(LBER_USE_DER))) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return -1;
	}

	if (ber_printf(msg, "ooo", (clear_text) ? clear_text : "",
		       clear_text_len, (chain_data) ? chain_data : "",
		      (chain_data_len) ? *chain_data_len : 0UL,
		      (sig) ? sig : "", (sig_len) ? *sig_len : 0) < 0) {
		rc = -1;
		TRACE_ERROR("Failed to encode message: %d.\n", rc);
		goto done;
	}

	/* Call service */
	rc = icsf_call(ld, &reason_code, handle, sizeof(handle), rule_array,
			sizeof(rule_array), ICSF_TAG_CSFPOWH, msg, &result);

	if (reason)
		*reason = reason_code;

	/* If there was an error related to buffer being too small,
	 * don't exit until you get the max required length from response.
	 */
	if (ICSF_RC_IS_ERROR(rc) && (reason_code != 3003))
		goto done;

	/* Parse the response. */
	if (ber_scanf(result, "{ooi}", &bvChain, &bvSig, &length) < 0) {
		rc = -1;
		TRACE_ERROR("Failed to decode the response.\n");
		goto done;
	}

	/* Only need to return the length for signing */
	if (sig_len && !verify)
		*sig_len = length;

	/* leave if just returning the length. */
	if (!verify && *reason == 3003)
		goto done;

	/* copy the chained data when required */
	if (chain_data)
		memcpy(chain_data, bvChain.bv_val, bvChain.bv_len);

	/* copy signature when signing */
	if (!verify)
		memcpy(sig, bvSig.bv_val, bvSig.bv_len);

done:
	if (result)
		ber_free(result, 1);
	if (msg)
		ber_free(msg, 1);
	if (bvSig.bv_val)
		ber_memfree(bvSig.bv_val);
	if (bvChain.bv_val)
		ber_memfree(bvChain.bv_val);

	return rc;
}

/*
 * Derive a symmetric key.
 */
int
icsf_derive_key(LDAP *ld, int *reason, CK_MECHANISM_PTR mech,
		struct icsf_object_record *baseKey,
		struct icsf_object_record *object,
		CK_ATTRIBUTE *attrs, CK_ULONG attrs_len)
{
	int rc = -1;
	char handle[ICSF_HANDLE_LEN];
	char rule_array[1 * ICSF_RULE_ITEM_LEN];
	BerElement *msg = NULL;
	BerElement *result = NULL;
	CK_VERSION_PTR version = NULL;
	CK_SSL3_MASTER_KEY_DERIVE_PARAMS * params = NULL;
	CK_SSL3_RANDOM_DATA * random_data = NULL;
	struct berval clientData = {0, NULL}, serverData = {0, NULL};
	struct berval publicValue = {0, NULL}, bvParam = {0, NULL};

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL(mech);

	object_record_to_handle(handle, baseKey);

	/* Map mechanism into the rule array */
	switch (mech->mechanism) {
	case CKM_SSL3_MASTER_KEY_DERIVE:
		strpad(rule_array, "SSL-MS", ICSF_RULE_ITEM_LEN, ' ');
		break;
	case CKM_DH_PKCS_DERIVE:
		strpad(rule_array, "PKCS-DH", ICSF_RULE_ITEM_LEN, ' ');
		break;
	default:
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return -1;
	}

	if (!(msg = ber_alloc_t(LBER_USE_DER))) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return rc;
	}

	/* Encode message:
	 *
	 * DVKInput ::= SEQUENCE {
	 * 	attrList	Attributes,
	 * 	parmsListChoice	DVKInputParmsList
	 * }
	 *
	 * DVKInputParmsList ::= CHOICE {
	 *    PKCS-DH_publicValue  [0] OCTET STRING,
	 *    SSL-TLS              [1] SSL-TLS_DVKInputParmsList,
	 *    EC-DH                [2] EC-DH_DVKInputParmsList
	 * }
	 *
	 * SSL-TLS_DVKInputParmsList ::= SEQUENCE {
	 *    clientRandomData    OCTET STRING,
	 *    serverRandomData    OCTET STRING
	 * }
	 *
	 * EC-DH is not supported
	 *
	 * attrList is built by icsf_ber_put_attribute_list()
	 */
	if (ber_printf(msg, "{") < 0) {
		TRACE_ERROR("Failed to encode message.\n");
		goto cleanup;
	}

	if (icsf_ber_put_attribute_list(msg, attrs, attrs_len) < 0 ) {
		TRACE_DEVEL("Failed to encode message.\n");
		goto cleanup;
	}

	if (ber_printf(msg, "}") < 0) {
		TRACE_ERROR("Failed to encode message.\n");
		goto cleanup;
	}

	/* Attribute list depends on type of mechanism */
	switch (mech->mechanism) {
	case CKM_DH_PKCS_DERIVE:
		if ((!mech->pParameter) || ((mech->ulParameterLen < 64) ||
		    (mech->ulParameterLen > 256))) {
			TRACE_ERROR("%s\n",
				    ock_err(ERR_MECHANISM_PARAM_INVALID));
			return CKR_MECHANISM_PARAM_INVALID;
		}
		publicValue.bv_val = mech->pParameter;
		publicValue.bv_len = mech->ulParameterLen;
		if (ber_printf(msg, "tO", 0|LBER_PRIMITIVE|LBER_CLASS_CONTEXT, &publicValue) < 0) {
			TRACE_ERROR("Failed to encode message.\n");
			goto cleanup;
		}
		break;
	case CKM_SSL3_MASTER_KEY_DERIVE:
		params = (CK_SSL3_MASTER_KEY_DERIVE_PARAMS *)mech->pParameter;
		random_data = (CK_SSL3_RANDOM_DATA *) (&params->RandomInfo);

		clientData.bv_len = random_data->ulClientRandomLen;
		clientData.bv_val = random_data->pClientRandom;
		serverData.bv_len = random_data->ulServerRandomLen;
		serverData.bv_val = random_data->pServerRandom;

		if (ber_printf(msg, "t{OO}", 1|LBER_CLASS_CONTEXT|LBER_CONSTRUCTED,
		    &clientData, &serverData) < 0) {
			TRACE_ERROR("Failed to encode message.\n");
			goto cleanup;
		}
		break;
	default:
		TRACE_ERROR("Mechanism not supported.\n");
		return -1;
	}

	rc = icsf_call(ld, reason, handle, sizeof(handle), rule_array,
			sizeof(rule_array), ICSF_TAG_CSFPDVK, msg, &result);
	if (!rc) {
		handle_to_object_record(object, handle);

		/* Decode the result:
		*
		* DVKOutput ::= SEQUENCE {
		*    parmsListChoice      DVKOutputParmsList
		* }
		*
		* DVKOutputParmsList ::= CHOICE {
		*    PKCS-DH_Output       [0] NULL,
		*    SSL-TLS_Output       [1] OCTET STRING,
		*    EC-DH_Output         [2] NULL (not supported)
		* }
		*/
		if (mech->mechanism == CKM_SSL3_MASTER_KEY_DERIVE){
			if (ber_scanf(result, "o", &bvParam) < 0 ){
				TRACE_ERROR("Failed to Derive Key\n");
				rc = -1;
				goto cleanup;
			}

			params = (CK_SSL3_MASTER_KEY_DERIVE_PARAMS *)mech->pParameter;
			version = (CK_VERSION_PTR) (&params->pVersion);
			version->major = bvParam.bv_val[0];
			version->minor = bvParam.bv_val[1];
		}
	}

	rc = 0;

cleanup:
	if (msg)
		ber_free(msg, 1);
	if (result)
		ber_free(result, 1);

	return rc;
}

/*
 * Devive multiple keys at once.
 */
int
icsf_derive_multple_keys(LDAP *ld, int *p_reason, CK_MECHANISM_PTR mech,
			 struct icsf_object_record *key,
			 CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len,
			 struct icsf_object_record *client_mac_handle,
			 struct icsf_object_record *server_mac_handle,
			 struct icsf_object_record *client_key_handle,
			 struct icsf_object_record *server_key_handle,
			 unsigned char *client_iv, unsigned char *server_iv)
{
	int rc = 0;
	const char *rule_alg;
	char handle[ICSF_HANDLE_LEN];
	char rule_array[ICSF_RULE_ITEM_LEN];
	BerElement *msg = NULL;
	BerElement *result = NULL;
	ber_tag_t tag;
	CK_SSL3_KEY_MAT_PARAMS *params;
	struct berval bv_client_random_data;
	struct berval bv_server_random_data;
	struct berval bv_client_mac_handle = { 0, NULL };
	struct berval bv_server_mac_handle = { 0, NULL };
	struct berval bv_client_key_handle = { 0, NULL };
	struct berval bv_server_key_handle = { 0, NULL };
	struct berval bv_client_iv = { 0, NULL };
	struct berval bv_server_iv = { 0, NULL };

	CHECK_ARG_NON_NULL(ld);
	CHECK_ARG_NON_NULL(mech);
	CHECK_ARG_NON_NULL(key);

	object_record_to_handle(handle, key);

	/* Build rule array based on mechanism */
	if (!(rule_alg = get_algorithm_rule(mech, 0))) {
		TRACE_ERROR("Invalid algorithm: %lu\n",
			    (unsigned long) mech->mechanism);
		return -1;
	}

	strpad(rule_array, rule_alg, ICSF_RULE_ITEM_LEN, ' ');

	/* Build request */
	if (!(msg = ber_alloc_t(LBER_USE_DER)))
	{
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return -1;
	}

	/**
	 *  DMKInput sequence.
	 *
	 *  DMKInput ::= SEQUENCE {
	 *     attrList             Attributes,
	 *     parmsListChoice      DMKInputParmsList
	 *  }
	 *
	 *  DMKInputParmsList ::= CHOICE {
	 *     SSL-KM_TLS-KM [0]    SSL_TLS_DMKInputParmsList
	 *  }
	 *
	 *  SSL_TLS_DMKInputParmsList ::= SEQUENCE {
	 *     export               BOOLEAN,
	 *     macSize              INTEGER,
	 *     keySize              INTEGER,
	 *     ivSize               INTEGER,
	 *     clientRandomData     OCTET STRING,
	 *     serverRandomData     OCTET STRING
	 *  }
	 */
	params = (CK_SSL3_KEY_MAT_PARAMS *) mech->pParameter;
	if (!params) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
		rc = CKR_MECHANISM_PARAM_INVALID;
		goto done;
	}

	rc = ber_printf(msg, "{");
	if (rc < 0) {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
		goto done;
	}

	if (icsf_ber_put_attribute_list(msg, attrs, attrs_len) < 0) {
		TRACE_ERROR("icsf_ber_put_attribute_list failed\n");
		goto done;
	}

	if (ber_printf(msg, "}") < 0) {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
		goto done;
	}

	tag = 0 | LBER_CLASS_CONTEXT | LBER_CONSTRUCTED;
	bv_client_random_data.bv_len = params->RandomInfo.ulClientRandomLen;
	bv_client_random_data.bv_val = params->RandomInfo.pClientRandom;
	bv_server_random_data.bv_len = params->RandomInfo.ulServerRandomLen;
	bv_server_random_data.bv_val = params->RandomInfo.pServerRandom;

	rc = ber_printf(msg, "t{biiiOO}", tag,
			(ber_int_t) params->bIsExport,
			(ber_int_t) params->ulMacSizeInBits,
			(ber_int_t) params->ulKeySizeInBits,
			(ber_int_t) params->ulIVSizeInBits,
			&bv_client_random_data, &bv_server_random_data);
	if (rc < 0) {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
		goto done;
	}

	/* Call request */
	rc = icsf_call(ld, p_reason, handle, sizeof(handle), rule_array,
			sizeof(rule_array), ICSF_TAG_CSFPDMK, msg, &result);
	if (ICSF_RC_IS_ERROR(rc))
		goto done;

	/*
	 *  DMKOutput ::= SEQUENCE {
	 *     parmsListChoice     DMKOutputParmsList
	 *  }
	 *
	 *  DMKOutputParmsList ::= CHOICE {
	 *     SSL-KM_TLS-KM   [0] SSL_TLS_DMKOutputParmsList
	 *  }
	 *
	 *  SSL_TLS_DMKOutputParmsList ::= SEQUENCE {
	 *     clientMACHandle     OCTET STRING,
	 *     clientMACHandle     OCTET STRING,
	 *     clientKeyHandle     OCTET STRING,
	 *     serverKeyHandle     OCTET STRING,
	 *     clientIV            OCTET STRING,
	 *     serverIV            OCTET STRING
	 *  }
	 */

	/*
	 * Since we are copying the values after all, "m" has the advantage of
	 * not needing to free the returned values...
	 */
	if (ber_scanf(result, "{t{mmmmmm}}", &tag, &bv_client_mac_handle,
			&bv_server_mac_handle, &bv_client_key_handle,
			&bv_server_key_handle, &bv_client_iv,
			&bv_server_iv) < 0) {
		rc = -1;
		TRACE_ERROR("Failed to decode the response.\n");
		goto done;
	}

	/* Copy key handles */
	if (bv_client_mac_handle.bv_len != ICSF_HANDLE_LEN ||
			bv_server_mac_handle.bv_len != ICSF_HANDLE_LEN ||
			bv_client_key_handle.bv_len != ICSF_HANDLE_LEN ||
			bv_server_key_handle.bv_len != ICSF_HANDLE_LEN) {
		TRACE_ERROR("Invalid key handle size: %lu/%lu/%lu/%lu\n",
			    (unsigned long) bv_client_mac_handle.bv_len,
			    (unsigned long) bv_server_mac_handle.bv_len,
			    (unsigned long) bv_client_key_handle.bv_len,
			    (unsigned long) bv_server_key_handle.bv_len);
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}
	handle_to_object_record(client_mac_handle, bv_client_mac_handle.bv_val);
	handle_to_object_record(server_mac_handle, bv_server_mac_handle.bv_val);
	handle_to_object_record(client_key_handle, bv_client_key_handle.bv_val);
	handle_to_object_record(server_key_handle, bv_server_key_handle.bv_val);

	/* Copy IVs */
	if (params->ulIVSizeInBits) {
		if (8 * bv_client_iv.bv_len != params->ulIVSizeInBits) {
			TRACE_ERROR("Invalid client IV size: %lu\n",
				    (unsigned long) bv_client_iv.bv_len);
			rc = CKR_FUNCTION_FAILED;
			goto done;
		}
		memcpy(params->pReturnedKeyMaterial->pIVClient,
			bv_client_iv.bv_val, bv_client_iv.bv_len);

		if (8 * bv_server_iv.bv_len != params->ulIVSizeInBits) {
			TRACE_ERROR("Invalid server IV size: %lu\n",
				    (unsigned long) bv_server_iv.bv_len);
			rc = CKR_FUNCTION_FAILED;
			goto done;
		}
		memcpy(params->pReturnedKeyMaterial->pIVServer,
			bv_server_iv.bv_val, bv_server_iv.bv_len);
	}

done:
	if (result)
		ber_free(result, 1);
	if (msg)
		ber_free(msg, 1);
	return rc;
}
