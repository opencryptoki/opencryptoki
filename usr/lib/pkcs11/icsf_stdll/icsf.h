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
#include <lber.h>
#include "pkcs11types.h"

/* OIDs used for PKCS extension */
#define ICSF_REQ_OID "1.3.18.0.2.12.83"
#define ICSF_RES_OID "1.3.18.0.2.12.84"

/*
 * Tag numbers for each ICSF call.
 *
 * ICSF message is composed by some fields that are common to all services and
 * a service-specific field. The tag number of this field identifies the
 * service that is called.
 */
#define ICSF_TAG_CSFPGAV 3
#define ICSF_TAG_CSFPGSK 5
#define ICSF_TAG_CSFPSAV 11
#define ICSF_TAG_CSFPSKD 12
#define ICSF_TAG_CSFPSKE 13
#define ICSF_TAG_CSFPTRC 14
#define ICSF_TAG_CSFPTRD 15
#define ICSF_TAG_CSFPTRL 16

/* Return codes */
#define ICSF_RC_SUCCESS 0
#define ICSF_RC_PARTIAL_SUCCESS 4
#define ICSF_RC_IS_ERROR(rc) \
	(rc > ICSF_RC_PARTIAL_SUCCESS)

/* Default lengths */
#define ICSF_HANDLE_LEN 44
#define ICSF_TOKEN_RECORD_LEN 116
#define ICSF_TOKEN_NAME_LEN 32
#define ICSF_SEQUENCE_LEN 8
#define ICSF_MANUFACTURER_LEN 32
#define ICSF_MODEL_LEN 16
#define ICSF_SERIAL_LEN 16
#define ICSF_DATE_LEN 8
#define ICSF_TIME_LEN 8
#define ICSF_FLAGS_LEN 4
#define ICSF_RULE_ITEM_LEN 8

#define MAX_RECORDS 10

/* Object types */
#define ICSF_SESSION_OBJECT 'S'
#define ICSF_TOKEN_OBJECT 'T'
#define ICSF_IS_VALID_OBJECT_TYPE(_type) \
	(_type == ICSF_SESSION_OBJECT || \
	 _type == ICSF_TOKEN_OBJECT)

/* Chaining types */
#define ICSF_CHAINING_INITIAL 1
#define ICSF_CHAINING_CONTINUE 2
#define ICSF_CHAINING_FINAL 3
#define ICSF_CHAINING_ONLY 4

#define ICSF_CHAINING_IS_VALID(_type) \
	(((_type) == ICSF_CHAINING_INITIAL) || \
	 ((_type) == ICSF_CHAINING_CONTINUE) || \
	 ((_type) == ICSF_CHAINING_FINAL) || \
	 ((_type) == ICSF_CHAINING_ONLY))

#define ICSF_CHAINING(_type) \
	(((_type) == ICSF_CHAINING_INITIAL) ? "INITIAL" : \
	 ((_type) == ICSF_CHAINING_CONTINUE) ? "CONTINUE" : \
	 ((_type) == ICSF_CHAINING_FINAL) ? "FINAL" : \
	 ((_type) == ICSF_CHAINING_ONLY) ? "ONLY" : \
	 NULL)

#define ICSF_CHAINING_DATA_LEN (128)

/* Macros for testing flags. */
#define ICSF_IS_TOKEN_READ_ONLY(_flags) \
	(_flags[0] & (1 << 7))

struct icsf_token_record {
	char name[ICSF_TOKEN_NAME_LEN + 1];
	char manufacturer[ICSF_MANUFACTURER_LEN + 1];
	char model[ICSF_MODEL_LEN + 1];
	char serial[ICSF_SERIAL_LEN + 1];
	char date[ICSF_DATE_LEN + 1];
	char time[ICSF_TIME_LEN + 1];
	char flags[ICSF_FLAGS_LEN];
};

struct icsf_object_record {
	char token_name[ICSF_TOKEN_NAME_LEN + 1];
	unsigned long sequence;
	char id;
};

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

int
icsf_create_token(LDAP *ld, int *reason, const char *token_name,
	          const char *manufacturer_id, const char *model,
	          const char *serial_number);

int
icsf_destroy_token(LDAP *ld, int *reason, char *token_name);

int
icsf_list_tokens(LDAP *ld, int *reason, struct icsf_token_record *first,
	         struct icsf_token_record *records, size_t *records_len);

int
icsf_create_object(LDAP *ld, int *reason, const char *token_name,
	           CK_ATTRIBUTE *attrs, CK_ULONG attrs_len,
		   struct icsf_object_record *object);

int
icsf_list_objects(LDAP *ld, int *reason, const char *token_name,
		  CK_ULONG attrs_len, CK_ATTRIBUTE *attrs,
	          struct icsf_object_record *previous,
	          struct icsf_object_record *records, size_t *records_len,
	          int all);

int
icsf_destroy_object(LDAP *ld, int *reason, struct icsf_object_record *obj);

int
icsf_generate_secret_key(LDAP *ld, int *reason, const char *token_name,
			CK_MECHANISM_PTR mech,
			CK_ATTRIBUTE *attrs, CK_ULONG attrs_len,
			struct icsf_object_record *object);

int
icsf_get_attribute(LDAP *ld, int *reason, struct icsf_object_record *object,
                   CK_ATTRIBUTE *attrs, CK_ULONG attrs_len);

int
icsf_set_attribute(LDAP *ld, int *reason, struct icsf_object_record *object,
                   CK_ATTRIBUTE *attrs, CK_ULONG attrs_len);

int
icsf_secret_key_encrypt(LDAP *ld, int *reason, struct icsf_object_record *key,
			CK_MECHANISM_PTR mech, int chaining,
			const char *clear_text, size_t clear_text_len,
			char *cipher_text, size_t *p_cipher_text_len,
			char *chaining_data, size_t *p_chaining_data_len);

int
icsf_secret_key_decrypt(LDAP *ld, int *reason, struct icsf_object_record *key,
			CK_MECHANISM_PTR mech, int chaining,
			const char *cipher_text, size_t cipher_text_len,
			char *clear_text, size_t *p_clear_text_len,
			char *chaining_data, size_t *p_chaining_data_len);
#endif
