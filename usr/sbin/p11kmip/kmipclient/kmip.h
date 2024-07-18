/*
 * COPYRIGHT (c) International Business Machines Corp. 2021-2024
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */
#ifndef KMIP_H
#define KMIP_H

#include <stdint.h>
#include <stdbool.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>

#ifdef HAVE_LIBCURL
#ifdef HAVE_LIBJSONC
#include <json-c/json.h>
#endif
#ifdef HAVE_LIBXML2
#include <libxml/parser.h>
#include <libxml/tree.h>
#endif
#include <curl/curl.h>
#endif

#include "kmipclient.h"

/* KMIP Connection related structures */
#define KMIP_DEFAULT_PROTOCOL_VERSION_MAJOR	1
#define KMIP_DEFAULT_PROTOCOL_VERSION_MINOR	0

struct kmip_connection {
	struct kmip_conn_config config;
	union {
		struct {
			SSL_CTX *ssl_ctx;
			SSL *ssl;
			BIO *bio;
		} plain_tls;
#ifdef HAVE_LIBCURL
		struct {
			CURL **curl;
			struct curl_slist *headers;
		} https;
#endif
	} u;
};

#define plain_tls   u.plain_tls
#ifdef HAVE_LIBCURL
#define https       u.https
#endif

/* KMIP node related structures */
struct kmip_node {
	enum kmip_tag tag;
	enum kmip_type type;
	unsigned int length;
	char *name; /* optional, only used for JSON and XML encoding */
	union {
		struct kmip_node *structure_value;
		int32_t integer_value;
		int64_t long_value;
		BIGNUM *big_integer_value;
		uint32_t enumeration_value;
		bool boolean_value;
		char *text_value;
		unsigned char *bytes_value;
		int64_t date_time_value;
		uint32_t interval_value;
		int64_t date_time_ext_value;
	} u;
	struct kmip_node *parent;
	struct kmip_node *next;
	volatile unsigned long ref_count;
};

#define structure_value         u.structure_value
#define integer_value           u.integer_value
#define long_value              u.long_value
#define big_integer_value       u.big_integer_value
#define enumeration_value       u.enumeration_value
#define boolean_value           u.boolean_value
#define text_value              u.text_value
#define bytes_value             u.bytes_value
#define date_time_value         u.date_time_value
#define interval_value          u.interval_value
#define date_time_ext_value     u.date_time_ext_value


/* Attribute related internal functions */
int kmip_v2_attr_from_v1_attr(struct kmip_node *v1_attr,
			      struct kmip_node **v2_attr);
int kmip_v1_attr_from_v2_attr(struct kmip_node *v2_attr,
			      struct kmip_node **v1_attr);

char *kmip_build_v1_custom_attr_name(const char *vendor_id,
				     const char *attr_name);

struct kmip_node *kmip_new_attribute_name_v1(
					const struct kmip_node *v2_attr_ref);
int kmip_get_attribute_name_v1(const struct kmip_node *node,
			       struct kmip_node **v2_attr_ref);

/* Connection related internal functions */
int kmip_connection_tls_init(struct kmip_connection *connection, bool debug);
int kmip_connection_tls_perform(struct kmip_connection *connection,
				struct kmip_node *request,
				struct kmip_node **response,
				bool debug);
void kmip_connection_tls_term(struct kmip_connection *connection);

#ifdef HAVE_LIBCURL
int kmip_connection_https_init(struct kmip_connection *connection, bool debug);
int kmip_connection_https_perform(struct kmip_connection *connection,
				  struct kmip_node *request,
				  struct kmip_node **response,
				  bool debug);
void kmip_connection_https_term(struct kmip_connection *connection);
#endif

/* KIMP decoding and encoding internal functions */
int kmip_decode_ttlv(BIO *bio, size_t *size, struct kmip_node **node,
		     bool debug);
int kmip_encode_ttlv(struct kmip_node *node, BIO *bio, size_t *size,
		     bool debug);

#ifdef HAVE_LIBCURL
#ifdef HAVE_LIBJSONC
int kmip_decode_json(const json_object *obj, struct kmip_node *parent,
		     struct kmip_node **node, bool debug);
int kmip_encode_json(const struct kmip_node *node, json_object **obj,
		     bool debug);
#endif

#ifdef HAVE_LIBXML2
int kmip_decode_xml(const xmlNode *xml, struct kmip_node *parent,
		    struct kmip_node **node, bool debug);
int kmip_encode_xml(const struct kmip_node *node, xmlNode **xml, bool debug);
#endif
#endif

#endif
