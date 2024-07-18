/*
 * COPYRIGHT (c) International Business Machines Corp. 2021-2024
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <errno.h>
#include <string.h>
#include <sys/stat.h>

#ifdef HAVE_LIBCURL

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "kmip.h"
#include "utils.h"

#ifdef UNUSED
#elif defined(__GNUC__)
# define UNUSED(x) UNUSED_ ## x __attribute__((unused))
#else
# define UNUSED(x) x
#endif

#define HTTP_HDR_CONTENT_TYPE	"Content-Type:"

#define CURL_ERROR_CHECK(rc, text, debug, label)			\
		do {							\
			if ((rc) != CURLE_OK) {				\
				kmip_debug((debug), "%s: %s", (text),	\
					   curl_easy_strerror((rc)));	\
				goto label;				\
			}						\
		} while (0)

struct curl_sslctx_cb_data {
	const struct kmip_connection *conn;
	bool debug;
};

struct curl_write_cb_data {
	const struct kmip_connection *conn;
	bool error;
	bool debug;
	union {
#ifdef HAVE_LIBJSONC
		struct {
			json_tokener *tok;
			json_object *resp_obj;
		} json;
#endif
#ifdef HAVE_LIBXML2
		struct {
			xmlParserCtxtPtr ctx;
		} xml;
#endif
		struct {
			BIO *resp_mem_bio;
		} ttlv;
	} u;
};

#ifdef HAVE_LIBJSONC
#define json        u.json
#endif
#ifdef HAVE_LIBXML2
#define xml         u.xml
#endif
#define ttlv        u.ttlv

struct curl_header_cb_data {
	const struct kmip_connection *conn;
	bool error;
	bool debug;
};

/**
 * Initializes a new HTTPS connection to a KMIP server.
 *
 * @param connn             The KMIP connection
 * @param debug             if true, debug messages are printed
 *
 * @returns 0 in case of success, or a negative errno value
 */
int kmip_connection_https_init(struct kmip_connection *conn, bool debug)
{
	const char *content_type, *accept, *server, *tok;
	const struct curl_tlssessioninfo *info = NULL;
	bool port_found = false;
	struct stat sb;
	int rc;

	if (conn == NULL)
		return -EINVAL;

	if (strncmp(conn->config.server, "https://", 8) != 0) {
		kmip_debug(debug, "Server must start with 'https://'");
		return -EINVAL;
	}

	/* Find port (if any) and beginning of uri */
	server = conn->config.server + 8;
	if (*server == '[') {
		/* IPv6 address enclosed in square brackets */
		tok = strchr(server, ']');
		if (tok == NULL) {
			kmip_debug(debug, "malformed IPv6 address");
			return -EINVAL;
		}
		tok++;
		port_found = (*tok == ':');
	} else {
		/* hostname or IPv4 address */
		tok = strchr(server, ':');
		port_found = (tok != NULL);
	}

	conn->https.curl = curl_easy_init();
	if (conn->https.curl == NULL) {
		kmip_debug(debug, "curl_easy_init failed");
		return -EIO;
	}

	/*
	 * The CURLOPT_SSL_CTX_FUNCTION callback only works with the OpenSSL
	 * curl backend. Check that OpenSSL is the current curl backend.
	 */
	rc = curl_easy_getinfo(conn->https.curl, CURLINFO_TLS_SSL_PTR, &info);
	CURL_ERROR_CHECK(rc, "curl_easy_getinfo CURLINFO_TLS_SSL_PTR", debug,
			 out);
	if (info->backend != CURLSSLBACKEND_OPENSSL) {
		kmip_debug(debug, "libcurl is not using the OpenSSL backend");
		rc = -EIO;
		goto out;
	}

	rc = curl_easy_setopt(conn->https.curl, CURLOPT_VERBOSE, debug ? 1 : 0);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_VERBOSE", debug, out);

	rc = curl_easy_setopt(conn->https.curl, CURLOPT_URL,
			      conn->config.server);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_URL", debug, out);

	if (!port_found) {
		rc = curl_easy_setopt(conn->https.curl, CURLOPT_PORT,
				      KMIP_DEFAULT_HTTPS_PORT_NUM);
		CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_URL", debug,
				 out);
	}

	rc = curl_easy_setopt(conn->https.curl, CURLOPT_SSL_VERIFYPEER,
			 conn->config.tls_verify_peer ? 1L : 0L);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_SSL_VERIFYPEER", debug,
			 out);
	rc = curl_easy_setopt(conn->https.curl, CURLOPT_SSL_VERIFYHOST,
			 conn->config.tls_verify_host ? 2L : 0L);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_SSL_VERIFYHOST", debug,
			 out);

	if (conn->config.tls_ca != NULL) {
		if (stat(conn->config.tls_ca, &sb) != 0) {
			rc = -errno;
			kmip_debug(debug, "stat failed on '%s': %s",
					conn->config.tls_ca, strerror(-rc));
			goto out;
		}

		if (S_ISDIR(sb.st_mode)) {
			rc = curl_easy_setopt(conn->https.curl, CURLOPT_CAPATH,
					      conn->config.tls_ca);
			CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_CAPATH",
					 debug, out);
		} else {
			rc = curl_easy_setopt(conn->https.curl, CURLOPT_CAINFO,
					      conn->config.tls_ca);
			CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_CAINFO",
					 debug, out);
		}
	}

	if (conn->config.tls_issuer_cert != NULL) {
		rc = curl_easy_setopt(conn->https.curl, CURLOPT_ISSUERCERT,
				      conn->config.tls_issuer_cert);
		CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_ISSUERCERT",
				 debug, out);
	}

	if (conn->config.tls_pinned_pubkey != NULL) {
		rc = curl_easy_setopt(conn->https.curl, CURLOPT_PINNEDPUBLICKEY,
				      conn->config.tls_pinned_pubkey);
		CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_PINNEDPUBLICKEY",
				 debug, out);
	}

	rc = curl_easy_setopt(conn->https.curl, CURLOPT_FOLLOWLOCATION, 0L);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_FOLLOWLOCATION",
			 debug, out);

	if (conn->config.tls_cipher_list != NULL) {
		rc = curl_easy_setopt(conn->https.curl, CURLOPT_SSL_CIPHER_LIST,
				      conn->config.tls_cipher_list);
		CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_SSL_CIPHER_LIST",
				 debug, out);
	}

	if (conn->config.tls13_cipher_list != NULL) {
		rc = curl_easy_setopt(conn->https.curl, CURLOPT_TLS13_CIPHERS,
				      conn->config.tls13_cipher_list);
		CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_TLS13_CIPHERS",
				 debug, out);
	}

	switch (conn->config.encoding) {
	case KMIP_ENCODING_TTLV:
		content_type = "Content-Type: application/octet-stream";
		accept = "Accept: application/octet-stream";
		break;
#ifdef HAVE_LIBJSONC
	case KMIP_ENCODING_JSON:
		content_type = "Content-Type: application/json;charset=UTF-8";
		accept = "Accept: application/json";
		break;
#endif
#ifdef HAVE_LIBXML2
	case KMIP_ENCODING_XML:
		content_type = "Content-Type: text/xml;charset=UTF-8";
		accept = "Accept: text/xml";
		break;
#endif
	default:
		kmip_debug(debug, "invalid encoding: %d",
			   conn->config.encoding);
		rc = -EINVAL;
		goto out;
	}

	conn->https.headers = curl_slist_append(conn->https.headers,
						content_type);
	if (conn->https.headers == NULL) {
		kmip_debug(debug, "curl_slist_append failed");
		rc = -ENOMEM;
		goto out;
	}

	conn->https.headers = curl_slist_append(conn->https.headers, accept);
	if (conn->https.headers == NULL) {
		kmip_debug(debug, "curl_slist_append failed");
		rc = -ENOMEM;
		goto out;
	}

	conn->https.headers = curl_slist_append(conn->https.headers,
						"Accept-Charset: UTF-8");
	if (conn->https.headers == NULL) {
		kmip_debug(debug, "curl_slist_append failed");
		rc = -ENOMEM;
		goto out;
	}

	/* Disable "Expect: 100-continue" */
	conn->https.headers = curl_slist_append(conn->https.headers, "Expect:");
	if (conn->https.headers == NULL) {
		kmip_debug(debug, "curl_slist_append failed");
		rc = -ENOMEM;
		goto out;
	}

	/* As per KMIP HTTPS profile: Cache-Control: no-cache */
	conn->https.headers = curl_slist_append(conn->https.headers,
						"Cache-Control: no-cache");
	if (conn->https.headers == NULL) {
		kmip_debug(debug, "curl_slist_append failed");
		rc = -ENOMEM;
		goto out;
	}

	rc = curl_easy_setopt(conn->https.curl, CURLOPT_HTTPHEADER,
			      conn->https.headers);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_HTTPHEADER", debug,
			 out);

	rc = 0;

out:
	if (rc != 0)
		kmip_connection_https_term(conn);

	return rc;
}

/**
 * This callback called before the SSL handshake is performed.
 * It sets the client certificate and private key into the context.
 * It also adds a pinned server certificate to the SSL certificate store, so
 * that it is treated as trusted, although it might be self-signed.
 */
static CURLcode mkip_connection_https_sslctx_cb(CURL *UNUSED(curl),
						void *sslctx, void *parm)
{
	struct curl_sslctx_cb_data *sslctx_cb = parm;
	SSL_CTX *ssl_ctx = (SSL_CTX *)sslctx;
	const struct kmip_connection *conn;
	X509_STORE *store;
	X509 *cert = NULL;
	FILE *fp;
	int rc;

	if (ssl_ctx == NULL || sslctx_cb == NULL || sslctx_cb->conn == NULL)
		return CURLE_ABORTED_BY_CALLBACK;

	conn = sslctx_cb->conn;

	if (SSL_CTX_use_certificate_file(sslctx, conn->config.tls_client_cert,
					 SSL_FILETYPE_PEM) != 1) {
		kmip_debug(sslctx_cb->debug, "Failed to load the client "
			   "certificate '%s'", conn->config.tls_client_cert);
		if (sslctx_cb->debug)
			ERR_print_errors_fp(stderr);
		return CURLE_ABORTED_BY_CALLBACK;
	}

	if (SSL_CTX_use_PrivateKey(ssl_ctx, conn->config.tls_client_key) != 1) {
		kmip_debug(sslctx_cb->debug, "Failed to set the client key");
		if (sslctx_cb->debug)
			ERR_print_errors_fp(stderr);
		return CURLE_ABORTED_BY_CALLBACK;
	}

	if (conn->config.tls_server_cert == NULL)
		return CURLE_OK;

	store = SSL_CTX_get_cert_store(ssl_ctx);
	if (store == NULL) {
		kmip_debug(sslctx_cb->debug, "Failed to get SSL Store");
		if (sslctx_cb->debug)
			ERR_print_errors_fp(stderr);
		return CURLE_ABORTED_BY_CALLBACK;
	}

	fp = fopen(conn->config.tls_server_cert, "r");
	if (fp == NULL) {
		rc = -errno;
		kmip_debug(sslctx_cb->debug,
			   "Failed to read server cert '%s': %s",
			   conn->config.tls_server_cert, strerror(-rc));
		return CURLE_ABORTED_BY_CALLBACK;
	}

	cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);

	if (cert == NULL) {
		kmip_debug(sslctx_cb->debug, "Failed to read the server "
			   "certificate from file '%s'",
			   conn->config.tls_server_cert);
		if (sslctx_cb->debug)
			ERR_print_errors_fp(stderr);
		return CURLE_ABORTED_BY_CALLBACK;
	}

	if (sslctx_cb->debug) {
		kmip_debug(sslctx_cb->debug, "Pinned server certificate:");
		X509_print_ex_fp(stderr, cert, XN_FLAG_COMPAT,
				 X509_FLAG_COMPAT);
	}

	rc = X509_STORE_add_cert(store, cert);
	if (rc != 1) {
		kmip_debug(sslctx_cb->debug, "Failed to add server "
			   "certificate to SSL Store");
		if (sslctx_cb->debug)
			ERR_print_errors_fp(stderr);
		X509_free(cert);
		return CURLE_ABORTED_BY_CALLBACK;
	}

	X509_free(cert);
	return CURLE_OK;
}

/**
 * Callback called during curl_easy_perform() to handle received headers.
 * Check for the expected response content type.
 */
static size_t mkip_connection_https_header_cb(void *contents, size_t size,
					     size_t nmemb, void *userp)
{
	struct curl_header_cb_data *cb = (struct curl_header_cb_data *)userp;
	size_t num = size * nmemb;
	const char *content_type;
	char *hdr = contents;
	size_t ofs;
	char *val;

	if (num < strlen(HTTP_HDR_CONTENT_TYPE))
		goto out;

	if (strncasecmp(hdr, HTTP_HDR_CONTENT_TYPE,
			strlen(HTTP_HDR_CONTENT_TYPE)) != 0)
		goto out;

	ofs = strlen(HTTP_HDR_CONTENT_TYPE);
	val = hdr + ofs;
	while (*val == ' ' && ofs < num) {
		ofs++;
		val++;
	}
	if (ofs >= num)
		goto out;

	switch (cb->conn->config.encoding) {
	case KMIP_ENCODING_TTLV:
		content_type = "application/octet-stream";
		break;
#ifdef HAVE_LIBJSONC
	case KMIP_ENCODING_JSON:
		content_type = "application/json";
		break;
#endif
#ifdef HAVE_LIBXML2
	case KMIP_ENCODING_XML:
		content_type = "text/xml";
		break;
#endif
	default:
		return 0;
	}

	if (num - ofs >= strlen(content_type) &&
	    strncasecmp(val, content_type, strlen(content_type)) == 0)
		goto out;

	cb->error = true;
	kmip_debug(cb->debug, "Unexpected response Content-Type: %.*s",
		   (int)(num - ofs), val);
	return 0;

out:
	return num;
}



/**
 * Callback called during curl_easy_perform() to handle received data.
 * Parse the (potentially partial) KMIP data.
 */
static size_t mkip_connection_https_write_cb(void *contents, size_t size,
					      size_t nmemb, void *userp)
{
	struct curl_write_cb_data *cb = (struct curl_write_cb_data *)userp;
#ifdef HAVE_LIBJSONC
	enum json_tokener_error jerr;
#endif
	size_t num = size * nmemb;
#ifdef HAVE_LIBXML2
	int rc;
#endif

	switch (cb->conn->config.encoding) {
	case KMIP_ENCODING_TTLV:
		kmip_debug(cb->debug, "Response Data (TTLV): %lu bytes", num);
		if (cb->debug)
			kmip_print_dump(__func__, (unsigned char *)contents,
					num, 2);

		if (BIO_write(cb->ttlv.resp_mem_bio, contents, num) !=
								(int)num) {
			cb->error = true;
			kmip_debug(cb->debug, "BIO_write failed");
			return 0;
		}
		break;

#ifdef HAVE_LIBJSONC
	case KMIP_ENCODING_JSON:
		kmip_debug(cb->debug, "Response Data (JSON):");
		kmip_debug(cb->debug, "  ->%*s<-", (int)num, (char *)contents);

		if (cb->json.resp_obj != NULL) {
			kmip_debug(cb->debug, "JSON data already complete, but "
				   "additional data received");
			cb->error = true;
			return 0;
		}

		cb->json.resp_obj = json_tokener_parse_ex(cb->json.tok,
						(const char *)contents, num);

		if (cb->json.resp_obj == NULL) {
			jerr = json_tokener_get_error(cb->json.tok);
			if (jerr == json_tokener_continue)
				goto out;

			cb->error = true;
			kmip_debug(cb->debug, "json_tokener_parse_ex failed: %s",
				   json_tokener_error_desc(jerr));
			return 0;
		}

		break;
#endif
#ifdef HAVE_LIBXML2
	case KMIP_ENCODING_XML:
		kmip_debug(cb->debug, "Response Data (XML):");
		kmip_debug(cb->debug, "  ->%*s<-", (int)num, (char *)contents);

		rc = xmlParseChunk(cb->xml.ctx, (const char *)contents, num, 0);
		if (rc != XML_ERR_OK) {
			cb->error = true;
			kmip_debug(cb->debug, "xmlParseChunk failed: %d", rc);
			return 0;
		}
		break;
#endif
	}

#ifdef HAVE_LIBJSONC
out:
#endif
	return num;
}


/**
 * Perform a request over the KMIP connection
 *
 * @param conn              the KMIP connection
 * @param request           the request to send
 * @param response          On return: the received response. Must be freed by
 *                          the caller.
 *
 * @param debug             if true, debug messages are printed
 *
 * @returns 0 in case of success, or a negative errno value
 */
int kmip_connection_https_perform(struct kmip_connection *conn,
				  struct kmip_node *request,
				  struct kmip_node **response,
				  bool debug)
{
	struct curl_sslctx_cb_data sslctx_cb = { 0 };
	struct curl_header_cb_data header_cb = { 0 };
	struct curl_write_cb_data write_cb = { 0 };
	char error_str[CURL_ERROR_SIZE] = { 0 };
#ifdef HAVE_LIBJSONC
	json_object *req_json_obj = NULL;
#endif
#ifdef HAVE_LIBXML2
	xmlNode *req_xml_obj = NULL;
	xmlDoc *req_xml_doc = NULL;
#endif
	BIO *req_mem_bio = NULL;
	char *req_buff = NULL;
	int req_buff_size = 0;
	long status_code;
	size_t size;
	int rc;

	if (conn == NULL || request == NULL || response == NULL)
		return -EINVAL;

	*response = NULL;

	rc = curl_easy_setopt(conn->https.curl, CURLOPT_ERRORBUFFER,
			      error_str);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_ERRORBUFFER", debug,
			 out);

	/* Setup SSL Context callback */
	sslctx_cb.conn = conn;
	sslctx_cb.debug = debug;

	rc = curl_easy_setopt(conn->https.curl, CURLOPT_SSL_CTX_FUNCTION,
			      mkip_connection_https_sslctx_cb);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt "
			 "CURLOPT_SSL_CTX_FUNCTION", debug, out);
	rc = curl_easy_setopt(conn->https.curl, CURLOPT_SSL_CTX_DATA,
			      &sslctx_cb);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_SSL_CTX_DATA",
			 debug, out);

	/* Setup write callback to handle received data */
	write_cb.conn = conn;
	write_cb.debug = debug;

	switch (conn->config.encoding) {
	case KMIP_ENCODING_TTLV:
		write_cb.ttlv.resp_mem_bio = BIO_new(BIO_s_mem());
		if (write_cb.ttlv.resp_mem_bio == NULL) {
			kmip_debug(debug, "BIO_new failed");
			rc = -ENOMEM;
			goto out;
		}
		break;

#ifdef HAVE_LIBJSONC
	case KMIP_ENCODING_JSON:
		write_cb.json.tok = json_tokener_new();
		if (write_cb.json.tok == NULL) {
			kmip_debug(debug, "json_tokener_new failed");
			rc = -EIO;
			goto out;
		}
		break;
#endif
#ifdef HAVE_LIBXML2
	case KMIP_ENCODING_XML:
		write_cb.xml.ctx = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0,
							   NULL);
		if (write_cb.xml.ctx == NULL) {
			kmip_debug(debug, "xmlCreatePushParserCtxt failed");
			rc = -EIO;
			goto out;
		}
		break;
#endif
	}

	rc = curl_easy_setopt(conn->https.curl, CURLOPT_WRITEFUNCTION,
			      mkip_connection_https_write_cb);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_WRITEFUNCTION", debug,
			 out);
	rc = curl_easy_setopt(conn->https.curl, CURLOPT_WRITEDATA,
			      (void *)&write_cb);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_WRITEDATA", debug,
			 out);

	/* Setup header callback to check content type */
	header_cb.conn = conn;
	header_cb.debug = debug;

	rc = curl_easy_setopt(conn->https.curl, CURLOPT_HEADERFUNCTION,
			      mkip_connection_https_header_cb);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_HEADERFUNCTION", debug,
			 out);
	rc = curl_easy_setopt(conn->https.curl, CURLOPT_HEADERDATA,
			      (void *)&header_cb);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_HEADERDATA", debug,
			 out);

	/* Setup POST request and post data */
	rc = curl_easy_setopt(conn->https.curl, CURLOPT_CUSTOMREQUEST, "POST");
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_CUSTOMREQUEST",
			 debug, out);

	rc = curl_easy_setopt(conn->https.curl, CURLOPT_POST, 1L);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_POST",
			  debug, out);

	switch (conn->config.encoding) {
	case KMIP_ENCODING_TTLV:
		req_mem_bio = BIO_new(BIO_s_mem());
		if (req_mem_bio == NULL) {
			kmip_debug(debug, "BIO_new failed");
			rc = -ENOMEM;
			goto out;
		}

		rc = kmip_encode_ttlv(request, req_mem_bio, &size, debug);
		if (rc != 0) {
			kmip_debug(debug, "kmip_encode_ttlv failed");
			goto out;
		}

		req_buff_size = BIO_get_mem_data(req_mem_bio, &req_buff);

		kmip_debug(debug, "Request Data (TTLV): %d bytes",
			   req_buff_size);
		if (debug)
			kmip_print_dump(__func__, (unsigned char *)req_buff,
					req_buff_size, 2);
		break;

#ifdef HAVE_LIBJSONC
	case KMIP_ENCODING_JSON:
		rc = kmip_encode_json(request, &req_json_obj, debug);
		if (rc != 0) {
			kmip_debug(debug, "kmip_encode_json failed");
			goto out;
		}

		/*
		 * The memory returned by json_object_to_json_string_ext
		 * is freed when the JSON object is freed.
		 */
		req_buff = (char *)json_object_to_json_string_ext(req_json_obj,
					JSON_C_TO_STRING_PLAIN |
					JSON_C_TO_STRING_NOSLASHESCAPE);
		if (req_buff == NULL) {
			kmip_debug(debug,
				   "json_object_to_json_string_ext failed");
			rc = -EIO;
			goto out;
		}
		req_buff_size = strlen(req_buff);

		kmip_debug(debug, "Request Data (JSON):");
		kmip_debug(debug, "  ->%*s<-", req_buff_size,
			   req_buff);
		break;
#endif
#ifdef HAVE_LIBXML2
	case KMIP_ENCODING_XML:
		req_xml_doc = xmlNewDoc((xmlChar *)"1.0");
		if (req_xml_doc == NULL) {
			kmip_debug(debug, "xmlNewDoc failed");
			rc = -EIO;
			goto out;
		}

		rc = kmip_encode_xml(request, &req_xml_obj, debug);
		if (rc != 0) {
			kmip_debug(debug, "kmip_encode_xml failed");
			goto out;
		}

		xmlDocSetRootElement(req_xml_doc, req_xml_obj);
		req_xml_obj = NULL;

		xmlDocDumpFormatMemoryEnc(req_xml_doc, (xmlChar **)&req_buff,
					  &req_buff_size, "UTF-8", 0);
		if (req_buff == NULL || req_buff_size == 0) {
			kmip_debug(debug, "xmlDocDumpFormatMemoryEnc failed");
			rc = -EIO;
			goto out;
		}

		kmip_debug(debug, "Request Data (XML):");
		kmip_debug(debug, "  ->%*s<-", req_buff_size,
			   req_buff);
		break;
#endif
	}

	rc = curl_easy_setopt(conn->https.curl, CURLOPT_POSTFIELDSIZE,
			      req_buff_size);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_POSTFIELDSIZE",
			 debug, out);
	rc = curl_easy_setopt(conn->https.curl, CURLOPT_POSTFIELDS,
			      req_buff);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_POSTFIELDS",
			 debug, out);

	/* Perform the request */
	rc = curl_easy_perform(conn->https.curl);
	if (rc != CURLE_OK) {
		kmip_debug(debug, "curl_easy_perform for '%s' failed: %s",
			   conn->config.server, curl_easy_strerror(rc));
		kmip_debug(debug, "Error: %s", error_str);

		if (header_cb.error) {
			kmip_debug(debug, "Unexpected Content-Type");
			rc = -EBADMSG;
		}
		if (write_cb.error) {
			kmip_debug(debug, "JSON/XML parsing failed");
			rc = -EBADMSG;
		}
		rc = -EIO;
		goto out;
	}

	/* Check response */
	rc = curl_easy_getinfo(conn->https.curl, CURLINFO_RESPONSE_CODE,
			       &status_code);
	CURL_ERROR_CHECK(rc, "curl_easy_getinfo CURLINFO_RESPONSE_CODE",
			 debug, out);
	kmip_debug(debug, "HTTP status code: %d", status_code);
	if (status_code != 200) {
		rc = -EBADMSG;
		goto out;
	}

	/* Process received data */
	switch (conn->config.encoding) {
	case KMIP_ENCODING_TTLV:
		rc = kmip_decode_ttlv(write_cb.ttlv.resp_mem_bio, NULL,
				      response, debug);
		if (rc != 0) {
			kmip_debug(debug, "kmip_decode_ttlv failed");
			goto out;
		}
		break;

#ifdef HAVE_LIBJSONC
	case KMIP_ENCODING_JSON:
		if (write_cb.json.resp_obj == NULL) {
			kmip_debug(debug, "JSON content not wellformed");
			rc = -EBADMSG;
			goto out;
		}

		rc = kmip_decode_json(write_cb.json.resp_obj, NULL, response,
				      debug);
		if (rc != 0) {
			kmip_debug(debug, "kmip_decode_json failed");
			goto out;
		}
		break;
#endif
#ifdef HAVE_LIBXML2
	case KMIP_ENCODING_XML:
		rc = xmlParseChunk(write_cb.xml.ctx, "", 0, 1);
		if (rc != XML_ERR_OK || !write_cb.xml.ctx->wellFormed ||
		    write_cb.xml.ctx->myDoc == NULL) {
			kmip_debug(debug, "XML content not wellformed");
			rc = -EBADMSG;
			goto out;
		}

		rc = kmip_decode_xml(xmlDocGetRootElement(
						write_cb.xml.ctx->myDoc),
				     NULL, response, debug);
		if (rc != 0) {
			kmip_debug(debug, "kmip_decode_xml failed");
			goto out;
		}
		break;
#endif
	}

	rc = 0;

out:
	/* Cleanup */
	switch (conn->config.encoding) {
	case KMIP_ENCODING_TTLV:
		if (req_mem_bio != NULL)
			BIO_free(req_mem_bio);
		if (write_cb.ttlv.resp_mem_bio != NULL)
			BIO_free(write_cb.ttlv.resp_mem_bio);

		break;
#ifdef HAVE_LIBJSONC
	case KMIP_ENCODING_JSON:
		if (write_cb.json.tok != NULL)
			json_tokener_free(write_cb.json.tok);
		if (write_cb.json.resp_obj != NULL)
			json_object_put(write_cb.json.resp_obj);
		if (req_json_obj != NULL)
			json_object_put(req_json_obj);
		break;
#endif
#ifdef HAVE_LIBXML2
	case KMIP_ENCODING_XML:
		if (write_cb.xml.ctx != NULL) {
			xmlFreeDoc(write_cb.xml.ctx->myDoc);
			xmlFreeParserCtxt(write_cb.xml.ctx);
		}
		if (req_xml_doc != NULL)
			xmlFreeDoc(req_xml_doc);
		if (req_xml_obj != NULL)
			xmlFreeNode(req_xml_obj);
		if (req_buff != NULL)
			xmlFree(req_buff);
		break;
#endif
	}

	if (rc != 0 && *response != NULL) {
		kmip_node_free(*response);
		*response = NULL;
	}

	curl_easy_setopt(conn->https.curl, CURLOPT_SSL_CTX_FUNCTION, NULL);
	curl_easy_setopt(conn->https.curl, CURLOPT_SSL_CTX_DATA, NULL);
	curl_easy_setopt(conn->https.curl, CURLOPT_WRITEFUNCTION, NULL);
	curl_easy_setopt(conn->https.curl, CURLOPT_WRITEDATA, NULL);
	curl_easy_setopt(conn->https.curl, CURLOPT_HEADERFUNCTION, NULL);
	curl_easy_setopt(conn->https.curl, CURLOPT_HEADERDATA, NULL);
	curl_easy_setopt(conn->https.curl, CURLOPT_ERRORBUFFER, NULL);
	curl_easy_setopt(conn->https.curl, CURLOPT_POSTFIELDS, NULL);
	curl_easy_setopt(conn->https.curl, CURLOPT_POSTFIELDSIZE, -1);

	return rc;
}

/**
 * Terminates a HTTPS KMIP connection.
 *
 * @param conn             the KMIP connection to free
 */
void kmip_connection_https_term(struct kmip_connection *conn)
{
	if (conn == NULL)
		return;

	if (conn->https.curl != NULL)
		curl_easy_cleanup(conn->https.curl);
	conn->https.curl = NULL;

	if (conn->https.headers != NULL)
		curl_slist_free_all(conn->https.headers);
	conn->https.headers = NULL;
}

#endif
