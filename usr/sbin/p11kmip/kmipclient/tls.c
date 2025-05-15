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

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/opensslv.h>

#include "kmip.h"
#include "utils.h"

#ifndef OPENSSL_VERSION_PREREQ
	#if defined(OPENSSL_VERSION_MAJOR) && defined(OPENSSL_VERSION_MINOR)
		#define OPENSSL_VERSION_PREREQ(maj, min)		\
			((OPENSSL_VERSION_MAJOR << 16) +		\
			OPENSSL_VERSION_MINOR >= ((maj) << 16) + (min))
	#else
		#define OPENSSL_VERSION_PREREQ(maj, min)		\
			(OPENSSL_VERSION_NUMBER >= (((maj) << 28) |	\
			((min) << 20)))
	#endif
#endif

/**
 * Verify the pinned public key of the server of a plain TLS KMIP connection
 *
 * @param conn              the KMIP connection to free
 * @param cert_pubkey       the server certificate's public key
 * @param debug             if true, debug messages are printed
 */
static int kmip_connection_tls_verify_pinned_pubkey(
					struct kmip_connection *conn,
					EVP_PKEY *cert_pubkey, bool debug)
{
	EVP_PKEY *pinned_key = NULL;
	int rc = 0;
	FILE *fp;

	fp = fopen(conn->config.tls_pinned_pubkey, "r");
	if (fp == NULL) {
		rc = -errno;
		kmip_debug(debug, "Failed to read pinned public key '%s': %s",
				conn->config.tls_pinned_pubkey, strerror(-rc));
		return rc;
	}

	pinned_key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
	fclose(fp);

	if (pinned_key == NULL) {
		kmip_debug(debug, "PEM_read_PUBKEY failed: '%s'",
			   conn->config.tls_pinned_pubkey);
		if (debug)
			ERR_print_errors_fp(stderr);
		return -EIO;
	}

#if !OPENSSL_VERSION_PREREQ(3, 0)
	if (EVP_PKEY_cmp(pinned_key, cert_pubkey) != 1) {
#else
	if (EVP_PKEY_eq(pinned_key, cert_pubkey) != 1) {
#endif
		kmip_debug(debug, "Server public key does not match the pinned "
			   "public key '%s'", conn->config.tls_pinned_pubkey);
		rc = -EPERM;
	}

	EVP_PKEY_free(pinned_key);

	return rc;
}

/**
 * Verify the pinned server certificate key of the server of a plain TLS KMIP
 * connection
 *
 * @param conn              the KMIP connection to free
 * @param server_cert       the server certificate
 * @param debug             if true, debug messages are printed
 */
static int kmip_connection_tls_verify_pinned_cert(
					struct kmip_connection *conn,
					X509 *server_cert, bool debug)
{
	X509 *pinned_cert = NULL;
	int rc = 0;
	FILE *fp;

	fp = fopen(conn->config.tls_server_cert, "r");
	if (fp == NULL) {
		rc = -errno;
		kmip_debug(debug, "Failed to read pinned server cert: %s",
				conn->config.tls_server_cert, strerror(-rc));
		return rc;
	}

	pinned_cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);

	if (pinned_cert == NULL) {
		kmip_debug(debug, "PEM_read_X509 failed: '%s'",
			   conn->config.tls_server_cert);
		if (debug)
			ERR_print_errors_fp(stderr);
		return -EIO;
	}

	if (X509_cmp(pinned_cert, server_cert) != 0) {
		kmip_debug(debug, "Server certificate does not match the "
			   "pinned certificate '%s'",
			   conn->config.tls_server_cert);
		rc = -EPERM;
	}

	X509_free(pinned_cert);

	return rc;
}

/**
 * Verify the issuer certificate key of the server of a plain TLS KMIP
 * connection
 *
 * @param conn              the KMIP connection to free
 * @param server_cert       the server certificate
 * @param debug             if true, debug messages are printed
 */
static int kmip_connection_tls_verify_issuer_cert(
					struct kmip_connection *conn,
					X509 *server_cert, bool debug)
{
	X509 *issuer_cert = NULL;
	int rc = 0;
	FILE *fp;

	fp = fopen(conn->config.tls_issuer_cert, "r");
	if (fp == NULL) {
		rc = -errno;
		kmip_debug(debug, "Failed to read issuer cert '%s': %s",
				conn->config.tls_issuer_cert, strerror(-rc));
		return rc;
	}

	issuer_cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);

	if (issuer_cert == NULL) {
		kmip_debug(debug, "PEM_read_X509 failed: '%s'",
			   conn->config.tls_issuer_cert);
		if (debug)
			ERR_print_errors_fp(stderr);
		return -EIO;
	}

	if (X509_check_issued(issuer_cert, server_cert) != X509_V_OK) {
		kmip_debug(debug, "The server certificate was not issued by "
			   "certificate '%s'", conn->config.tls_issuer_cert);
		rc = -EPERM;
	}

	X509_free(issuer_cert);

	return rc;
}

/**
 * Verify the server of a plain TLS KMIP connection
 *
 * @param conn              the KMIP connection to free
 * @param debug             if true, debug messages are printed
 */
static int kmip_connection_tls_verify_server(struct kmip_connection *conn,
					     bool debug)
{
	X509 *server_cert;
	int rc;

	server_cert = SSL_get_peer_certificate(conn->plain_tls.ssl);
	if (server_cert == NULL) {
		kmip_debug(debug, "SSL_get_peer_certificate failed");
		if (debug)
			ERR_print_errors_fp(stderr);
		rc = -EIO;
		goto out;
	}

	if (conn->config.tls_issuer_cert != NULL) {
		rc = kmip_connection_tls_verify_issuer_cert(conn, server_cert,
							    debug);
		if (rc != 0) {
			kmip_debug(debug,
				   "kmip_connection_tls_verify_issuer_cert "
				   "failed");
			goto out;
		}
	}

	if (conn->config.tls_server_cert != NULL) {
		rc = kmip_connection_tls_verify_pinned_cert(conn, server_cert,
							    debug);
		if (rc != 0) {
			kmip_debug(debug,
				   "kmip_connection_tls_verify_pinned_cert "
				   "failed");
			goto out;
		}
	}

	if (conn->config.tls_pinned_pubkey != NULL) {
		rc = kmip_connection_tls_verify_pinned_pubkey(conn,
					X509_get0_pubkey(server_cert),
					debug);
		if (rc != 0) {
			kmip_debug(debug,
				   "kmip_connection_tls_pinned_pubkey failed");
			goto out;
		}
	}

	rc = 0;

out:
	if (server_cert != NULL)
		X509_free(server_cert);

	return 0;
}

/**
 * Initializes a new plain TLS connection to a KMIP server.
 *
 * @param conn              The KMIP connection
 * @param debug             if true, debug messages are printed
 *
 * @returns 0 in case of success, or a negative errno value
 */
int kmip_connection_tls_init(struct kmip_connection *conn, bool debug)
{
	char *hostname = NULL, *port = NULL, *tok;
	struct stat sb;
	int rc;

	if (conn == NULL)
		return -EINVAL;

	conn->plain_tls.ssl_ctx = SSL_CTX_new(TLS_client_method());
	if (conn->plain_tls.ssl_ctx == NULL) {
		kmip_debug(debug, "SSL_CTX_new failed");
		if (debug)
			ERR_print_errors_fp(stderr);
		return -EIO;
	}

	if (SSL_CTX_use_certificate_file(conn->plain_tls.ssl_ctx,
					 conn->config.tls_client_cert,
					 SSL_FILETYPE_PEM) != 1) {
		kmip_debug(debug, "Loading the client certificate from '%s' "
			   "failed", conn->config.tls_client_cert);
		if (debug)
			ERR_print_errors_fp(stderr);
		rc = -EIO;
		goto out;
	}

	if (SSL_CTX_use_PrivateKey(conn->plain_tls.ssl_ctx,
				   conn->config.tls_client_key) != 1) {
		kmip_debug(debug, "Setting the client key from PKEY %p "
			   "failed", conn->config.tls_client_key);
		if (debug)
			ERR_print_errors_fp(stderr);
		rc = -EIO;
		goto out;

	}

	if (conn->config.tls_ca != NULL) {
		if (stat(conn->config.tls_ca, &sb) != 0) {
			rc = -errno;
			kmip_debug(debug, "stat failed on '%s': %s",
				   conn->config.tls_ca, strerror(-rc));
			goto out;
		}

		if (S_ISDIR(sb.st_mode)) {
			if (SSL_CTX_load_verify_locations(
					conn->plain_tls.ssl_ctx, NULL,
					conn->config.tls_ca) != 1) {
				kmip_debug(debug, "Setting the verify location "
					   "to '%s' failed",
					   conn->config.tls_ca);
				if (debug)
					ERR_print_errors_fp(stderr);
				rc = -EIO;
				goto out;
			}
		} else {
			if (SSL_CTX_load_verify_locations(
					conn->plain_tls.ssl_ctx,
					conn->config.tls_ca, NULL) != 1) {
				kmip_debug(debug, "Setting the verify location "
					   "to '%s' failed",
					   conn->config.tls_ca);
				if (debug)
					ERR_print_errors_fp(stderr);
				rc = -EIO;
				goto out;
			}
		}
	}

	conn->plain_tls.bio =
			BIO_new_buffer_ssl_connect(conn->plain_tls.ssl_ctx);
	if (conn->plain_tls.bio == NULL) {
		kmip_debug(debug, "BIO_new_ssl_connect failed");
		if (debug)
			ERR_print_errors_fp(stderr);
		rc = -EIO;
		goto out;
	}

	BIO_get_ssl(conn->plain_tls.bio, &conn->plain_tls.ssl);
	if (conn->plain_tls.ssl == NULL) {
		kmip_debug(debug, "BIO_get_ssl failed");
		if (debug)
			ERR_print_errors_fp(stderr);
		rc = -EIO;
		goto out;
	}

	hostname = strdup(conn->config.server);
	if (hostname == NULL) {
		kmip_debug(debug, "strdup failed");
		rc = -ENOMEM;
		goto out;
	}

	/* Split port number from hostname, if specified */
	if (hostname[0] == '[') {
		/* IPv6 address enclosed in square brackets */
		tok = strchr(hostname, ']');
		if (tok == NULL) {
			kmip_debug(debug, "malformed IPv6 address");
			rc = -EINVAL;
			goto out;
		}
		tok++;
		if (*tok == ':') {
			port = tok + 1;
			*tok = 0;
		}
	} else {
		/* hostname or IPv4 address */
		tok = strchr(hostname, ':');
		if (tok != NULL) {
			port = tok + 1;
			*tok = 0;
		}
	}

	kmip_debug(debug, "hostname: '%s'", hostname);
	if (port == NULL) {
		port = KMIP_DEFAULT_PLAIN_TLS_PORT;
		kmip_debug(debug, "port: default (%s)", port);
	} else {
		kmip_debug(debug, "port: %s", port);
	}

	if (conn->config.tls_verify_host) {
		SSL_set_hostflags(conn->plain_tls.ssl,
				  X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
		if (SSL_set1_host(conn->plain_tls.ssl, hostname) != 1) {
			kmip_debug(debug, "SSL_set1_host failed");
			if (debug)
				ERR_print_errors_fp(stderr);
			rc = -EIO;
			goto out;
		}
	}

	SSL_set_verify(conn->plain_tls.ssl, (conn->config.tls_verify_peer ||
					     conn->config.tls_verify_host) ?
				SSL_VERIFY_PEER : SSL_VERIFY_NONE, NULL);

	if (conn->config.tls_cipher_list != NULL) {
		if (SSL_set_cipher_list(conn->plain_tls.ssl,
					conn->config.tls_cipher_list) != 1) {
			kmip_debug(debug, "SSL_set_cipher_list failed");
			if (debug)
				ERR_print_errors_fp(stderr);
			rc = -EIO;
			goto out;
		}
	}

	if (conn->config.tls13_cipher_list != NULL) {
		if (SSL_set_ciphersuites(conn->plain_tls.ssl,
					 conn->config.tls13_cipher_list) != 1) {
			kmip_debug(debug, "SSL_set_ciphersuites failed");
			if (debug)
				ERR_print_errors_fp(stderr);
			rc = -EIO;
			goto out;
		}
	}

	SSL_set_mode(conn->plain_tls.ssl, SSL_MODE_AUTO_RETRY);

	BIO_set_conn_hostname(conn->plain_tls.bio, hostname);
	BIO_set_conn_port(conn->plain_tls.bio, port);

	if (BIO_do_connect(conn->plain_tls.bio) != 1) {
		kmip_debug(debug, "BIO_do_connect failed");
		if (debug)
			ERR_print_errors_fp(stderr);
		rc = -EIO;
		goto out;
	}

	kmip_debug(debug, "TLS connection established using %s",
		   SSL_get_cipher_name(conn->plain_tls.ssl));

	rc = kmip_connection_tls_verify_server(conn, debug);
	if (rc != 0) {
		kmip_debug(debug, "kmip_connection_tls_verify_server failed");
		if (debug)
			ERR_print_errors_fp(stderr);
		rc = -EIO;
		goto out;
	}

	rc = 0;

out:
	if (rc != 0)
		kmip_connection_tls_term(conn);
	if (hostname != NULL)
		free(hostname);

	return rc;
}

/**
 * Perform a request over the KMIP connection
 *
 * @param conn     n        the KMIP connection
 * @param request           the request to send
 * @param response          On return: the received response. Must be freed by
 *                          the caller.
 *
 * @param debug             if true, debug messages are printed
 *
 * @returns 0 in case of success, or a negative errno value
 */
int kmip_connection_tls_perform(struct kmip_connection *conn,
				struct kmip_node *request,
				struct kmip_node **response,
				bool debug)
{
	size_t size;
	int rc;

	if (conn == NULL || request == NULL || response == NULL)
		return -EINVAL;

	*response = NULL;

	/* Send out the request */
	rc = kmip_encode_ttlv(request, conn->plain_tls.bio, &size, debug);
	if (rc != 0) {
		kmip_debug(debug, "kmip_encode_ttlv failed");
		goto out;
	}
	if (BIO_flush(conn->plain_tls.bio) != 1) {
		kmip_debug(debug, "BIO_flush failed");
		goto out;
	}
	kmip_debug(debug, "%lu bytes sent", size);

	/* receive the response */
	rc = kmip_decode_ttlv(conn->plain_tls.bio, NULL, response, debug);
	if (rc != 0 || *response == NULL) {
		kmip_debug(debug, "kmip_decode_ttlv failed");
		goto out;
	}

	rc = 0;

out:
	if (rc != 0) {
		if (BIO_reset(conn->plain_tls.bio) != 1)
			kmip_debug(debug, "BIO_reset failed");
	}

	return rc;
}

/**
 * Terminates a plain TLS KMIP connection.
 *
 * @param conn              the KMIP connection to free
 */
void kmip_connection_tls_term(struct kmip_connection *conn)
{
	if (conn == NULL)
		return;

	if (conn->plain_tls.bio != NULL) {
		BIO_ssl_shutdown(conn->plain_tls.bio);
		BIO_free_all(conn->plain_tls.bio);
	}
	if (conn->plain_tls.ssl_ctx != NULL)
		SSL_CTX_free(conn->plain_tls.ssl_ctx);

	conn->plain_tls.bio = NULL;
	conn->plain_tls.ssl_ctx = NULL;
	conn->plain_tls.ssl = NULL;
}
