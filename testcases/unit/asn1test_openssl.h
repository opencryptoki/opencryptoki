/*
 * COPYRIGHT (c) International Business Machines Corp. 2026
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * Unit tests for PKCS#8 private key and SPKI public key encoding/decoding using
 * OpenSSL and opencryptoki asn1 functions.
 */

#ifndef ASN1TEST_OPENSSL_H
#define ASN1TEST_OPENSSL_H

/* OpenSSL PKCS#8 Private Key Tests */
int test_openssl_pkcs8_rsa(void);
int test_openssl_pkcs8_dsa(void);
int test_openssl_pkcs8_dh(void);
int test_openssl_pkcs8_ec(void);
int test_openssl_pkcs8_edwards(void);
int test_openssl_pkcs8_montgomery(void);
int test_openssl_pkcs8_ml_dsa(void);
int test_openssl_pkcs8_ml_kem(void);

/* OpenSSL SPKI Public Key Tests */
int test_openssl_spki_rsa(void);
int test_openssl_spki_dsa(void);
int test_openssl_spki_dh(void);
int test_openssl_spki_ec(void);
int test_openssl_spki_edwards(void);
int test_openssl_spki_montgomery(void);
int test_openssl_spki_ml_dsa(void);
int test_openssl_spki_ml_kem(void);

#endif /* ASN1TEST_OPENSSL_H */
