
/*
 * Licensed materials, Property of IBM Corp.
 *
 * openCryptoki CCA token
 *
 * (C) COPYRIGHT International Business Machines Corp. 2001, 2002, 2006
 *
 * Author: Kent E. Yoder <yoder1@us.ibm.com>
 *
 */

#ifndef __CCA_STDLL_H__
#define __CCA_STDLL_H__

/* CCA library constants */

#define CCA_PRIVATE_KEY_NAME_SIZE       64
#define CCA_REGENERATION_DATA_SIZE      64
#define CCA_KEY_TOKEN_SIZE              2500
#define CCA_KEY_VALUE_STRUCT_SIZE       2500
#define CCA_RULE_ARRAY_SIZE             256
#define CCA_KEYWORD_SIZE                8
#define CCA_KEY_ID_SIZE                 64
#define CCA_RNG_SIZE                    8
#define CCA_OCV_SIZE                    18
#define CCA_SUCCESS                     0
#define CCA_PKB_E_OFFSET                18
#define CCA_PKB_E_SIZE                  2
#define CCA_PKB_E_SIZE_OFFSET           4

/* CCA Internal Key Token parsing constants */

/* Size of an RSA internal key token header */
#define CCA_RSA_INTTOK_HDR_LENGTH		8
/* Offset into an RSA internal key token of the private key area */
#define CCA_RSA_INTTOK_PRIVKEY_OFFSET		8
/* Offset into an RSA key area of the total length */
#define CCA_RSA_INTTOK_PRIVKEY_LENGTH_OFFSET	2
#define CCA_RSA_INTTOK_PUBKEY_LENGTH_OFFSET	2
/* Offset into an RSA private key area of the length of n, the modulus */
#define CCA_RSA_INTTOK_PRIVKEY_N_LENGTH_OFFSET	64
/* Offset into an RSA public key area of the length of e, the public exponent */
#define CCA_RSA_INTTOK_PUBKEY_E_LENGTH_OFFSET	6
/* Offset into an RSA public key area of the value of e, the public exponent */
#define CCA_RSA_INTTOK_PUBKEY_E_OFFSET		12
/* Offset into the rule_array returned by the STATCCAE command for the
 * Current Symmetric Master Key register status */
#define CCA_STATCCAE_SYM_CMK_OFFSET		8
/* Offset into the rule_array returned by the STATCCAE command for the
 * Current Asymmetric Master Key register status */
#define CCA_STATCCAE_ASYM_CMK_OFFSET		56

/* CCA STDLL constants */

#define CCATOK_MAX_N_LEN		512
#define CCATOK_MAX_E_LEN		256

#define sw_des3_cbc_encrypt(clear, len, cipher, len2, iv, key) \
	sw_des3_cbc(clear, len, cipher, len2, iv, key, 1)

#define sw_des3_cbc_decrypt(clear, len, cipher, len2, iv, key) \
	sw_des3_cbc(clear, len, cipher, len2, iv, key, 0)

/* CCA STDLL debug logging definitions */

#ifdef DEBUG
#define CCADBG(fn, rc, reason)		fprintf(stderr, "CCA_TOK DEBUG %s:%d " fn " failed. "	\
						"return: %ld, reason: %ld\n", __FUNCTION__,	\
						__LINE__, rc, reason)
#define DBG(fmt, ...)			fprintf(stderr, "CCA_TOK DEBUG %s:%d %s " fmt "\n",	\
						__FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#else
#define CCADBG(...)			do { } while (0)
#define DBG(...)			do { } while (0)
#endif

#define LOG(priority, fmt, ...) \
	do { \
		openlog("openCryptoki(CCA)", LOG_NDELAY|LOG_PID, LOG_USER); \
		syslog(priority, "%s " fmt, __FILE__, ##__VA_ARGS__); \
	} while (0)

#endif
