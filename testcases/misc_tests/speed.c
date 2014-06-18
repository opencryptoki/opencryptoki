// File: speed.c
//
// Performance tests for Opencryptoki
//
//    RSA keygen (with keylength 1024, 2048, 4096)
//    RSA sign and verify (with keylength 1024, 2048, 4096)
//    RSA encrypt and decrypt (with keylength 1024, 2048, 4096)
//    DES3 encrypt and decrypt (with modes ECB and CBC)
//    AES encrypt and decrypt (with modes ECB and CBC, with keylength 128, 192, 256)
//    SHA1, SHA256, SHA512
//


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/timeb.h>

#include "pkcs11types.h"
#include "regress.h"
#include "common.c"

#define SHA1_HASH_LEN   20
#define SHA256_HASH_LEN 32
#define SHA512_HASH_LEN 64
#define MAX_HASH_LEN SHA512_HASH_LEN


// the GetSystemTime and SYSTEMTIME implementation
// from regress.h only has a ms resolution
// and produces absolut inacceptable measurements.
// So we use gettimeofday() and struct timeval
// with us resolution instead.
#ifdef SYSTEMTIME
#undef SYSTEMTIME
#endif
#define SYSTEMTIME struct timeval
#ifdef GetSystemTime
#undef GetSystemTime
#endif
#define GetSystemTime(x) gettimeofday((x),NULL)
inline unsigned long delta_time_us(struct timeval *t1, struct timeval *t2)
{
		 unsigned long d;
		 struct timeval td;
		 timersub(t2, t1, &td);
		 d = td.tv_sec * 1000 * 1000 + td.tv_usec;
		 return (d ? d : 1); // return 1us if delta is 0
}


int do_GetFunctionList(void);

CK_FUNCTION_LIST  *funcs;
CK_SLOT_ID  SLOT_ID;

// keylength: 512, 1024, 2048, 4096
int do_RSA_PKCS_EncryptDecrypt(int keylength)
{
	CK_SLOT_ID slot_id;
	CK_SESSION_HANDLE session;
	CK_MECHANISM mech;
	CK_FLAGS flags;
	CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG user_pin_len;
	CK_RV rv, rc;

	CK_OBJECT_HANDLE publ_key, priv_key;
	CK_BYTE data1[100];
	CK_BYTE data2[512];
	CK_BYTE encdata[512];
	CK_ULONG len1, len2, encdata_len;

	CK_ULONG i;
	CK_ULONG iterations = 2000;
	SYSTEMTIME t1, t2;
	CK_ULONG diff, avg_time, min_time, max_time, tot_time;

	CK_ULONG bits = keylength;
	CK_BYTE pub_exp[] = { 0x01, 0x00, 0x01 };

	CK_ATTRIBUTE pub_tmpl[] = {{CKA_MODULUS_BITS, &bits, sizeof(bits)},
			   {CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp)}};

	testcase_begin("RSA PKCS Encrypt with keylen=%d datalen=%d",
		keylength, (int)sizeof(data1));

	slot_id = SLOT_ID;

	testcase_rw_session();
	testcase_user_login();

	mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;

	rc = funcs->C_GenerateKeyPair(session, &mech, pub_tmpl, 2, NULL, 0,
				      &publ_key, &priv_key);
	if (rc != CKR_OK) {
		testcase_error("C_GenerateKeyPair rc=%s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	len1 = sizeof(data1);
	encdata_len = sizeof(encdata);
	for (i=0; i < len1; i++)
		data1[i] = (unsigned char) i;

	mech.mechanism = CKM_RSA_PKCS;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;

	tot_time = 0;
	max_time = 0;
	min_time = 0xFFFFFFFF;

	for (i=0; i < iterations + 2; i++) {
		GetSystemTime(&t1);

		rc = funcs->C_EncryptInit(session, &mech, publ_key);
		if (rc != CKR_OK) {
			testcase_error("C_EncryptInit rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		encdata_len = sizeof(encdata);
		rc = funcs->C_Encrypt(session, data1, len1, encdata,
				      &encdata_len);
		if (rc != CKR_OK) {
			testcase_error("C_Encrypt rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		GetSystemTime(&t2);

		diff = delta_time_us(&t1, &t2);

		tot_time += diff;

		if (diff < min_time)
			min_time = diff;

		if (diff > max_time)
			max_time = diff;
	}

	tot_time -= min_time;
	tot_time -= max_time;
	avg_time = tot_time / iterations;

	// us -> ms
	tot_time /= 1000;
	min_time /= 1000;
	max_time /= 1000;
	avg_time /= 1000;

	printf("%ld iterations: total=%ldms min=%ldms max=%ldms avg=%ldms op/s=%.3f\n\n", iterations, tot_time, min_time, max_time, avg_time,
	      (double)(iterations * 1000) / (double)tot_time);


	printf("RSA PKCS Decrypt with keylen=%d datalen=%d\n",
		keylength, (int)encdata_len);

	tot_time = 0;
	max_time = 0;
	min_time = 0xFFFFFFFF;

	for (i=0; i < iterations + 2; i++) {
		GetSystemTime(&t1);

		rc = funcs->C_DecryptInit(session, &mech, priv_key);
		if (rc != CKR_OK) {
			testcase_error("C_DecryptInit rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		len2 = sizeof(data2);
		rc = funcs->C_Decrypt(session, encdata, encdata_len, data2,
				      &len2);
		if (rc != CKR_OK) {
			testcase_error("C_Decrypt rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}
		if (len2 != len1) {
			testcase_error("len1=%lu and len2=%lu do not match ?!?",
				  len1, len2);
			rc = CKR_FUNCTION_FAILED;;
			goto testcase_cleanup;
		}

		GetSystemTime(&t2);

		diff = delta_time_us(&t1, &t2);

		tot_time += diff;

		if (diff < min_time)
			min_time = diff;

		if (diff > max_time)
			max_time = diff;

	}

	tot_time -= min_time;
	tot_time -= max_time;
	avg_time = tot_time / iterations;

	// us -> ms
	tot_time /= 1000;
	min_time /= 1000;
	max_time /= 1000;
	avg_time /= 1000;

	printf("%ld iterations: total=%ldms min=%ldms max=%ldms avg=%ldms op/s=%.3f\n\n", iterations, tot_time, min_time, max_time, avg_time,
	      (double)(iterations * 1000) / (double)tot_time);

testcase_cleanup:
	rv = funcs->C_CloseAllSessions(slot_id);
	if (rv != CKR_OK)
		testcase_error("C_CloseAllSessions rv=%s", p11_get_ckr(rv));

	if (rc != CKR_OK)
		return FALSE;
	else
		return TRUE;
}

// keylength: 512, 1024, 2048, 4096
int do_RSA_KeyGen(int keylength)
{
	CK_SLOT_ID slot_id;
	CK_SESSION_HANDLE session;
	CK_MECHANISM mech;
	CK_FLAGS flags;
	CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG user_pin_len;
	CK_RV rv, rc;

	CK_ULONG iterations = 10;
	SYSTEMTIME  t1, t2;
	CK_ULONG diff, avg_time, max_time, min_time, tot_time, i;
	CK_ULONG  bits = 2048;

	CK_OBJECT_HANDLE publ_key, priv_key;
	CK_BYTE pub_exp[] = { 0x01, 0x00, 0x01 };
	CK_ATTRIBUTE pub_tmpl[] = {{CKA_MODULUS_BITS, &bits, sizeof(bits)},
			{CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp)}};

	testcase_begin("RSA KeyGen with keylen=%d", keylength);

	slot_id = SLOT_ID;

	testcase_rw_session();
	testcase_user_login();

	mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;

	rc = funcs->C_GenerateKeyPair(session, &mech, pub_tmpl, 2, NULL, 0,
				      &publ_key, &priv_key);
	if (rc != CKR_OK) {
		testcase_error("C_GenerateKeyPair rc=%s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	min_time = 0xFFFFFFFF;
	max_time = 0x00000000;
	tot_time = 0x00000000;

	for (i=0; i < iterations + 2; i++) {
		GetSystemTime(&t1);
		rc = funcs->C_GenerateKeyPair(session, &mech, pub_tmpl, 2,
					      NULL, 0, &publ_key, &priv_key);
		if (rc != CKR_OK) {
			testcase_error("C_GenerateKeyPair rc=%s",
					p11_get_ckr(rc));
			goto testcase_cleanup;
		}
		GetSystemTime(&t2);
		diff = delta_time_us(&t1, &t2);
		tot_time += diff;
		if (diff < min_time)
			min_time = diff;
		if (diff > max_time)
			max_time = diff;
	}

	tot_time -= min_time;
	tot_time -= max_time;
	avg_time = tot_time / iterations;

	// us -> ms
	tot_time /= 1000;
	min_time /= 1000;
	max_time /= 1000;
	avg_time /= 1000;

	printf("%ld iterations: total=%ldms min=%ldms max=%ldms avg=%ldms op/s=%.3f\n\n", iterations, tot_time, min_time, max_time, avg_time,
	      (double)(iterations * 1000) / (double)tot_time);

testcase_cleanup:
	rv = funcs->C_CloseSession(session);
	if (rv != CKR_OK)
		testcase_error("C_CloseSession rv=%s", p11_get_ckr(rv));

	if (rc != CKR_OK)
		return FALSE;
	else
		return TRUE;
}

// keylength: 512, 1024, 2048, 4096
int do_RSA_PKCS_SignVerify(int keylength)
{
	CK_SLOT_ID slot_id;
	CK_SESSION_HANDLE session;
	CK_MECHANISM mech;
	CK_FLAGS flags;
	CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG user_pin_len;
	CK_RV rv, rc;

	CK_ULONG i, len1, sig_len;
	CK_BYTE signature[512];
	CK_BYTE data1[100];
	CK_OBJECT_HANDLE publ_key, priv_key;

	SYSTEMTIME t1, t2;
	CK_ULONG diff, avg_time, min_time, max_time, tot_time;
	CK_ULONG iterations = 1000;

	CK_ULONG bits = keylength;
	CK_BYTE pub_exp[] = { 0x01, 0x00, 0x01 };
	CK_ATTRIBUTE pub_tmpl[] = {{CKA_MODULUS_BITS, &bits, sizeof(bits)},
			{CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp)}};

	slot_id = SLOT_ID;

	testcase_begin("RSA PKCS Sign with keylen=%d datalen=%d",
		keylength, (int)sizeof(data1));

	testcase_rw_session();
	testcase_user_login();

	mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;

	rc = funcs->C_GenerateKeyPair(session, &mech, pub_tmpl, 2, NULL, 0,
				      &publ_key, &priv_key);
	if (rc != CKR_OK) {
		testcase_error("C_GenerateKeyPair rc=%s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	// sign some data
	len1 = sizeof(data1);
	sig_len = sizeof(signature);

	for (i=0; i < len1; i++)
		data1[i] = (unsigned char) i;

	mech.mechanism = CKM_RSA_PKCS;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;

	tot_time = 0;
	max_time = 0;
	min_time = 0xFFFFFFFF;

	for (i=0; i < iterations + 2; i++) {
		GetSystemTime(&t1);

		rc = funcs->C_SignInit(session, &mech, priv_key);
		if (rc != CKR_OK) {
			testcase_error("C_SignInit rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		sig_len = sizeof(signature);
		rc = funcs->C_Sign(session, data1, len1, signature, &sig_len);
		if (rc != CKR_OK) {
			testcase_error("C_Sign rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		GetSystemTime(&t2);
		diff = delta_time_us(&t1, &t2);
		tot_time += diff;
		if (diff < min_time)
			min_time = diff;
		if (diff > max_time)
			max_time = diff;
	}

	tot_time -= min_time;
	tot_time -= max_time;
	avg_time = tot_time / iterations;

	// us -> ms
	tot_time /= 1000;
	min_time /= 1000;
	max_time /= 1000;
	avg_time /= 1000;

	printf("%ld iterations: total=%ldms min=%ldms max=%ldms avg=%ldms op/s=%.3f\n\n",iterations, tot_time, min_time, max_time, avg_time,
		(double)(iterations * 1000) / (double)tot_time);

	printf("RSA PKCS Verify with keylen=%d datalen=%d\n",
		keylength, (int)sizeof(data1));

	tot_time = 0;
	max_time = 0;
	min_time = 0xFFFFFFFF;

	for (i=0; i < iterations + 2; i++) {
		GetSystemTime(&t1);
		rc = funcs->C_VerifyInit(session, &mech, publ_key);
		if (rc != CKR_OK) {
			testcase_error("C_VerifyInit rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		rc = funcs->C_Verify(session, data1, len1, signature, sig_len);
		if (rc != CKR_OK) {
			testcase_error("C_Verify rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		GetSystemTime(&t2);
		diff = delta_time_us(&t1, &t2);
		tot_time += diff;
		if (diff < min_time)
			min_time = diff;
		if (diff > max_time)
			max_time = diff;
	}

	tot_time -= min_time;
	tot_time -= max_time;
	avg_time = tot_time / iterations;

	// us -> ms
	tot_time /= 1000;
	min_time /= 1000;
	max_time /= 1000;
	avg_time /= 1000;

	printf("%ld iterations: total=%ldms min=%ldms max=%ldms avg=%ldms op/s=%.3f\n\n",iterations, tot_time, min_time, max_time, avg_time,
		(double)(iterations * 1000) / (double)tot_time);

testcase_cleanup:
	rv = funcs->C_CloseAllSessions(slot_id);
	if (rv != CKR_OK)
		testcase_error("C_CloseAllSession rv=%s", p11_get_ckr(rv));

	if (rc != CKR_OK)
		return FALSE;
	else
		return TRUE;
}

// mode: ECB CBC
int do_DES3_EncrDecr(const char* mode)
{
	CK_SLOT_ID slot_id;
	CK_SESSION_HANDLE session;
	CK_MECHANISM mech;
	CK_FLAGS flags;
	CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG user_pin_len;
	CK_RV rv, rc;

	CK_OBJECT_HANDLE h_key;
	CK_BYTE original[BIG_REQUEST];
	CK_BYTE cipher[BIG_REQUEST];
	CK_BYTE clear[BIG_REQUEST];
	CK_ULONG orig_len, cipher_len, clear_len;
	CK_BYTE init_v[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

	SYSTEMTIME t1, t2;
	CK_ULONG i, iterations = 10000;
	CK_ULONG avg_time, tot_time, min_time, max_time, diff;

	slot_id = SLOT_ID;

	testcase_begin("DES3 Encrypt with mode=%s datalen=%d\n",
			mode, BIG_REQUEST);

	testcase_rw_session();
	testcase_user_login();

	mech.mechanism = CKM_DES3_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;

	// generate a DES3 key
	rc = funcs->C_GenerateKey(session, &mech, NULL, 0, &h_key);
	if (rc != CKR_OK) {
		testcase_error("C_GenerateKey rc=%s",p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	// clear buffers
	memset(clear, 0, BIG_REQUEST);
	memset(original, 0, BIG_REQUEST);
	memset(cipher, 0, BIG_REQUEST);

	// encrypt some data
	orig_len = BIG_REQUEST;
	for (i=0; i < orig_len; i++)
		original[i] = i % 255;

	if (strcmp(mode, "ECB") == 0) {
		mech.mechanism = CKM_DES3_ECB;
		mech.ulParameterLen = 0;
		mech.pParameter = NULL;
	} else if (strcmp(mode, "CBC") == 0) {
		mech.mechanism = CKM_DES3_CBC;
		mech.ulParameterLen = 8;
		mech.pParameter = init_v;
	} else {
		testcase_error("unknown mode %s in do_DES3_EncrDecr()", mode);
		rc = CKR_MECHANISM_INVALID;
		goto testcase_cleanup;
	}

	tot_time = 0;
	max_time = 0;
	min_time = 0xFFFFFFFF;

	for (i=0; i < iterations + 2; i++) {
		GetSystemTime(&t1);
		rc = funcs->C_EncryptInit(session, &mech, h_key);
		if (rc != CKR_OK) {
			testcase_error("C_EncryptInit rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		cipher_len = BIG_REQUEST;
		rc = funcs->C_Encrypt(session, original, orig_len, cipher,
				      &cipher_len);
		if (rc != CKR_OK) {
			testcase_error("C_Encrypt rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		GetSystemTime(&t2);

		diff = delta_time_us(&t1, &t2);

		tot_time += diff;

		if (diff < min_time)
			min_time = diff;

		if (diff > max_time)
			max_time = diff;
	}

	tot_time -= min_time;
	tot_time -= max_time;
	avg_time = tot_time / iterations;

	// us -> ms
	tot_time /= 1000;

	printf("%ld iterations: total=%ldms min=%ldus max=%ldus avg=%ldus op/s=%.3f %.3fMB/s\n\n", iterations, tot_time, min_time, max_time, avg_time,
		(double)(iterations * 1000) / (double)tot_time,
		(((double)(iterations * 1000)/(double)(1024*1024)) * BIG_REQUEST) / (double)tot_time);

	printf("DES3 Decrypt with mode=%s datalen=%d\n", mode, BIG_REQUEST);

	tot_time = 0;
	max_time = 0;
	min_time = 0xFFFFFFFF;

	for (i=0; i < iterations + 2; i++) {
		GetSystemTime(&t1);

		rc = funcs->C_DecryptInit(session, &mech, h_key);
		if (rc != CKR_OK) {
			testcase_error("C_DecryptInit rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		clear_len = BIG_REQUEST;
		rc = funcs->C_Decrypt(session, cipher, cipher_len, clear,
				      &clear_len);
		if (rc != CKR_OK) {
			testcase_error("C_Decrypt rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		GetSystemTime(&t2);

		diff = delta_time_us(&t1, &t2);

		tot_time += diff;

		if (diff < min_time)
			min_time = diff;

		if (diff > max_time)
			max_time = diff;
	}

	tot_time -= min_time;
	tot_time -= max_time;
	avg_time = tot_time / iterations;

	// us -> ms
	tot_time /= 1000;

	printf("%ld iterations: total=%ldms min=%ldus max=%ldus avg=%ldus op/s=%.3f %.3fMB/s\n\n", iterations, tot_time, min_time, max_time, avg_time,
		(double)(iterations * 1000) / (double)tot_time,
		(((double)(iterations * 1000)/(double)(1024*1024)) * BIG_REQUEST) / (double)tot_time);

testcase_cleanup:
	rv = funcs->C_CloseAllSessions(slot_id);
	if (rv != CKR_OK)
		testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rv));

	if (rc != CKR_OK)
		return FALSE;
	else
		return TRUE;
}

// keylength: 128...256
// mode: ECB CBC
int do_AES_EncrDecr(int keylength, const char* mode)
{
	CK_SLOT_ID slot_id;
	CK_SESSION_HANDLE session;
	CK_MECHANISM mech;
	CK_FLAGS flags;
	CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG user_pin_len;
	CK_RV rv, rc;

	CK_OBJECT_HANDLE h_key;
	CK_BYTE original[BIG_REQUEST];
	CK_BYTE cipher[BIG_REQUEST];
	CK_BYTE clear[BIG_REQUEST];
	CK_ULONG orig_len, cipher_len, clear_len;
	CK_ULONG key_len = keylength / 8;

	CK_BYTE init_v[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };

	CK_ULONG i, iterations = 50000;
	SYSTEMTIME t1, t2;
	CK_ULONG avg_time, tot_time, min_time, max_time, diff;

	testcase_begin("AES Encrypt with mode=%s keylen=%ld datalen=%d\n",
			mode, key_len * 8, BIG_REQUEST);

	slot_id = SLOT_ID;

	testcase_rw_session();
	testcase_user_login();

	mech.mechanism = CKM_AES_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;

	rc = generate_AESKey(session, key_len, &mech, &h_key);
	if (rc != CKR_OK) {
		testcase_error("C_GenerateKey rc=%s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	// clear buffers
	memset(original, 0, BIG_REQUEST);
	memset(clear, 0, BIG_REQUEST);
	memset(cipher, 0, BIG_REQUEST);

	// encrypt some data
	orig_len = BIG_REQUEST;
	for (i=0; i < orig_len; i++)
		original[i] = i % 255;

	if (strcmp(mode, "ECB") == 0) {
		mech.mechanism = CKM_AES_ECB;
		mech.ulParameterLen = 0;
		mech.pParameter = NULL;
	} else if (strcmp(mode, "CBC") == 0) {
		mech.mechanism = CKM_AES_CBC;
		mech.ulParameterLen = 16;
		mech.pParameter = init_v;
	} else {
		testcase_error("unknown mode %s in do_AES_EncrDecr()", mode);
		rc = CKR_MECHANISM_INVALID;
		goto testcase_cleanup;
	}

	tot_time = 0;
	max_time = 0;
	min_time = 0xFFFFFFFF;

	for (i=0; i < iterations + 2; i++) {
		GetSystemTime(&t1);
		rc = funcs->C_EncryptInit(session, &mech, h_key);
		if (rc != CKR_OK) {
			testcase_error("C_EncryptInit rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		cipher_len = BIG_REQUEST;
		rc = funcs->C_Encrypt(session, original, orig_len, cipher,
				      &cipher_len);
		if (rc != CKR_OK) {
			testcase_error("C_Encrypt rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		GetSystemTime(&t2);
		diff = delta_time_us(&t1, &t2);
		tot_time += diff;
		if (diff < min_time)
			min_time = diff;

		if (diff > max_time)
			max_time = diff;
	}

	tot_time -= min_time;
	tot_time -= max_time;
	avg_time = tot_time / iterations;

	// us -> ms
	tot_time /= 1000;

	printf("%ld iterations: total=%ldms min=%ldus max=%ldus avg=%ldus op/s=%.3f %.3fMB/s\n\n",iterations, tot_time, min_time, max_time, avg_time,
		(double)(iterations * 1000) / (double)tot_time,
		(((double)(iterations * 1000)/(double)(1024*1024)) * BIG_REQUEST) / (double)tot_time);

	printf("AES Decrypt with mode=%s keylen=%ld datalen=%d\n",
		mode, key_len * 8, BIG_REQUEST);

	tot_time = 0;
	max_time = 0;
	min_time = 0xFFFFFFFF;

	for (i=0; i < iterations + 2; i++) {
		GetSystemTime(&t1);
		rc = funcs->C_DecryptInit(session, &mech, h_key);
		if (rc != CKR_OK) {
			testcase_error("C_DecryptInit rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		clear_len = BIG_REQUEST;
		rc = funcs->C_Decrypt(session, cipher, cipher_len, clear,
				      &clear_len);
		if (rc != CKR_OK) {
			testcase_error("C_Decrypt rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		GetSystemTime(&t2);
		diff = delta_time_us(&t1, &t2);
		tot_time += diff;
		if (diff < min_time)
			min_time = diff;

		if (diff > max_time)
			max_time = diff;

	}

	tot_time -= min_time;
	tot_time -= max_time;
	avg_time = tot_time / iterations;

	// us -> ms
	tot_time /= 1000;

	printf("%ld iterations: total=%ldms min=%ldus max=%ldus avg=%ldus op/s=%.3f %.3fMB/s\n\n", iterations, tot_time, min_time, max_time, avg_time,
		(double)(iterations * 1000) / (double)tot_time,
		(((double)(iterations * 1000)/(double)(1024*1024)) * BIG_REQUEST) / (double)tot_time);


testcase_cleanup:
	rv = funcs->C_CloseAllSessions(slot_id);
	if (rv != CKR_OK)
		testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rv));

	if (rc == CKR_OK)
		return TRUE;
	else
		return FALSE;
}

int do_SHA(const char *mode)
{
	CK_SLOT_ID slot_id;
	CK_SESSION_HANDLE session;
	CK_MECHANISM mech;
	CK_FLAGS flags;
	CK_RV rc, rv;

	CK_BYTE data[BIG_REQUEST];
	CK_BYTE hash[MAX_HASH_LEN];
	CK_ULONG data_len, hash_len, h_len;

	SYSTEMTIME t1, t2;
	CK_ULONG diff, avg_time, tot_time, min_time, max_time;
	CK_ULONG i, iterations = 20000;

	printf("SHA (%s) with datalen=%d\n", mode, BIG_REQUEST);

	slot_id = SLOT_ID;

	testcase_rw_session();

	mech.ulParameterLen = 0;
	mech.pParameter = NULL;

	if (strcmp(mode, "SHA1") == 0) {
		mech.mechanism  = CKM_SHA_1;
		hash_len = SHA1_HASH_LEN;
	} else if (strcmp(mode, "SHA256") == 0) {
		mech.mechanism = CKM_SHA256;
		hash_len = SHA256_HASH_LEN;
	} else if (strcmp(mode, "SHA512") == 0) {
		mech.mechanism = CKM_SHA512;
		hash_len = SHA512_HASH_LEN;
	} else {
		testcase_error("unknown mode %s in do_SHA()", mode);
		rc = CKR_MECHANISM_INVALID;
		goto testcase_cleanup;
	}

	// generate some data to hash
	//
	data_len = BIG_REQUEST;
	memset(data, 0, data_len);
	for (i=0; i < data_len; i++)
		data[i] = i % 255;

	tot_time = 0;
	max_time = 0;
	min_time = 0xFFFFFFFF;

	for (i=0; i < iterations + 2; i++) {
		GetSystemTime(&t1);

		rc = funcs->C_DigestInit(session, &mech);
		if (rc != CKR_OK) {
			testcase_error("C_DigestInit rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		h_len = sizeof(hash);
		rc = funcs->C_Digest(session, data, data_len, hash, &h_len);
		if (rc != CKR_OK) {
			testcase_error("C_Digest rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		if (h_len != hash_len) {
			testcase_error("returned hashlen %ld doesn't match to expected len %ld\n", h_len, hash_len);
			rc = CKR_FUNCTION_FAILED;
			goto testcase_cleanup;
		}

		GetSystemTime(&t2);
		diff = delta_time_us(&t1, &t2);
		tot_time += diff;
		if (diff < min_time)
			min_time = diff;

		if (diff > max_time)
			max_time = diff;
	}

	tot_time -= min_time;
	tot_time -= max_time;
	avg_time = tot_time / iterations;

	// us -> ms
	tot_time /= 1000;

	printf("%ld iterations: total=%ldms min=%ldus max=%ldus avg=%ldus op/s=%.3f %.3fMB/s\n\n", iterations, tot_time, min_time, max_time, avg_time,
		(double)(iterations * 1000) / (double)tot_time,
		(((double)(iterations * 1000)/(double)(1024*1024)) * BIG_REQUEST) / (double)tot_time);

testcase_cleanup:
	rv = funcs->C_CloseAllSessions(slot_id);
	if (rv != CKR_OK)
		testcase_error("C_CloseAllSessions rv=%s", p11_get_ckr(rv));

	if (rc == CKR_OK)
		return TRUE;
	else
		return FALSE;
}


int do_DummyFunction( void )
{
#if DUMMY
	CK_SLOT_ID slot_id;
	CK_ULONG i, diff, avg_time, min_time, max_time;
	CK_ULONG iterations = 1000;
	SYSTEMTIME t1, t2;

	testcase_begin("do_DummyFunction...");

	slot_id = SLOT_ID;

	tot_time = 0;
	max_time = 0;
	min_time = 0xFFFFFFFF;

	for (i=0; i < iterations+2; i++) {
		GetSystemTime(&t1);
		DummyFunction(slot_id);

		GetSystemTime(&t2);

		diff = delta_time_us(&t1, &t2);
		tot_time += diff;

		if (diff < min_time)
			min_time = diff;

		if (diff > max_time)
			max_time = diff;
	}

	tot_time -= min_time;
	tot_time -= max_time;
	avg_time = tot_time / iterations;

	// us -> ms
	tot_time /= 1000;
	min_time /= 1000;
	max_time /= 1000;

	printf("%ld iterations: total=%ldms min=%ldms max=%ldms avg=%ldms op/s=%.3f\n\n", iterations, tot_time, min_time, max_time, avg_time,
		(double)(iterations * 1000) / (double)tot_time);
#endif

	return TRUE;
}

void speed_usage(char *fct)
{
	printf("usage:  %s -slot <num>", fct);
	printf(" [-rsa_keygen] [-rsa_signverify]");
	printf(" [-rsa_endecrypt] [-des3] [-aes] [-sha]");
	printf(" [-h] \n\n");

	return;
}

int main(int argc, char **argv)
{
	CK_C_INITIALIZE_ARGS  cinit_args;
	int rc, i;
	int do_rsa_keygen = 0;
	int do_rsa_signverify = 0;
	int do_rsa_endecrypt = 0;
	int do_des3_endecrypt = 0;
	int do_aes_endecrypt = 0;
	int do_sha = 0;

	SLOT_ID = 1000;

	for (i=1; i < argc; i++) {
		if (strcmp(argv[i], "-slot") == 0) {
			SLOT_ID = atoi(argv[i+1]);
			i++;
			continue;
		}
		if (strcmp(argv[i], "-rsa_keygen") == 0) {
			do_rsa_keygen = 1;
		} else if (strcmp(argv[i], "-rsa_signverify") == 0) {
			do_rsa_signverify = 1;
		} else if (strcmp(argv[i], "-rsa_endecrypt") == 0) {
			do_rsa_endecrypt = 1;
		} else if (strcmp(argv[i], "-des3") == 0) {
			do_des3_endecrypt = 1;
		} else if (strcmp(argv[i], "-aes") == 0) {
			do_aes_endecrypt = 1;
		} else if (strcmp(argv[i], "-sha") == 0) {
			do_sha = 1;
		} else if (strcmp(argv[i], "-h") == 0) {
			speed_usage(argv[0]);
			return 0;
		} else {
			printf("unknown option '%s'\n", argv[i]);
			speed_usage(argv[0]);
			return 1;
		}
	}

	// error if slot has not been identified.
	if (SLOT_ID == 1000) {
		printf("Please specify the slot to be tested.\n");
		speed_usage(argv[0]);
		return 1;
	}

	if (do_rsa_keygen + do_rsa_signverify + do_rsa_endecrypt
	    + do_des3_endecrypt + do_aes_endecrypt + do_sha == 0) {
		do_rsa_keygen = 1;
		do_rsa_signverify = 1;
		do_rsa_endecrypt = 1;
		do_des3_endecrypt = 1;
		do_aes_endecrypt = 1;
		do_sha = 1;
	}

	printf("Using slot #%lu...\n\n", SLOT_ID );

	rc = do_GetFunctionList();
	if (!rc)
		return rc;

	memset(&cinit_args, 0x0, sizeof(cinit_args));
	cinit_args.flags = CKF_OS_LOCKING_OK;

	funcs->C_Initialize(&cinit_args);

	if (do_rsa_keygen) {
		rc = do_RSA_KeyGen(1024);
		if (!rc)
			return rc;
		rc = do_RSA_KeyGen(2048);
		if (!rc)
			return rc;
		rc = do_RSA_KeyGen(4096);
		if (!rc)
			return rc;
	}

	if (do_rsa_signverify) {
		rc = do_RSA_PKCS_SignVerify(1024);
		if (!rc)
			return rc;
		rc = do_RSA_PKCS_SignVerify(2048);
		if (!rc)
			return rc;
		rc = do_RSA_PKCS_SignVerify(4096);
		if (!rc)
			return rc;
	}

	if (do_rsa_endecrypt) {
		rc = do_RSA_PKCS_EncryptDecrypt(1024);
		if (!rc)
			return rc;
		rc = do_RSA_PKCS_EncryptDecrypt(2048);
		if (!rc)
			return rc;
		rc = do_RSA_PKCS_EncryptDecrypt(4096);
		if (!rc)
			return rc;
	}

	if (do_des3_endecrypt) {
		rc = do_DES3_EncrDecr("ECB");
		if (!rc)
			return rc;
		rc = do_DES3_EncrDecr("CBC");
		if (!rc)
			return rc;
	}

	if (do_aes_endecrypt) {
		rc = do_AES_EncrDecr(128, "ECB");
		if (!rc)
			return rc;
		rc = do_AES_EncrDecr(128, "CBC");
		if (!rc)
			return rc;
		rc = do_AES_EncrDecr(192, "ECB");
		if (!rc)
			return rc;
		rc = do_AES_EncrDecr(192, "CBC");
		if (!rc)
			return rc;
		rc = do_AES_EncrDecr(256, "ECB");
		if (!rc)
			return rc;
		rc = do_AES_EncrDecr(256, "CBC");
		if (!rc)
			return rc;
	}

	if (do_sha) {
		rc = do_SHA("SHA1");
		if (!rc)
			return rc;
		rc = do_SHA("SHA256");
		if (!rc)
			return rc;
		rc = do_SHA("SHA512");
		if (!rc)
			return rc;
	}

	funcs->C_Finalize( NULL );

	return 0;
}
