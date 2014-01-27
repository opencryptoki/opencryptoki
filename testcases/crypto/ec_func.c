// File: ecc_func.c
//

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"
#include "common.c"


/*
 * Below is a list for the OIDs and DER encodings of the brainpool.
 * Currently we only support the regular curves and not the twisted curves.
 * They are listed here for completeness.
 * Beginning of each DER encoding should be 06 for OID and 09 for the length.
 * For example brainpoolP160r1 should be 06092B2403030208010101
 * brainpoolP160r1
 *		1.3.36.3.3.2.8.1.1.1
 *		2B2403030208010101
 * brainpoolP160t1
 *		1.3.36.3.3.2.8.1.1.2
 *		2B2403030208010102
 * brainpoolP192r1
 *		1.3.36.3.3.2.8.1.1.3
 *		2B2403030208010103
 * brainpoolP192t1
 *		1.3.36.3.3.2.8.1.1.4
 *		2B2403030208010104
 * brainpoolP224r1
 *		1.3.36.3.3.2.8.1.1.5
 *		2B2403030208010105
 * brainpoolP224t1
 *		1.3.36.3.3.2.8.1.1.6
 *		2B2403030208010106
 * brainpoolP256r1
 *		1.3.36.3.3.2.8.1.1.7
 *		2B2403030208010107
 * brainpoolP256t1
 *		1.3.36.3.3.2.8.1.1.8
 *		2B2403030208010108
 * brainpoolP320r1
 *		1.3.36.3.3.2.8.1.1.9
 *		2B2403030208010109
 * brainpoolP320t1
 *		1.3.36.3.3.2.8.1.1.10
 *		2B240303020801010A
 * brainpoolP384r1
 *		1.3.36.3.3.2.8.1.1.11
 *		2B240303020801010B
 * brainpoolP384t1
 *		1.3.36.3.3.2.8.1.1.12
 *		2B240303020801010C
 * brainpoolP512r1
 *		1.3.36.3.3.2.8.1.1.13
 *		2B240303020801010D
 * brainpoolP512t1
 *		1.3.36.3.3.2.8.1.1.14
 *		2B240303020801010E
 * prime192
 *		1.2.840.10045.3.1.1
 *		2A8648CE3D030101
 * secp224
 *		1.3.132.0.33
 *		2B81040021
 * prime256
 *		1.2.840.10045.3.1.7
 *		2A8648CE3D030107
 * secp384
 *		1.3.132.0.34
 *		2B81040022
 * secp521
 *		1.3.132.0.35
 *		2B81040023
 */

CK_ULONG total_assertions = 65;

typedef struct ec_struct {
		CK_VOID_PTR curve;
		CK_ULONG size;
}_ec_struct;

/* Supported Elliptic Curves */
#define NUMEC		13
CK_BYTE brainpoolP160r1[] = { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x01 };
CK_BYTE brainpoolP192r1[] = { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x03 };
CK_BYTE brainpoolP224r1[] = { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x05 };
CK_BYTE brainpoolP256r1[] = { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07 };
CK_BYTE brainpoolP320r1[] = { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x09 };
CK_BYTE brainpoolP384r1[] = { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B };
CK_BYTE brainpoolP512r1[] = { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D };
CK_BYTE brainpoolP512t1[] = { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0E };
CK_BYTE prime192[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01 };
CK_BYTE secp224[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x21 };
CK_BYTE prime256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
CK_BYTE secp384[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
CK_BYTE secp521[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 };

_ec_struct der_ec_supported[NUMEC] = {
	{ &brainpoolP160r1, sizeof(brainpoolP160r1)},
	{ &brainpoolP192r1, sizeof(brainpoolP192r1)},
	{ &brainpoolP224r1, sizeof(brainpoolP224r1)},
	{ &brainpoolP256r1, sizeof(brainpoolP256r1)},
	{ &brainpoolP320r1, sizeof(brainpoolP320r1)},
	{ &brainpoolP384r1, sizeof(brainpoolP384r1)},
	{ &brainpoolP512r1, sizeof(brainpoolP512r1)},
	{ &brainpoolP512t1, sizeof(brainpoolP512t1)},
	{ &prime192, sizeof(prime192)},
	{ &secp224, sizeof(secp224)},
	{ &prime256, sizeof(prime256)},
	{ &secp384, sizeof(secp384)},
	{ &secp521, sizeof(secp521)}
};

/* Invalid curves */
#define NUMECINVAL	4
CK_BYTE invalidCurve[] = { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x08, 0x08, 0x01, 0x01, 0x01 };
CK_BYTE invalidLen1[] = { 0x06, 0x0A, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x01 };
CK_BYTE invalidLen2[] = { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01 };
CK_BYTE invalidOIDfield[] = { 0x05, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x01 };

_ec_struct der_ec_notsupported[NUMECINVAL] = {
	{&invalidCurve, sizeof(invalidCurve)},
	{&invalidLen1, sizeof(invalidLen1)},
	{&invalidLen2, sizeof(invalidLen2)},
	{&invalidOIDfield, sizeof(invalidOIDfield)}
};

typedef struct signVerifyParam {
	CK_MECHANISM_TYPE	mechtype;
	CK_ULONG		inputlen;
}_signVerifyParam;


_signVerifyParam signVerifyInput[] = {
	{ CKM_ECDSA, 20 },
	{ CKM_ECDSA, 32 },
	{ CKM_ECDSA, 48 },
	{ CKM_ECDSA, 64 }
};

CK_RV
run_GenerateSignVerifyECC(CK_SESSION_HANDLE session, CK_MECHANISM_TYPE mechType, CK_ULONG inputlen, CK_OBJECT_HANDLE priv_key, CK_OBJECT_HANDLE publ_key)
{
	CK_MECHANISM		mech2;
	CK_BYTE_PTR		data = NULL, signature = NULL;
	CK_ULONG		i, signaturelen;
	CK_MECHANISM_INFO	mech_info;
	CK_RV rc;

	testcase_begin("Starting with mechtype='%s', inputlen=%lu", p11_get_ckm(mechType), inputlen);

	mech2.mechanism	= mechType;
	mech2.ulParameterLen = 0;
	mech2.pParameter = NULL;

	/* query the slot, check if this mech if supported */
	rc = funcs->C_GetMechanismInfo(SLOT_ID, mech2.mechanism, &mech_info);
	if (rc != CKR_OK) {
		if (rc == CKR_MECHANISM_INVALID) {
			/* no support for EC key gen? skip */
			testcase_skip("Slot %u doesn't support %s",
				(unsigned int) SLOT_ID, p11_get_ckm(mechType));
			goto testcase_cleanup;
		}
		else {
			testcase_error("C_GetMechanismInfo() rc = %s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}
	}

	data = calloc(sizeof(CK_BYTE), inputlen);
	if (data == NULL) {
		testcase_error("Can't allocate memory for %lu bytes",
				sizeof(CK_BYTE) * inputlen);
		rc = -1;
		goto testcase_cleanup;
	}

	for (i = 0; i < inputlen; i++) {
		data[i] = (i + 1) % 255;
	}

	rc = funcs->C_SignInit(session, &mech2, priv_key);
	if (rc != CKR_OK) {
		testcase_error("C_SignInit rc=%s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	/* get signature length */
	rc = funcs->C_Sign(session, data, inputlen, NULL, &signaturelen);
	if (rc != CKR_OK) {
		testcase_error("C_Sign rc=%s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	signature = calloc(sizeof(CK_BYTE), signaturelen);
	if (signature == NULL) {
		testcase_error("Can't allocate memory for %lu bytes",
						sizeof(CK_BYTE) * signaturelen);
		rc = -1;
		goto testcase_cleanup;
	}

	rc = funcs->C_Sign(session, data, inputlen, signature, &signaturelen);
	if (rc != CKR_OK) {
		testcase_error("C_Sign rc=%s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	/****** Verify *******/
	rc = funcs->C_VerifyInit(session, &mech2, publ_key);
	if (rc != CKR_OK) {
		testcase_error("C_VerifyInit rc=%s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	rc = funcs->C_Verify(session, data, inputlen, signature, signaturelen);
	if (rc != CKR_OK) {
		testcase_error("C_Verify rc=%s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	// corrupt the signature and re-verify
	memcpy (signature, "ABCDEFGHIJKLMNOPQRSTUV", 26);

	rc = funcs->C_VerifyInit(session, &mech2, publ_key);
	if (rc != CKR_OK) {
		testcase_error("C_VerifyInit rc=%s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	rc = funcs->C_Verify(session, data, inputlen, signature, signaturelen);
	if (rc != CKR_SIGNATURE_INVALID) {
		testcase_error("C_Verify rc=%s", p11_get_ckr(rc));
		PRINT_ERR("		Expected CKR_SIGNATURE_INVALID\n");
		goto testcase_cleanup;
	}

	rc = CKR_OK;

testcase_cleanup:
	if(data)
		free(data);
	if(signature)
		free(signature);

	return rc;
}

CK_RV
run_GenerateECCKeyPairSignVerify()
{
	CK_MECHANISM		mech;
	CK_OBJECT_HANDLE	publ_key, priv_key;
	CK_SESSION_HANDLE	session;
	CK_BYTE			user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG		user_pin_len, i, j;
	CK_FLAGS		flags;
	CK_MECHANISM_INFO	mech_info;
	CK_RV rc;

	testcase_begin("Starting ECC generate key pair.");

	testcase_rw_session();
	testcase_user_login();

	mech.mechanism	= CKM_EC_KEY_PAIR_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter	= NULL;

	/* query the slot, check if this mech is supported */
	rc = funcs->C_GetMechanismInfo(SLOT_ID, mech.mechanism, &mech_info);
	if (rc != CKR_OK) {
		if (rc == CKR_MECHANISM_INVALID) {
			/* no support for EC key gen? skip */
			testcase_skip("Slot %u doesn't support CKM_EC_KEY_PAIR_GEN",
				(unsigned int) SLOT_ID);
			goto testcase_cleanup;
		}
		else {
			testcase_error("C_GetMechanismInfo() rc = %s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}
	}

	for (i = 0; i < NUMEC; i++) {

		if (!(is_ep11_token(SLOT_ID))) {
			if (!memcmp(der_ec_supported[i].curve, brainpoolP512t1,
			    sizeof(brainpoolP512t1))) {
				testcase_skip("Slot %u doesn't support this curve", (unsigned int)SLOT_ID);
				continue;
			}
		}

		CK_ATTRIBUTE ec_attr[] =
		{
			{CKA_ECDSA_PARAMS, der_ec_supported[i].curve, der_ec_supported[i].size}
		};

		rc = funcs->C_GenerateKeyPair(session, &mech, ec_attr, 1, NULL, 0, &publ_key, &priv_key );
		testcase_new_assertion();
		if (rc != CKR_OK) {
			testcase_fail("C_GenerateKeyPair with valid input failed at i=%lu, rc=%s", i, p11_get_ckr(rc));
			goto testcase_cleanup;
		}
		testcase_pass("*Generate supported key pair index=%lu passed.", i);

		for (j = 0; j < (sizeof(signVerifyInput) / sizeof(_signVerifyParam)); j++) {
			testcase_new_assertion();
			rc = run_GenerateSignVerifyECC(
					session,
					signVerifyInput[j].mechtype,
					signVerifyInput[j].inputlen,
					priv_key,
					publ_key);
			if (rc != 0) {
				testcase_fail("run_GenerateSignVerifyECC failed index=%lu.", j);
				goto testcase_cleanup;
			}
			testcase_pass("*Sign & verify i=%lu, j=%lu passed.", i, j);
		}
	}

	for (i = 0; i < NUMECINVAL; i++) {
		CK_ATTRIBUTE ec_attr[] =
		{
			{CKA_ECDSA_PARAMS, der_ec_notsupported[i].curve, der_ec_notsupported[i].size}
		};

		rc = funcs->C_GenerateKeyPair(session, &mech, ec_attr, 1, NULL, 0, &publ_key, &priv_key );
		testcase_new_assertion();
		if (rc == CKR_OK) {
			testcase_fail("C_GenerateKeyPair with invalid input failed at i=%lu", i);
			goto testcase_cleanup;
		}
		testcase_pass("*Generate unsupported key pair index=%lu passed.", i);
	}

	rc = CKR_OK;

testcase_cleanup:
	testcase_close_session();

	return rc;
}

int
main(int argc, char **argv)
{
	CK_C_INITIALIZE_ARGS cinit_args;
	int rc;
	CK_RV rv;

	rc = do_ParseArgs(argc, argv);
	if ( rc != 1)
		return rc;

	printf("Using slot #%lu...\n\n", SLOT_ID );
	printf("With option: no_init: %d\n", no_init);

	rc = do_GetFunctionList();
	if (!rc) {
		PRINT_ERR("ERROR do_GetFunctionList() Failed , rc = 0x%0x\n", rc);
		return rc;
	}

	memset( &cinit_args, 0x0, sizeof(cinit_args) );
	cinit_args.flags = CKF_OS_LOCKING_OK;

	// SAB Add calls to ALL functions before the C_Initialize gets hit

	funcs->C_Initialize( &cinit_args );

	{
		CK_SESSION_HANDLE  hsess = 0;

		rc = funcs->C_GetFunctionStatus(hsess);
		if (rc  != CKR_FUNCTION_NOT_PARALLEL)
			return rc;

		rc = funcs->C_CancelFunction(hsess);
		if (rc  != CKR_FUNCTION_NOT_PARALLEL)
			return rc;
	}

	testcase_setup(total_assertions);

	rv = run_GenerateECCKeyPairSignVerify();

	testcase_print_result();

	/* make sure we return non-zero if rv is non-zero */
	return ((rv==0) || (rv % 256) ? rv : -1);
}
