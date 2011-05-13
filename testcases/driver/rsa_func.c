// File: rsa_func.c
//

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"



//
// This function should test:
//  * RSA Key Generation, CKM_RSA_PKCS_KEY_PAIR_GEN
//  * RSA Encryption, mechanism chosen by the caller
//  * RSA Decryption, mechanism chosen by the caller
//
// Key generation parameters:
//  * @mechtype is the encryption/decryption mechanism to use
//  * @publ_exp is a byte array with the public exponent
//  * @publ_explen is the length for the @publ_exp byte array
//  * @mod_bits is the lengt for the modulus in bits
//
// Data encryption parameters:
//  * @inputlen is the length for the data to be encrypted/decrypted
//  * @inplace true means we use the same buffer for both input and output in
//             the encrypt/decrypt ops
CK_RV do_GenerateEncryptDecryptRSA(
                CK_MECHANISM_TYPE   mechtype,
                CK_ULONG            mod_bits,
                CK_ULONG            publ_explen,
                CK_BYTE_PTR         publ_exp,
                CK_ULONG            inputlen,
                CK_BBOOL            inplace)
{
        CK_SESSION_HANDLE   session;
        CK_FLAGS            flags;
        CK_BYTE             user_pin[PKCS11_MAX_PIN_LEN];
        CK_ULONG            user_pin_len;
        CK_MECHANISM        mech1, mech2;
        CK_MECHANISM_INFO   mech_info;
        CK_BBOOL            testcase_skip = FALSE;
        CK_RV               retval, rc = CKR_OK;

        //
        CK_OBJECT_HANDLE        publ_key, priv_key;
        CK_ATTRIBUTE            pub_tmpl[] = {
                                  {CKA_MODULUS_BITS,    &mod_bits, sizeof(mod_bits) },
                                  {CKA_PUBLIC_EXPONENT, publ_exp,  publ_explen     }
                                };
        CK_BYTE_PTR             cleartxt = NULL,
                                ciphertxt = NULL;
        CK_ULONG                encryptlen,
                                decryptlen;
        char                    *s;
        CK_ULONG                i;

        if ( p11_ahex_dump(&s, publ_exp, publ_explen) == NULL) {
                testcase_error("p11_ahex_dump() failed");
                rc = -1;
                goto testcase_cleanup;
        }

        testcase_begin("Starting with mechtype='%s', publ_exp='%s', mod_bits='%lu', inputlen='%lu', inplace='%u'",
                        p11_get_ckm(mechtype), s, mod_bits, inputlen, (unsigned int) inplace);
        free(s);

        testcase_rw_session();
        testcase_user_login();

        mech1.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
        mech1.ulParameterLen = 0;
        mech1.pParameter     = NULL;

        /* query the slot, check if this mech, length is supported */
        rc = funcs->C_GetMechanismInfo(SLOT_ID, mech1.mechanism, &mech_info);
        if (rc != CKR_OK) {
                if (rc == CKR_MECHANISM_INVALID) {
                        /* no support for PKCS RSA key gen? skip */
                        testcase_skip("Slot %u doesn't support CKM_RSA_PKCS_KEY_PAIR_GEN",
                                        (unsigned int) SLOT_ID);
                        goto testcase_cleanup;
                }
                else {
                        testcase_error("C_GetMechanismInfo() rc = %s", p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
        }
        else {
                if ( (mod_bits < mech_info.ulMinKeySize) ||
                     (mod_bits > mech_info.ulMaxKeySize) ) {
                        testcase_skip("Requested bit length outside advertised range (%lu, %lu)",
                                        mech_info.ulMinKeySize, mech_info.ulMaxKeySize);
                        goto testcase_cleanup;
                }
        }

        mech2.mechanism = mechtype;
        mech2.ulParameterLen = 0;
        mech2.pParameter = NULL;

        rc = funcs->C_GetMechanismInfo(SLOT_ID, mech2.mechanism, &mech_info);
        if (rc != CKR_OK) {
                if (rc == CKR_MECHANISM_INVALID) {
                        /* no support for specified mech? skip */
                        testcase_skip("Slot %u doesn't support %s",
                                        (unsigned int) SLOT_ID, p11_get_ckm(mechtype));
                        goto testcase_cleanup;
                }
                else {
                        testcase_error("C_GetMechanismInfo() rc = %s", p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
        }
        else {
                if ( (mod_bits < mech_info.ulMinKeySize) ||
                     (mod_bits > mech_info.ulMaxKeySize) ) {
                        testcase_skip("Requested key bit length outside of %s range (%lu, %lu)",
                                        p11_get_ckm(mechtype), mech_info.ulMinKeySize,
                                        mech_info.ulMaxKeySize);
                        goto testcase_cleanup;
                }
                if ( !(mech_info.flags & CKF_ENCRYPT) ) {
                        testcase_skip("Token does not support CKF_ENCRYPT in the %s mechanism",
                                        p11_get_ckm(mechtype));
                        goto testcase_cleanup;
                }
                if ( !(mech_info.flags & CKF_DECRYPT) ) {
                        testcase_skip("Token does not support CKF_DECRYPT in %s mechanism",
                                        p11_get_ckm(mechtype));
                        goto testcase_cleanup;
                }
        }


        rc = funcs->C_GenerateKeyPair(session, &mech1,
                        pub_tmpl, 2, NULL, 0,
                        &publ_key, &priv_key );

        if (rc != CKR_OK) {
                if (rc == CKR_TEMPLATE_INCONSISTENT) {
                        testcase_skip("Token can't generate key with provided template (this is usually ok for non-standard public exponents)");
                        goto testcase_cleanup;
                }
                else {
                        testcase_fail("C_GenerateKeyPair() rc = %s",
                                        p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
        }

        /* TODO: Check flags for generated key pair     */


        cleartxt = calloc(sizeof(CK_BYTE), inputlen);
        if (cleartxt == NULL) {
                testcase_fail("Can't allocate memory for %lu bytes",
                                sizeof(CK_BYTE) * inputlen);
                rc = -1;
                goto testcase_cleanup;
        }

        for (i = 0; i < inputlen; i++) {
                cleartxt[i] = (i + 1)  % 255;
        }

        rc = funcs->C_EncryptInit(session, &mech2, publ_key);

        if (rc != CKR_OK) {
                testcase_fail("C_EncryptInit() rc = %s",
                                p11_get_ckr(rc));
                goto testcase_cleanup;
        }

        /* excercise the "length only" semantics */
        rc = funcs->C_Encrypt(session, cleartxt, inputlen,
                        NULL, &encryptlen);
        if (rc != CKR_OK) {
                testcase_fail("C_Encrypt() rc = %s",
                                p11_get_ckr(rc));
                goto testcase_cleanup;
        }

        /* We're doing  RSA Encrypt... Output len *has* to be at least  *
         * the RSA key modulus, so do the math ourselves and check if   *
         * the size being returned is really sufficient                 */
        if ( encryptlen < ( (mod_bits + 7) / 8) ) {
                testcase_fail("C_Encrypt() (length only mode) returned output buffer too small (got %lu, expected >= %lu)",
                                encryptlen, (mod_bits + 7) / 8);
                rc = -1;
                goto testcase_cleanup;
        }

        /* allocate buf if we're not doing inplace crypt/decrypt */
        if (!inplace) {
                ciphertxt = calloc(sizeof(CK_BYTE), encryptlen);
                if (ciphertxt == NULL) {
                        testcase_fail("Can't allocate memory for %lu bytes",
                                        sizeof(CK_BYTE) * encryptlen);
                        rc = -1;
                        goto testcase_cleanup;
                }
        }
        else if (encryptlen > inputlen) {
                /* must extend storage for inplace encrypt */
                cleartxt = realloc(cleartxt, encryptlen * sizeof (CK_BYTE));
                if (cleartxt == NULL) {
                        testcase_fail("Can't re-allocate memory for %lu bytes",
                                        sizeof(CK_BYTE) * encryptlen);
                        rc = -1;
                        goto testcase_cleanup;
                }
        }

        rc = funcs->C_Encrypt(session, cleartxt, inputlen,
                        inplace ? cleartxt : ciphertxt,
                        &encryptlen);
        if (rc != CKR_OK) {
                testcase_fail("C_Encrypt() rc = %s",
                                p11_get_ckr(rc));
                goto testcase_cleanup;
        }

        /* repeat the length test, now with tight boundaries */
        if ( encryptlen != ( (mod_bits + 7) / 8) ) {
                testcase_fail("C_Encrypt() returned output buffer too small (got %lu, expected %lu)",
                                encryptlen, (mod_bits + 7) / 8);
                if ( p11_ahex_dump(&s, inplace ? cleartxt : ciphertxt, encryptlen) != NULL) {
                        testcase_notice("full dump for encrypted value:\n%s", s);
                        free(s);
                }
                rc = -1;
                goto testcase_cleanup;
        }

        rc = funcs->C_DecryptInit(session, &mech2, priv_key);
        if (rc != CKR_OK) {
                testcase_fail("C_DecryptInit() rc = %s",
                                p11_get_ckr(rc));
                goto testcase_cleanup;
        }

        /* exercise the "length only" semantics for decrypt */
        rc = funcs->C_Decrypt(session,
                        inplace? cleartxt : ciphertxt,
                        encryptlen,
                        NULL, &decryptlen);
        if (rc != CKR_OK) {
                testcase_fail("C_Decrypt() rc = %s",
                                p11_get_ckr(rc));
                goto testcase_cleanup;
        }

        /* check the predicted decrypt length */
        if (decryptlen < inputlen) {
                testcase_fail("C_Decrypt() (length only mode) returned output buffer too small (got %lu, expected >= %lu)",
                                decryptlen, inputlen);
                rc = -1;
                goto testcase_cleanup;
        }

        /* need to make sure we have sufficient storage for decrypt */
        cleartxt = realloc(cleartxt, decryptlen * sizeof(CK_BYTE));
        if (cleartxt == NULL) {
                testcase_fail("Can't re-allocate memory for %lu bytes",
                                sizeof(CK_BYTE) * decryptlen);
                rc = -1;
                goto testcase_cleanup;
        }


        rc = funcs->C_Decrypt(session,
                        inplace ? cleartxt : ciphertxt,
                        encryptlen,
                        cleartxt, &decryptlen);
        if (rc != CKR_OK) {
                testcase_fail("C_Decrypt() rc = %s",
                                p11_get_ckr(rc));
                goto testcase_cleanup;
        }

        /* for CKM_RSA_X_509, we must take the padding out by ourselves         *
         * use inputlen for that                                                */
        if (mechtype == CKM_RSA_X_509) {
                /* quick sanity check */
                if (inputlen > decryptlen) {
                        testcase_fail("C_Decrypt() returned invalid output buffer len (got %lu, expected >= %lu",
                                        decryptlen, inputlen);
                        if ( p11_ahex_dump(&s, cleartxt, decryptlen) != NULL) {
                                testcase_notice("full dump for decrypted value:\n%s", s);
                                free(s);
                        }
                        rc = -1;
                        goto testcase_cleanup;
                }

                memmove(cleartxt, cleartxt + decryptlen - inputlen, inputlen);

                /* now adjust decryptlen for later comparisson */
                decryptlen = inputlen;
        }
        else {
                /* check out buffer length again, tight boundaries */
                if (decryptlen != inputlen) {
                        testcase_fail("C_Decrypt() returned output buffer too small (got %lu, expected %lu)",
                                        decryptlen, inputlen);
                        if ( p11_ahex_dump(&s, cleartxt, decryptlen) != NULL) {
                                testcase_notice("full dump for decrypted value:\n%s", s);
                                free(s);
                        }
                        rc = -1;
                        goto testcase_cleanup;
                }
        }

        /* Now check byte-by-byte */
        for (i = 0; i < decryptlen; i++) {
                if (cleartxt[i] != (i + 1) % 255) {
                        testcase_fail("C_Decrypt() decryption error at byte '%lu'", i);
                        if ( p11_ahex_dump(&s, cleartxt, decryptlen) != NULL) {
                                testcase_notice("full dump for decrypted value:\n%s", s);
                                free(s);
                        }
                        rc = -1;
                        goto testcase_cleanup;
                }
        }



testcase_cleanup:
        if ( rc == CKR_OK && !testcase_skip) {
                testcase_pass("Looks okay...");
        }

        retval = rc;

        testcase_close_session();

        if (cleartxt) free (cleartxt);
        if (ciphertxt) free (ciphertxt);

        return retval | rc;
}

//
// This function should test:
//  * RSA Key Generation, using CKM_RSA_PKCS_KEY_PAIR_GEN
//  * RSA Sign (optionally with Recover), mechanism chosen by the caller
//  * RSA Verify (optionally with Recover), mechanism chosen by the caller
//
// Key generation parameters:
//  * @mechtype is the sign/verify (recover) mechanism to use
//  * @publ_exp is a byte array with the public exponent
//  * @publ_explen is the length for the @publ_exp byte array
//  * @mod_bits is the lengt for the modulus in bits
//
// Data encryption parameters:
//  * @inputlen is the length for the data to be signed and verified
//  * @recover true means we will test the "Recover" version for
//    signing and verifying
CK_RV do_GenerateSignVerifyRSA(
                CK_MECHANISM_TYPE   mechtype,
                CK_ULONG            mod_bits,
                CK_ULONG            publ_explen,
                CK_BYTE_PTR         publ_exp,
                CK_ULONG            inputlen,
                CK_BBOOL            recover)
{
        CK_SESSION_HANDLE   session;
        CK_FLAGS            flags;
        CK_BYTE             user_pin[PKCS11_MAX_PIN_LEN];
        CK_ULONG            user_pin_len;
        CK_MECHANISM        mech1, mech2;
        CK_MECHANISM_INFO   mech_info;
        CK_BBOOL            testcase_skip = FALSE;
        CK_RV               retval, rc = CKR_OK;


        //
        CK_OBJECT_HANDLE        publ_key, priv_key;
        CK_ATTRIBUTE            pub_tmpl[] = {
                                  {CKA_MODULUS_BITS,    &mod_bits, sizeof(mod_bits) },
                                  {CKA_PUBLIC_EXPONENT, publ_exp,  publ_explen     }
                                };
        CK_BYTE_PTR             indata = NULL,
                                recoverdata = NULL,
                                signature = NULL;
        CK_ULONG                recoverdatalen,
                                signaturelen;
        char                    *s;
        CK_ULONG                i;

        if ( p11_ahex_dump(&s, publ_exp, publ_explen) == NULL) {
                testcase_error("p11_ahex_dump() failed");
                rc = -1;
                goto testcase_cleanup;
        }

        testcase_begin("Starting with mechtype='%s', publ_exp='%s', mod_bits='%lu', inputlen='%lu', recover='%u'",
                        p11_get_ckm(mechtype), s, mod_bits, inputlen, (unsigned int) recover);
        free(s);

        testcase_rw_session();
        testcase_user_login();

        mech1.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
        mech1.ulParameterLen = 0;
        mech1.pParameter     = NULL;

        /* query the slot, check if this mech, length is supported */
        rc = funcs->C_GetMechanismInfo(SLOT_ID, mech1.mechanism, &mech_info);
        if (rc != CKR_OK) {
                if (rc == CKR_MECHANISM_INVALID) {
                        /* no support for PKCS RSA key gen? skip */
                        testcase_skip("Slot %u doesn't support CKM_RSA_PKCS_KEY_PAIR_GEN",
                                        (unsigned int) SLOT_ID);
                        goto testcase_cleanup;
                }
                else {
                        testcase_error("C_GetMechanismInfo() rc = %s", p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
        }
        else {
                if ( (mod_bits < mech_info.ulMinKeySize) ||
                     (mod_bits > mech_info.ulMaxKeySize) ) {
                        testcase_skip("Requested bit length outside advertised range (%lu, %lu)",
                                        mech_info.ulMinKeySize, mech_info.ulMaxKeySize);
                        goto testcase_cleanup;
                }
        }

        mech2.mechanism = mechtype;
        mech2.ulParameterLen = 0;
        mech2.pParameter = NULL;

        rc = funcs->C_GetMechanismInfo(SLOT_ID, mech2.mechanism, &mech_info);
        if (rc != CKR_OK) {
                if (rc == CKR_MECHANISM_INVALID) {
                        /* no support for specified mech? skip */
                        testcase_skip("Slot %u doesn't support %s",
                                        (unsigned int) SLOT_ID, p11_get_ckm(mechtype));
                        goto testcase_cleanup;
                }
                else {
                        testcase_error("C_GetMechanismInfo() rc = %s", p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
        }
        else {
                if ( (mod_bits < mech_info.ulMinKeySize) ||
                     (mod_bits > mech_info.ulMaxKeySize) ) {
                        testcase_skip("Requested key bit length outside of %s range (%lu, %lu)",
                                        p11_get_ckm(mechtype), mech_info.ulMinKeySize,
                                        mech_info.ulMaxKeySize);
                        goto testcase_cleanup;
                }
                if ( !(mech_info.flags & (recover ? CKF_SIGN_RECOVER : CKF_SIGN)) ) {
                        if (recover)
                                testcase_skip("Token does not support CKF_SIGN_RECOVER in the %s mechanism",
                                                p11_get_ckm(mechtype));
                        else
                                testcase_skip("Token does not support CKF_SIGN in the %s mechanism",
                                                p11_get_ckm(mechtype));
                        goto testcase_cleanup;
                }
                if ( !(mech_info.flags & (recover ? CKF_VERIFY_RECOVER : CKF_VERIFY)) ) {
                        if (recover)
                                testcase_skip("Token does not support CKF_VERIFY_RECOVER in the %s mechanism",
                                                p11_get_ckm(mechtype));
                        else
                                testcase_skip("Token does not support CKF_VERIFY in the %s mechanism",
                                                p11_get_ckm(mechtype));
                        goto testcase_cleanup;
                }

        }


        rc = funcs->C_GenerateKeyPair(session, &mech1,
                        pub_tmpl, 2, NULL, 0,
                        &publ_key, &priv_key );

        if (rc != CKR_OK) {
                if (rc == CKR_TEMPLATE_INCONSISTENT) {
                        testcase_skip("Token can't generate key with provided template (this is usually ok for non-standard public exponents)");
                        goto testcase_cleanup;
                }
                else {
                        testcase_fail("C_GenerateKeyPair() rc = %s",
                                        p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
        }

        /* TODO: Check flags for generated key pair     */


        indata = calloc(sizeof(CK_BYTE), inputlen);
        if (indata == NULL) {
                testcase_fail("Can't allocate memory for %lu bytes",
                                sizeof(CK_BYTE) * inputlen);
                rc = -1;
                goto testcase_cleanup;
        }

        for (i = 0; i < inputlen; i++) {
                indata[i] = (i + 1)  % 255;
        }

        if (!recover) {
                rc = funcs->C_SignInit(session, &mech2, priv_key);
                if (rc != CKR_OK) {
                        testcase_fail("C_SignInit() rc = %s",
                                        p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
        }
        else {
                rc = funcs->C_SignRecoverInit(session, &mech2, priv_key);
                if (rc != CKR_OK) {
                        testcase_fail("C_SignRecoverInit() rc = %s",
                                        p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
        }

        /* excercise the "length only" semantics */
        if (!recover) {
                rc = funcs->C_Sign(session, indata, inputlen,
                                NULL, &signaturelen);
                if (rc != CKR_OK) {
                        testcase_fail("C_Sign() rc = %s",
                                        p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
        }
        else {
                rc = funcs->C_SignRecover(session, indata, inputlen,
                                NULL, &signaturelen);
                if (rc != CKR_OK) {
                        testcase_fail("C_SignRecover() rc = %s",
                                        p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
        }


        /* We're doing RSA Sign... Output len *has* to be at least      *
         * the RSA key modulus, so do the math ourselves and check if   *
         * the size being returned is really sufficient                 */
        if ( signaturelen < ( (mod_bits + 7) / 8) ) {
                if (!recover) {
                        testcase_fail("C_Sign() (length only mode) returned output buffer too small (got %lu, expected >= %lu)",
                                        signaturelen, (mod_bits + 7) / 8);
                }
                else {
                        testcase_fail("C_SignRecover() (length only mode) returned output buffer too small (got %lu, expected >= %lu)",
                                        signaturelen, (mod_bits + 7) / 8);
                }
                rc = -1;
                goto testcase_cleanup;
        }

        signature = calloc(sizeof(CK_BYTE), signaturelen);
        if (signature == NULL) {
                testcase_fail("Can't allocate memory for %lu bytes",
                                sizeof(CK_BYTE) * signaturelen);
                rc = -1;
                goto testcase_cleanup;
        }

        if (!recover) {
                rc = funcs->C_Sign(session, indata, inputlen,
                                signature, &signaturelen);
                if (rc != CKR_OK) {
                        testcase_fail("C_Sign() rc = %s",
                                        p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
        }
        else {
                rc = funcs->C_SignRecover(session, indata, inputlen,
                                signature, &signaturelen);
                if (rc != CKR_OK) {
                        testcase_fail("C_SignRecover() rc = %s",
                                        p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
        }

        /* repeat the length test, now with tight boundaries */
        if ( signaturelen != ( (mod_bits + 7) / 8) ) {
                if (!recover) {
                        testcase_fail("C_Sign() returned output buffer too small (got %lu, expected %lu)",
                                        signaturelen, (mod_bits + 7) / 8);
                }
                else {
                        testcase_fail("C_SignRecover() returned output buffer too small (got %lu, expected %lu)",
                                        signaturelen, (mod_bits + 7) / 8);
                }
                if ( p11_ahex_dump(&s, signature, signaturelen) != NULL) {
                        testcase_notice("full dump for signature value:\n%s", s);
                        free(s);
                }
                rc = -1;
                goto testcase_cleanup;
        }

        if (!recover) {
                rc = funcs->C_VerifyInit(session, &mech2, publ_key);
                if (rc != CKR_OK) {
                        testcase_fail("C_VerifyInit() rc = %s",
                                        p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
        }
        else {
                rc = funcs->C_VerifyRecoverInit(session, &mech2, publ_key);
                if (rc != CKR_OK) {
                        testcase_fail("C_VerifyRecoverInit() rc = %s",
                                        p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
        }

        if (!recover) {
                rc = funcs->C_Verify(session,
                                indata, inputlen,
                                signature, signaturelen);
                if (rc != CKR_OK) {
                        testcase_fail("C_Verify() rc = %s",
                                        p11_get_ckr(rc));
                        goto testcase_cleanup;
                }

                /*  TODO: Maybe test invalid signature scenario? */
        }
        else {
                /* exercise the "length only" semantics for recover */
                rc = funcs->C_VerifyRecover(session,
                                signature, signaturelen,
                                NULL, &recoverdatalen);
                if (rc != CKR_OK) {
                        testcase_fail("C_VerifyRecover() rc = %s",
                                        p11_get_ckr(rc));
                        goto testcase_cleanup;
                }


                /* check the predicted recovered data length */
                if (recoverdatalen < inputlen) {
                        testcase_fail("C_VerifyRecover() (length only mode) returned output buffer too small (got %lu, expected >= %lu)",
                                recoverdatalen, inputlen);
                        rc = -1;
                        goto testcase_cleanup;
                }

                recoverdata = calloc(sizeof(CK_BYTE), recoverdatalen);
                if (recoverdata == NULL) {
                        testcase_fail("Can't allocate memory for %lu bytes",
                                        sizeof(CK_BYTE) * recoverdatalen);
                        rc = -1;
                        goto testcase_cleanup;
                }


                rc = funcs->C_VerifyRecover(session,
                                signature, signaturelen,
                                recoverdata, &recoverdatalen);
                if (rc != CKR_OK) {
                        testcase_fail("C_VerifyRecover() rc = %s",
                                        p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
                /* for CKM_RSA_X_509, we must take the padding out by ourselves         *
                 * use inputlen for that                                                */
                if (mechtype == CKM_RSA_X_509) {
                        /* quick sanity check */
                        if (inputlen > recoverdatalen) {
                                testcase_fail("C_VerifyRecover() returned invalid output buffer len (got %lu, expected >= %lu",
                                                recoverdatalen, inputlen);
                                if ( p11_ahex_dump(&s, recoverdata, recoverdatalen) != NULL) {
                                        testcase_notice("full dump for recovered signature value:\n%s", s);
                                        free(s);
                                }
                                rc = -1;
                                goto testcase_cleanup;
                        }
                        memmove(recoverdata, recoverdata + recoverdatalen - inputlen, inputlen);
                        /* now adjust decryptlen for later comparisson */
                        recoverdatalen = inputlen;
                }
                else {
                        /* check out buffer length again, tight boundaries */
                        if (recoverdatalen != inputlen) {
                                testcase_fail("C_VerifyRecover() returned output buffer too small (got %lu, expected %lu)",
                                                recoverdatalen, inputlen);
                                if ( p11_ahex_dump(&s, recoverdata, recoverdatalen) != NULL) {
                                        testcase_notice("full dump for recovered signature value:\n%s", s);
                                        free(s);
                                }
                                rc = -1;
                                goto testcase_cleanup;
                        }
                }

                /* Now check byte-by-byte */
                for (i = 0; i < recoverdatalen; i++) {
                        if (recoverdata[i] != (i + 1) % 255) {
                                testcase_fail("C_VerifyRecover() signature data recovery error at byte '%lu'", i);
                                if ( p11_ahex_dump(&s, recoverdata, recoverdatalen) != NULL) {
                                        testcase_notice("full dump for recovered signature value:\n%s", s);
                                        free(s);
                                }
                                rc = -1;
                                goto testcase_cleanup;
                        }
                }
        }



testcase_cleanup:
        if ( rc == CKR_OK && !testcase_skip) {
                testcase_pass("Looks okay...");
        }

        retval = rc;

        testcase_close_session();

        if (indata) free (indata);
        if (signature) free (signature);
        if (recoverdata) free (recoverdata);

        return retval | rc;
}

//
// Allocates memory on *dst and prints members
// of zero-terminated CK_ULONG array
// *dst must be freed by the caller
char *
my_ulong_dump(char **dst, CK_ULONG_PTR ptr, CK_ULONG size)
{
    unsigned long i, len;

    if (dst == NULL) {
        return NULL;
    }

    *dst = NULL;

    for (i = 0, len = 0; i < size; i++) {
        if ( (*dst = realloc(*dst, len + 25)) != NULL) {
            if (size == 1) {
                    sprintf(*dst + len, "[%lu]", ptr[i]);
            } else if (i == 0) {
                    sprintf(*dst + len, "[%lu, ", ptr[i]);
            } else if (i == (size - 1)) {
                    sprintf(*dst + len, "%lu]", ptr[i]);
            } else {
                    sprintf(*dst + len, "%lu, ", ptr[i]);
            }
            len = strlen(*dst);
        }
        else {
            break;
        }
    }

    return *dst;
}


//
// This function should test:
//  * RSA Key Generation, using CKM_RSA_PKCS_KEY_PAIR_GEN
//  * RSA Multipart Sign with mechanism chosen by the caller
//  * RSA Multipart Verify with mechanism chosen by the caller
//
// Key generation parameters:
//  * @mechtype is the multipart sign/verify mechanism to use
//  * @publ_exp is a byte array with the public exponent
//  * @publ_explen is the length for the @publ_exp byte array
//  * @mod_bits is the lengt for the modulus in bits
//
// Signing parameters:
//  * @partsnum brings the number of parts for the @partslensa array
//  * @partslens is CK_ULONG array with the sizes for the input
//               parts, e.g., { 10, 20, 30, 40 }
CK_RV do_GenerateMultipartSignVerifyRSA(
                CK_MECHANISM_TYPE   mechtype,
                CK_ULONG            mod_bits,
                CK_ULONG            publ_explen,
                CK_BYTE_PTR         publ_exp,
                CK_ULONG            partsnum,
                CK_ULONG_PTR        partslens)
{
        CK_SESSION_HANDLE   session;
        CK_FLAGS            flags;
        CK_BYTE             user_pin[PKCS11_MAX_PIN_LEN];
        CK_ULONG            user_pin_len;
        CK_MECHANISM        mech1, mech2;
        CK_MECHANISM_INFO   mech_info;
        CK_BBOOL            testcase_skip = FALSE;
        CK_RV               retval, rc = CKR_OK;


        //
        CK_OBJECT_HANDLE        publ_key, priv_key;
        CK_ATTRIBUTE            pub_tmpl[] = {
                                  {CKA_MODULUS_BITS,    &mod_bits, sizeof(mod_bits) },
                                  {CKA_PUBLIC_EXPONENT, publ_exp,  publ_explen     }
                                };
        CK_BYTE_PTR             indata = NULL,
                                signature = NULL;
        CK_ULONG                inputlen,
                                parts,
                                signaturelen;
        char                    *s, *r;
        CK_ULONG                i;

        if ( p11_ahex_dump(&s, publ_exp, publ_explen) == NULL) {
                testcase_error("p11_ahex_dump() failed");
                rc = -1;
                goto testcase_cleanup;
        }

        if ( my_ulong_dump(&r, partslens, partsnum) == NULL) {
                testcase_error("my_ulong_dump() failed");
                rc = -1;
                goto testcase_cleanup;
        }

        testcase_begin("Starting with mechtype='%s', publ_exp='%s', mod_bits='%lu', partslens='%s'",
                        p11_get_ckm(mechtype), s, mod_bits, r);
        free(s);
        free(r);


        testcase_rw_session();
        testcase_user_login();

        mech1.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
        mech1.ulParameterLen = 0;
        mech1.pParameter     = NULL;

        /* query the slot, check if this mech, length is supported */
        rc = funcs->C_GetMechanismInfo(SLOT_ID, mech1.mechanism, &mech_info);
        if (rc != CKR_OK) {
                if (rc == CKR_MECHANISM_INVALID) {
                        /* no support for PKCS RSA key gen? skip */
                        testcase_skip("Slot %u doesn't support CKM_RSA_PKCS_KEY_PAIR_GEN",
                                        (unsigned int) SLOT_ID);
                        goto testcase_cleanup;
                }
                else {
                        testcase_error("C_GetMechanismInfo() rc = %s", p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
        }
        else {
                if ( (mod_bits < mech_info.ulMinKeySize) ||
                     (mod_bits > mech_info.ulMaxKeySize) ) {
                        testcase_skip("Requested bit length outside advertised range (%lu, %lu)",
                                        mech_info.ulMinKeySize, mech_info.ulMaxKeySize);
                        goto testcase_cleanup;
                }
        }

        mech2.mechanism = mechtype;
        mech2.ulParameterLen = 0;
        mech2.pParameter = NULL;

        rc = funcs->C_GetMechanismInfo(SLOT_ID, mech2.mechanism, &mech_info);
        if (rc != CKR_OK) {
                if (rc == CKR_MECHANISM_INVALID) {
                        /* no support for specified mech? skip */
                        testcase_skip("Slot %u doesn't support %s",
                                        (unsigned int) SLOT_ID, p11_get_ckm(mechtype));
                        goto testcase_cleanup;
                }
                else {
                        testcase_error("C_GetMechanismInfo() rc = %s", p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
        }
        else {
                if ( (mod_bits < mech_info.ulMinKeySize) ||
                     (mod_bits > mech_info.ulMaxKeySize) ) {
                        testcase_skip("Requested key bit length outside of %s range (%lu, %lu)",
                                        p11_get_ckm(mechtype), mech_info.ulMinKeySize,
                                        mech_info.ulMaxKeySize);
                        goto testcase_cleanup;
                }
                if ( !(mech_info.flags & CKF_SIGN) ) {
                        testcase_skip("Token does not support CKF_SIGN in the %s mechanism",
                                        p11_get_ckm(mechtype));
                        goto testcase_cleanup;
                }
                if ( !(mech_info.flags & CKF_VERIFY) ) {
                        testcase_skip("Token does not support CKF_VERIFY in the %s mechanism",
                                        p11_get_ckm(mechtype));
                        goto testcase_cleanup;
                }

        }

        rc = funcs->C_GenerateKeyPair(session, &mech1,
                        pub_tmpl, 2, NULL, 0,
                        &publ_key, &priv_key );

        if (rc != CKR_OK) {
                if (rc == CKR_TEMPLATE_INCONSISTENT) {
                        testcase_skip("Token can't generate key with provided template "
                                        "(this is usually ok for non-standard public exponents)");
                        goto testcase_cleanup;
                }
                else {
                        testcase_fail("C_GenerateKeyPair() rc = %s",
                                        p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
        }

        /* TODO: Check flags for generated key pair     */

        rc = funcs->C_SignInit(session, &mech2, priv_key);
        if (rc != CKR_OK) {
                testcase_fail("C_SignInit() rc = %s",
                                p11_get_ckr(rc));
                goto testcase_cleanup;
        }

        for (parts = 0, inputlen = 0;
                        parts < partsnum;
                        parts++) {
                if (partslens[parts] > 0) {
                        indata = realloc(indata, partslens[parts]);
                }
                if (indata == NULL) {
                        testcase_fail("Can't re-allocate indata buffer to %lu bytes length",
                                        partslens[parts]);
                        rc = -1;
                        goto testcase_cleanup;
                }

                for (i = 0; i <  partslens[parts]; i++) {
                        indata[i] = (inputlen + i + 1) % 255;
                }

                rc = funcs->C_SignUpdate(session, indata, i);
                if (rc != CKR_OK) {
                        testcase_fail("C_SignUpdate() rc = %s",
                                        p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
        }

        /* Finalize the multi-part sign.. check required signaturelen first */
        rc = funcs->C_SignFinal(session, NULL, &signaturelen);
        if (rc != CKR_OK) {
                testcase_fail("C_SignFinal() rc = %s",
                                p11_get_ckr(rc));
                goto testcase_cleanup;
        }

        signature = calloc(sizeof(CK_BYTE), signaturelen);
        if (signature == NULL) {
                testcase_fail("Can't allocate memory for %lu bytes",
                                sizeof(CK_BYTE) * signaturelen);
                rc = -1;
                goto testcase_cleanup;
        }

        rc = funcs->C_SignFinal(session, signature, &signaturelen);
        if (rc != CKR_OK) {
                testcase_fail("C_SignFinal() rc = %s",
                                p11_get_ckr(rc));
                goto testcase_cleanup;
        }

        /* Now verify the signature */

        rc = funcs->C_VerifyInit(session, &mech2, publ_key);
        if (rc != CKR_OK) {
                testcase_fail("C_VerifyInit() rc = %s",
                                p11_get_ckr(rc));
                goto testcase_cleanup;
        }

        for (parts = 0, inputlen = 0;
                        parts < partsnum;
                        parts++) {
                if (partslens[parts] > 0) {
                        indata = realloc(indata, partslens[parts]);
                }
                if (indata == NULL) {
                        testcase_fail("Can't re-allocate indata buffer to %lu bytes length",
                                        partslens[parts]);
                        rc = -1;
                        goto testcase_cleanup;
                }

                for (i = 0; i <  partslens[parts]; i++) {
                        indata[i] = (inputlen + i + 1) % 255;
                }

                rc = funcs->C_VerifyUpdate(session, indata, i);
                if (rc != CKR_OK) {
                        testcase_fail("C_VerifyUpdate() rc = %s",
                                        p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
        }

        /* Finally, verify the signature */

        rc = funcs->C_VerifyFinal(session, signature, signaturelen);
        if (rc != CKR_OK) {
                testcase_fail("C_VerifyFinal() rc = %s",
                                p11_get_ckr(rc));
                goto testcase_cleanup;
        }

        /*  TODO: Maybe test invalid signature scenario? */

testcase_cleanup:
        if ( rc == CKR_OK && !testcase_skip) {
                testcase_pass("Looks okay...");
        }

        retval = rc;

        testcase_close_session();

        if (indata) free (indata);
        if (signature) free (signature);

        return retval | rc;
}


//
// This function should test:
//  * RSA Key Generation, using CKM_RSA_PKCS_KEY_PAIR_GEN
//  * RSA Public-Key Wrap
//  * RSA Private-Key Unwap
//
// RSA Key generation parameters:
//  * @mechtype is the wrap/unwrap mechanism to use
//  * @publ_exp is a byte array with the public exponent
//  * @publ_explen is the length for the @publ_exp byte array
//  * @mod_bits is the lengt for the modulus in bits
//
// Secret key generation and wrapping parameters:
//  * @keylen is the secret key length to generate
//  * @keytype is the mechanism type used to generate a secret key
CK_RV do_GenerateWrapUnwrapRSA(
                CK_MECHANISM_TYPE   mechtype,
                CK_ULONG            mod_bits,
                CK_ULONG            publ_explen,
                CK_BYTE_PTR         publ_exp,
                CK_ULONG            keylen,
                CK_MECHANISM_TYPE   keytype)
{
        CK_SESSION_HANDLE   session;
        CK_FLAGS            flags;
        CK_BYTE             user_pin[PKCS11_MAX_PIN_LEN];
        CK_ULONG            user_pin_len;
        CK_MECHANISM        mech1, mech2, mech3;
        CK_MECHANISM_INFO   mech_info;
        CK_BBOOL            testcase_skip = FALSE;
        CK_RV               retval, rc = CKR_OK;


        //
        CK_OBJECT_HANDLE        publ_key, priv_key, secret_key, unwrapped_key;
        CK_ATTRIBUTE            pub_tmpl[] = {
                                  {CKA_MODULUS_BITS,    &mod_bits, sizeof(mod_bits) },
                                  {CKA_PUBLIC_EXPONENT, publ_exp,  publ_explen     }
                                };
        CK_ATTRIBUTE            secret_tmpl[] = {
                                  {CKA_VALUE_LEN, &keylen, sizeof(keylen) }
                                };
        CK_ATTRIBUTE            unwrap_tmpl[] = {
                                  {CKA_CLASS,     NULL, 0},
                                  {CKA_KEY_TYPE,  NULL, 0},
                                  {CKA_VALUE_LEN, NULL, 0}
                                };
        CK_ATTRIBUTE            secret_value[] = {
                                  {CKA_VALUE, NULL, 0}
                                };
        CK_ULONG                s_valuelen = 0;
        CK_ATTRIBUTE            secret_value_len[] = {
                                  {CKA_VALUE_LEN,
                                   &s_valuelen,
                                   sizeof(s_valuelen)}
                                };
        CK_ATTRIBUTE            unwrapped_value[] = {
                                  {CKA_VALUE, NULL, 0}
                                };
        CK_ULONG                u_valuelen = 0;
        CK_ATTRIBUTE            unwrapped_value_len[] = {
                                  {CKA_VALUE_LEN,
                                   &u_valuelen,
                                   sizeof(u_valuelen)}
                                };
        CK_BYTE_PTR             wrapped_key = NULL;
        CK_ULONG                wrapped_keylen;
        char                    *s;
        CK_ULONG                i;

        if ( p11_ahex_dump(&s, publ_exp, publ_explen) == NULL) {
                testcase_error("p11_ahex_dump() failed");
                rc = -1;
                goto testcase_cleanup;
        }

        testcase_begin("Starting with mechtype='%s', publ_exp='%s', mod_bits='%lu', keylen='%lu', keytype='%s'",
                        p11_get_ckm(mechtype), s, mod_bits, keylen, p11_get_ckm(keytype));
        free(s);

        testcase_rw_session();
        testcase_user_login();

        mech1.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
        mech1.ulParameterLen = 0;
        mech1.pParameter     = NULL;

        /* query the slot, check if this mech, length is supported */
        rc = funcs->C_GetMechanismInfo(SLOT_ID, mech1.mechanism, &mech_info);
        if (rc != CKR_OK) {
                if (rc == CKR_MECHANISM_INVALID) {
                        /* no support for PKCS RSA key gen? skip */
                        testcase_skip("Slot %u doesn't support CKM_RSA_PKCS_KEY_PAIR_GEN",
                                        (unsigned int) SLOT_ID);
                        goto testcase_cleanup;
                }
                else {
                        testcase_error("C_GetMechanismInfo() rc = %s", p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
        }
        else {
                if ( (mod_bits < mech_info.ulMinKeySize) ||
                     (mod_bits > mech_info.ulMaxKeySize) ) {
                        testcase_skip("Requested bit length outside advertised range (%lu, %lu)",
                                        mech_info.ulMinKeySize, mech_info.ulMaxKeySize);
                        goto testcase_cleanup;
                }
        }

        mech2.mechanism = keytype;
        mech2.ulParameterLen = 0;
        mech2.pParameter = NULL;

        /* query the slot, check if this mech, length is supported */
        rc = funcs->C_GetMechanismInfo(SLOT_ID, mech2.mechanism, &mech_info);
        if (rc != CKR_OK) {
                if (rc == CKR_MECHANISM_INVALID) {
                        /* We don't support generating this type of secret key - skip */
                        testcase_skip("Slot %u doesn't support %s",
                                        (unsigned int) SLOT_ID, p11_get_ckm(keytype));
                        goto testcase_cleanup;
                }
                else {
                        testcase_error("C_GetMechanismInfo() rc = %s", p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
        }
        else {
                /* Check valid lengths for secret key generation */
                if ( (keylen < mech_info.ulMinKeySize) ||
                     (keylen > mech_info.ulMaxKeySize) ) {
                        testcase_skip("Requested secret key length outside of %s range (%lu, %lu)",
                                        p11_get_ckm(keytype), mech_info.ulMinKeySize,
                                        mech_info.ulMaxKeySize);
                        goto testcase_cleanup;
                }
        }

        mech3.mechanism = mechtype;
        mech3.ulParameterLen = 0;
        mech3.pParameter = NULL;

        rc = funcs->C_GetMechanismInfo(SLOT_ID, mech3.mechanism, &mech_info);
        if (rc != CKR_OK) {
                if (rc == CKR_MECHANISM_INVALID) {
                        /* no support for specified mech? skip */
                        testcase_skip("Slot %u doesn't support %s",
                                        (unsigned int) SLOT_ID, p11_get_ckm(mechtype));
                        goto testcase_cleanup;
                }
                else {
                        testcase_error("C_GetMechanismInfo() rc = %s", p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
        }
        else {
                if ( !(mech_info.flags & CKF_WRAP) ) {
                        testcase_skip("Token does not support CKF_WRAP in the %s mechanism",
                                        p11_get_ckm(mechtype));
                        goto testcase_cleanup;
                }
                if ( !(mech_info.flags & CKF_UNWRAP) ) {
                        testcase_skip("Token does not support CKF_UNWRAP in the %s mechanism",
                                        p11_get_ckm(mechtype));
                        goto testcase_cleanup;
                }

        }


        rc = funcs->C_GenerateKeyPair(session, &mech1,
                        pub_tmpl, 2, NULL, 0,
                        &publ_key, &priv_key );

        if (rc != CKR_OK) {
                if (rc == CKR_TEMPLATE_INCONSISTENT) {
                        testcase_skip("Token can't generate key with provided template (this is usually ok for non-standard public exponents)");
                        goto testcase_cleanup;
                }
                else {
                        testcase_fail("C_GenerateKeyPair() rc = %s",
                                        p11_get_ckr(rc));
                        goto testcase_cleanup;
                }
        }

        /* TODO: Check flags for generated key pair     */

        /* Now generate the secret key */
        rc = funcs->C_GenerateKey(session, &mech2,
                        secret_tmpl, 1, &secret_key);

        if (rc != CKR_OK) {
                testcase_fail("C_GenerateKeyPair() rc = %s",
                                p11_get_ckr(rc));
                goto testcase_cleanup;
        }

        /* Now extract the CKA_CLASS and CKA_KEY_TYPE from generated key        *
         * We will use this for unwrapping                                      *
         * Take sizes first                                                     */
        rc = funcs->C_GetAttributeValue(session, secret_key, unwrap_tmpl, 2);
        if (rc != CKR_OK) {
                testcase_fail("C_GetAttributeValue() rc = %s",
                                p11_get_ckr(rc));
                goto testcase_cleanup;
        }

        unwrap_tmpl[0].pValue = calloc(sizeof(CK_BYTE), unwrap_tmpl[0].ulValueLen);
        unwrap_tmpl[1].pValue = calloc(sizeof(CK_BYTE), unwrap_tmpl[1].ulValueLen);

        if ( (unwrap_tmpl[0].pValue == NULL) || (unwrap_tmpl[1].pValue == NULL) ) {
                testcase_fail("Error allocating %lu bytes for unwrap template attributes",
                                unwrap_tmpl[0].ulValueLen + unwrap_tmpl[1].ulValueLen);
                rc = -1;
                goto testcase_cleanup;
        }

        /* Get the actual values */
        rc = funcs->C_GetAttributeValue(session, secret_key, unwrap_tmpl, 2);
        if (rc != CKR_OK) {
                testcase_fail("C_GetAttributeValue() rc = %s",
                                p11_get_ckr(rc));
                goto testcase_cleanup;
        }

        /* Finally, let's wrap some secret keys */

        /* excercise the "length only" semantics */
        rc = funcs->C_WrapKey(session, &mech3, publ_key, secret_key,
                        NULL, &wrapped_keylen);
        if (rc != CKR_OK) {
                /* TODO: Check for CKR_WRAPPING_KEY_TYPE_INCONSISTENT ? */
                testcase_fail("C_WrapKey() rc = %s",
                                p11_get_ckr(rc));
                goto testcase_cleanup;
        }

        wrapped_key = calloc(sizeof(CK_BYTE), wrapped_keylen);
        if (wrapped_key == NULL) {
                testcase_fail("Can't allocate memory for %lu bytes",
                                sizeof(CK_BYTE) * wrapped_keylen);
                rc = -1;
                goto testcase_cleanup;
        }

        /* Wrap it */
        rc = funcs->C_WrapKey(session, &mech3, publ_key, secret_key,
                        wrapped_key, &wrapped_keylen);
        if (rc != CKR_OK) {
                testcase_fail("C_WrapKey() rc = %s",
                                p11_get_ckr(rc));
                goto testcase_cleanup;
        }

        /* now recover it */

        /* x.509 + variable key length specific case:
         * x.509 can't handle lengths right, so according to page 242 from
         * the PKCS#11 spec (v2.11), "If the resulting plaintext is to be
         * used to produce an unwrapped key, then however many bytes are
         * specified in the template for the length of the key are taken
         * from the end of this sequence of bytes."
         */
        if (mechtype == CKM_RSA_X_509 && keytype == CKM_AES_KEY_GEN) {
                unwrap_tmpl[2].type = CKA_VALUE_LEN;
                unwrap_tmpl[2].ulValueLen = sizeof(keylen);
                unwrap_tmpl[2].pValue = &keylen;

                rc = funcs->C_UnwrapKey(session, &mech3, priv_key, wrapped_key,
                                wrapped_keylen, unwrap_tmpl, 3, &unwrapped_key);
        }
        else {

                rc = funcs->C_UnwrapKey(session, &mech3, priv_key, wrapped_key,
                                wrapped_keylen, unwrap_tmpl, 2, &unwrapped_key);
        }

        if (rc != CKR_OK) {
                testcase_fail("C_UnwrapKey() rc = %s",
                                p11_get_ckr(rc));
                goto testcase_cleanup;
        }

        /* Get CKA_VALUE_LEN (if applicable) from both keys,    *
         * compare                                              */
        switch(keytype) {
                case CKM_GENERIC_SECRET_KEY_GEN:        /* generic key */
                case CKM_RC4_KEY_GEN:                   /* RC4 */
                case CKM_RC5_KEY_GEN:                   /* RC5 */
                case CKM_AES_KEY_GEN:                   /* AES */
                        /* Note that RC2, CAST, CAST3 and CAST128 also  *
                         * require CKA_VALUE_LEN                        */
                        rc = funcs->C_GetAttributeValue(session, secret_key,
                                        secret_value_len, 1);
                        if (rc != CKR_OK) {
                                testcase_fail("C_GetAttributeValue() rc = %s",
                                                p11_get_ckr(rc));
                                goto testcase_cleanup;
                        }

                        rc = funcs->C_GetAttributeValue(session, unwrapped_key,
                                        unwrapped_value_len, 1);
                        if (rc != CKR_OK) {
                                testcase_fail("C_GetAttributeValue() rc = %s",
                                                p11_get_ckr(rc));
                                goto testcase_cleanup;
                        }

                        if ( *((CK_ULONG_PTR) secret_value_len[0].pValue) !=
                             *((CK_ULONG_PTR) unwrapped_value_len[0].pValue) ) {
                                testcase_fail("CKA_VALUE_LEN value differs (original %lu, unwrapped %lu)",
                                                *((CK_ULONG_PTR) secret_value_len[0].pValue),
                                                *((CK_ULONG_PTR) unwrapped_value_len[0].pValue));
                                rc = -1;
                                goto testcase_cleanup;
                        }
        }

        /* Now need to get CKA_VALUE from both original and     *
         * unwrapped keys, and compare byte-by-byte             */

        /* Get sizes for both the original and unwrapped key's CKA_VALUES */
        rc = funcs->C_GetAttributeValue(session, secret_key, secret_value, 1);
        if (rc != CKR_OK) {
                testcase_fail("C_GetAttributeValue() rc = %s",
                                p11_get_ckr(rc));
                goto testcase_cleanup;
        }

        rc = funcs->C_GetAttributeValue(session, unwrapped_key, unwrapped_value, 1);
        if (rc != CKR_OK) {
                testcase_fail("C_GetAttributeValue() rc = %s",
                                p11_get_ckr(rc));
                goto testcase_cleanup;
        }

        /* We're not checking if ulValueLen is the same for both original and   *
         * unwrapped keys simply because then "can" be different (that's why    *
         * we have CKA_VALUE_LEN)                                               */

        /* now do some allocation */
        secret_value[0].pValue = calloc(sizeof(CK_BYTE), secret_value[0].ulValueLen);
        if (secret_value[0].pValue == NULL) {
                testcase_fail("Error allocating %lu bytes for Secret Key Value",
                                secret_value[0].ulValueLen);
                goto testcase_cleanup;
        }

        unwrapped_value[0].pValue = calloc(sizeof(CK_BYTE), unwrapped_value[0].ulValueLen);
        if (unwrapped_value[0].pValue == NULL) {
                testcase_fail("Error allocating %lu bytes for Unwrapped Key Value",
                                unwrapped_value[0].ulValueLen);
                goto testcase_cleanup;
        }

        /* Get the values */
        rc = funcs->C_GetAttributeValue(session, secret_key, secret_value, 1);
        if (rc != CKR_OK) {
                testcase_fail("C_GetAttributeValue() rc = %s",
                                p11_get_ckr(rc));
                goto testcase_cleanup;
        }

        rc = funcs->C_GetAttributeValue(session, unwrapped_key, unwrapped_value, 1);
        if (rc != CKR_OK) {
                testcase_fail("C_GetAttributeValue() rc = %s",
                                p11_get_ckr(rc));
                goto testcase_cleanup;
        }

        /* compare. For Keys with variable size, CKA_VALUE_LEN should be the    *
         * same as the original key's ulValueLen                                */
        for (i = 0; i < secret_value[0].ulValueLen; i++) {
                if ( ((CK_BYTE_PTR) secret_value[0].pValue)[i] != ((CK_BYTE_PTR) unwrapped_value[0].pValue)[i]) {
                        testcase_fail("Unwrapped key differs in byte %lu", i);
                        p11_ahex_dump(&s, unwrapped_value[0].pValue,
                                        unwrapped_value[0].ulValueLen);
                        if (s != NULL) {
                                testcase_notice("Full hex dump for unwrapped key value:\n%s", s);
                                free(s);
                        }
                        rc = -1;
                        goto testcase_cleanup;
                }
        }



testcase_cleanup:
        if ( rc == CKR_OK && !testcase_skip) {
                testcase_pass("Looks okay...");
        }

        retval = rc;

        testcase_close_session();

        if (unwrap_tmpl[0].pValue) free (unwrap_tmpl[0].pValue);
        if (unwrap_tmpl[1].pValue) free (unwrap_tmpl[1].pValue);
        if (wrapped_key) free (wrapped_key);
        if (secret_value[0].pValue) free (secret_value[0].pValue);
        if (unwrapped_value[0].pValue) free (unwrapped_value[0].pValue);

        return retval | rc;
}

CK_RV run_GenerateEncryptDecryptRSAPKCS()
{
        int     i;
        CK_RV   rv = 0;

        struct  _inputparam {
                CK_MECHANISM_TYPE mechtype;
                CK_ULONG          mod_bits;
                CK_ULONG          publ_exp_len;
                CK_BYTE           publ_exp[4]; /* up to 4 bytes for publ_exp */
                CK_ULONG          inputlen;
                CK_BBOOL          inplace;
        } inputdata[] = {
        /* PKCS#11 defines "Big number" as "a string of CK_BYTEs        *
         * representing an unsigned integer of arbitrary size,          *
         * most-significant byte first (e.g., the integer 32768 is      *
         * represented as the 2-byte string 0x80 0x00)".                *
         *                                                              *
         * This means that publ_exp must be in BIG ENDIAN byte-order    */

        // mod bits = 512. Input up to 53 bytes
                // publ exp = 3
                { CKM_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 53  , FALSE },
                { CKM_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 53  , TRUE  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 53  , FALSE },
                { CKM_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 53  , TRUE  },
                // publ exp = 65537
                { CKM_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 53  , FALSE },
                { CKM_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 53  , TRUE  },
        // mod bits = 768. Input up to 85 bytes
                // publ exp = 3
                { CKM_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 85  , FALSE },
                { CKM_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 85  , TRUE  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 85  , FALSE },
                { CKM_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 85  , TRUE  },
                // publ exp = 65537
                { CKM_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 85  , FALSE },
                { CKM_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 85  , TRUE  },
        // mod bits = 1024. Input up to 117 bytes
                // publ exp = 3
                { CKM_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 117 , FALSE },
                { CKM_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 117 , TRUE  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 117 , FALSE },
                { CKM_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 117 , TRUE  },
                // publ exp = 65537
                { CKM_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 117 , FALSE },
                { CKM_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 117 , TRUE  },
        // mod bits = 2048. Input up to 245 bytes
                // publ exp = 3
                { CKM_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 245 , FALSE },
                { CKM_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 245 , TRUE  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 245 , FALSE },
                { CKM_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 245 , TRUE  },
                // publ exp = 65537
                { CKM_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 245 , FALSE },
                { CKM_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 245 , TRUE  },
        // mod bits = 4096. Input up to 501 bytes
                // publ exp = 3
                { CKM_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 501 , FALSE },
                { CKM_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 501 , TRUE  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 501 , FALSE },
                { CKM_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 501 , TRUE  },
                // publ exp = 65537
                { CKM_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 501 , FALSE },
                { CKM_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 501 , TRUE  },
        };



        for (i = 0;
                i < (sizeof(inputdata) / sizeof(struct _inputparam));
                i++) {
                rv |= do_GenerateEncryptDecryptRSA(
                                inputdata[i].mechtype,
                                inputdata[i].mod_bits,
                                inputdata[i].publ_exp_len,
                                inputdata[i].publ_exp,
                                inputdata[i].inputlen,
                                inputdata[i].inplace
                                );
        }

        return rv;
}

CK_RV run_GenerateSignVerifyRSAPKCS()
{
        int     i;
        CK_RV   rv = 0;

        struct  _inputparam {
                CK_MECHANISM_TYPE mechtype;
                CK_ULONG          mod_bits;
                CK_ULONG          publ_exp_len;
                CK_BYTE           publ_exp[4]; /* up to 4 bytes for publ_exp */
                CK_ULONG          inputlen;
                CK_BBOOL          recover;
        } inputdata[] = {
        /* PKCS#11 defines "Big number" as "a string of CK_BYTEs        *
         * representing an unsigned integer of arbitrary size,          *
         * most-significant byte first (e.g., the integer 32768 is      *
         * represented as the 2-byte string 0x80 0x00)".                *
         *                                                              *
         * This means that publ_exp must be in BIG ENDIAN byte-order    */

        // mod bits = 512. Input up to 53 bytes
                // publ exp = 3
                { CKM_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 53  , FALSE },
                { CKM_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 53  , TRUE  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 53  , FALSE },
                { CKM_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 53  , TRUE  },
                // publ exp = 65537
                { CKM_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 53  , FALSE },
                { CKM_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 53  , TRUE  },
        // mod bits = 768. Input up to 85 bytes
                // publ exp = 3
                { CKM_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 85  , FALSE },
                { CKM_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 85  , TRUE  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 85  , FALSE },
                { CKM_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 85  , TRUE  },
                // publ exp = 65537
                { CKM_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 85  , FALSE },
                { CKM_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 85  , TRUE  },
        // mod bits = 1024. Input up to 117 bytes
                // publ exp = 3
                { CKM_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 117 , FALSE },
                { CKM_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 117 , TRUE  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 117 , FALSE },
                { CKM_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 117 , TRUE  },
                // publ exp = 65537
                { CKM_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 117 , FALSE },
                { CKM_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 117 , TRUE  },
        // mod bits = 2048. Input up to 245 bytes
                // publ exp = 3
                { CKM_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 245 , FALSE },
                { CKM_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 245 , TRUE  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 245 , FALSE },
                { CKM_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 245 , TRUE  },
                // publ exp = 65537
                { CKM_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 245 , FALSE },
                { CKM_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 245 , TRUE  },
        // mod bits = 4096. Input up to 501 bytes
                // publ exp = 3
                { CKM_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 501 , FALSE },
                { CKM_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 501 , TRUE  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 501 , FALSE },
                { CKM_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 501 , TRUE  },
                // publ exp = 65537
                { CKM_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , TRUE  },
                { CKM_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 501 , FALSE },
                { CKM_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 501 , TRUE  },
        };



        for (i = 0;
                i < (sizeof(inputdata) / sizeof(struct _inputparam));
                i++) {
                rv |= do_GenerateSignVerifyRSA(
                                inputdata[i].mechtype,
                                inputdata[i].mod_bits,
                                inputdata[i].publ_exp_len,
                                inputdata[i].publ_exp,
                                inputdata[i].inputlen,
                                inputdata[i].recover
                                );
        }

        return rv;
}

CK_RV run_GenerateEncryptDecryptRSAX509()
{
        int     i;
        CK_RV   rv = 0;

        struct  _inputparam {
                CK_MECHANISM_TYPE mechtype;
                CK_ULONG          mod_bits;
                CK_ULONG          publ_exp_len;
                CK_BYTE           publ_exp[4]; /* up to 4 bytes for publ_exp */
                CK_ULONG          inputlen;
                CK_BBOOL          inplace;
        } inputdata[] = {
        /* PKCS#11 defines "Big number" as "a string of CK_BYTEs        *
         * representing an unsigned integer of arbitrary size,          *
         * most-significant byte first (e.g., the integer 32768 is      *
         * represented as the 2-byte string 0x80 0x00)".                *
         *                                                              *
         * This means that publ_exp must be in BIG ENDIAN byte-order    */

        // mod bits = 512. Input up to 64 bytes
                // publ exp = 3
                { CKM_RSA_X_509, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 64  , FALSE },
                { CKM_RSA_X_509, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 64  , TRUE  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_X_509, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 64  , FALSE },
                { CKM_RSA_X_509, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 64  , TRUE  },
                // publ exp = 65537
                { CKM_RSA_X_509, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 64  , FALSE },
                { CKM_RSA_X_509, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 64  , TRUE  },
        // mod bits = 768. Input up to 96 bytes
                // publ exp = 3
                { CKM_RSA_X_509, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 96  , FALSE },
                { CKM_RSA_X_509, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 96  , TRUE  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_X_509, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 96  , FALSE },
                { CKM_RSA_X_509, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 96  , TRUE  },
                // publ exp = 65537
                { CKM_RSA_X_509, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 96  , FALSE },
                { CKM_RSA_X_509, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 96  , TRUE  },
        // mod bits = 1024. Input up to 128 bytes
                // publ exp = 3
                { CKM_RSA_X_509, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 128 , FALSE },
                { CKM_RSA_X_509, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 128 , TRUE  },
               // publ exp = 17 (big endian format)
                { CKM_RSA_X_509, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 128 , FALSE },
                { CKM_RSA_X_509, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 128 , TRUE  },
                // publ exp = 65537
                { CKM_RSA_X_509, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 128 , FALSE },
                { CKM_RSA_X_509, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 128 , TRUE  },
        // mod bits = 2048. Input up to 256 bytes
                // publ exp = 3
                { CKM_RSA_X_509, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 256 , FALSE },
                { CKM_RSA_X_509, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 256 , TRUE  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_X_509, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 256 , FALSE },
                { CKM_RSA_X_509, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 256 , TRUE  },
                // publ exp = 65537
                { CKM_RSA_X_509, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 256 , FALSE },
                { CKM_RSA_X_509, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 256 , TRUE  },
        // mod bits = 4096. Input up to 512 bytes
                // publ exp = 3
                { CKM_RSA_X_509, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 512 , FALSE },
                { CKM_RSA_X_509, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 512 , TRUE  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_X_509, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 512 , FALSE },
                { CKM_RSA_X_509, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 512 , TRUE  },
                // publ exp = 65537
                { CKM_RSA_X_509, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 512 , FALSE },
                { CKM_RSA_X_509, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 512 , TRUE  },
        };



        for (i = 0;
                i < (sizeof(inputdata) / sizeof(struct _inputparam));
                i++) {
                rv |= do_GenerateEncryptDecryptRSA(
                                inputdata[i].mechtype,
                                inputdata[i].mod_bits,
                                inputdata[i].publ_exp_len,
                                inputdata[i].publ_exp,
                                inputdata[i].inputlen,
                                inputdata[i].inplace
                                );
        }

        return rv;
}

CK_RV run_GenerateSignVerifyRSAX509()
{
        int     i;
        CK_RV   rv = 0;

        struct  _inputparam {
                CK_MECHANISM_TYPE mechtype;
                CK_ULONG          mod_bits;
                CK_ULONG          publ_exp_len;
                CK_BYTE           publ_exp[4]; /* up to 4 bytes for publ_exp */
                CK_ULONG          inputlen;
                CK_BBOOL          recover;
        } inputdata[] = {
        /* PKCS#11 defines "Big number" as "a string of CK_BYTEs        *
         * representing an unsigned integer of arbitrary size,          *
         * most-significant byte first (e.g., the integer 32768 is      *
         * represented as the 2-byte string 0x80 0x00)".                *
         *                                                              *
         * This means that publ_exp must be in BIG ENDIAN byte-order    */

        // mod bits = 512. Input up to 64 bytes
                // publ exp = 3
                { CKM_RSA_X_509, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 64  , FALSE },
                { CKM_RSA_X_509, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 64  , TRUE  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_X_509, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 64  , FALSE },
                { CKM_RSA_X_509, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 64  , TRUE  },
                // publ exp = 65537
                { CKM_RSA_X_509, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 64  , FALSE },
                { CKM_RSA_X_509, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 64  , TRUE  },
                // publ exp = large (4-bytes) even number
                { CKM_RSA_X_509, 512 , 4, { 0xFF, 0xFF, 0xFF, 0x11 }, 1   , FALSE },
                { CKM_RSA_X_509, 512 , 4, { 0xFF, 0xFF, 0xFF, 0x11 }, 1   , TRUE  },
                { CKM_RSA_X_509, 512 , 4, { 0xFF, 0xFF, 0xFF, 0x11 }, 64  , FALSE },
                { CKM_RSA_X_509, 512 , 4, { 0xFF, 0xFF, 0xFF, 0x11 }, 64  , TRUE  },
        // mod bits = 768. Input up to 96 bytes
                // publ exp = 3
                { CKM_RSA_X_509, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 96  , FALSE },
                { CKM_RSA_X_509, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 96  , TRUE  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_X_509, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 96  , FALSE },
                { CKM_RSA_X_509, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 96  , TRUE  },
                // publ exp = 65537
                { CKM_RSA_X_509, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 96  , FALSE },
                { CKM_RSA_X_509, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 96  , TRUE  },
                // publ exp = large (4-bytes) even number
                { CKM_RSA_X_509, 768 , 4, { 0xFF, 0xFF, 0xFF, 0x11 }, 1   , FALSE },
                { CKM_RSA_X_509, 768 , 4, { 0xFF, 0xFF, 0xFF, 0x11 }, 1   , TRUE  },
                { CKM_RSA_X_509, 768 , 4, { 0xFF, 0xFF, 0xFF, 0x11 }, 96  , FALSE },
                { CKM_RSA_X_509, 768 , 4, { 0xFF, 0xFF, 0xFF, 0x11 }, 96  , TRUE  },
        // mod bits = 1024. Input up to 128 bytes
                // publ exp = 3
                { CKM_RSA_X_509, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 128 , FALSE },
                { CKM_RSA_X_509, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 128 , TRUE  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_X_509, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 128 , FALSE },
                { CKM_RSA_X_509, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 128 , TRUE  },
                // publ exp = 65537
                { CKM_RSA_X_509, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 128 , FALSE },
                { CKM_RSA_X_509, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 128 , TRUE  },
                // publ exp = large (4-bytes) even number
                { CKM_RSA_X_509, 1024, 4, { 0xFF, 0xFF, 0xFF, 0x11 }, 1   , FALSE },
                { CKM_RSA_X_509, 1024, 4, { 0xFF, 0xFF, 0xFF, 0x11 }, 1   , TRUE  },
                { CKM_RSA_X_509, 1024, 4, { 0xFF, 0xFF, 0xFF, 0x11 }, 128 , FALSE },
                { CKM_RSA_X_509, 1024, 4, { 0xFF, 0xFF, 0xFF, 0x11 }, 128 , TRUE  },
        // mod bits = 2048. Input up to 256 bytes
                // publ exp = 3
                { CKM_RSA_X_509, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 256 , FALSE },
                { CKM_RSA_X_509, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 256 , TRUE  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_X_509, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 256 , FALSE },
                { CKM_RSA_X_509, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 256 , TRUE  },
                // publ exp = 65537
                { CKM_RSA_X_509, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 256 , FALSE },
                { CKM_RSA_X_509, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 256 , TRUE  },
                // publ exp = large (4-bytes) even number
                { CKM_RSA_X_509, 2048, 4, { 0xFF, 0xFF, 0xFF, 0x11 }, 1   , FALSE },
                { CKM_RSA_X_509, 2048, 4, { 0xFF, 0xFF, 0xFF, 0x11 }, 1   , TRUE  },
                { CKM_RSA_X_509, 2048, 4, { 0xFF, 0xFF, 0xFF, 0x11 }, 256 , FALSE },
                { CKM_RSA_X_509, 2048, 4, { 0xFF, 0xFF, 0xFF, 0x11 }, 256 , TRUE  },
        // mod bits = 4096. Input up to 512 bytes
                // publ exp = 3
                { CKM_RSA_X_509, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 512 , FALSE },
                { CKM_RSA_X_509, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 512 , TRUE  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_X_509, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 512 , FALSE },
                { CKM_RSA_X_509, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 512 , TRUE  },
                // publ exp = 65537
                { CKM_RSA_X_509, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_RSA_X_509, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , TRUE  },
                { CKM_RSA_X_509, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 512 , FALSE },
                { CKM_RSA_X_509, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 512 , TRUE  },
                // publ exp = large (4-bytes) even number
                { CKM_RSA_X_509, 4096, 4, { 0xFF, 0xFF, 0xFF, 0x11 }, 1   , FALSE },
                { CKM_RSA_X_509, 4096, 4, { 0xFF, 0xFF, 0xFF, 0x11 }, 1   , TRUE  },
                { CKM_RSA_X_509, 4096, 4, { 0xFF, 0xFF, 0xFF, 0x11 }, 512 , FALSE },
                { CKM_RSA_X_509, 4096, 4, { 0xFF, 0xFF, 0xFF, 0x11 }, 512 , TRUE  }
        };



        for (i = 0;
                i < (sizeof(inputdata) / sizeof(struct _inputparam));
                i++) {
                rv |= do_GenerateSignVerifyRSA(
                                inputdata[i].mechtype,
                                inputdata[i].mod_bits,
                                inputdata[i].publ_exp_len,
                                inputdata[i].publ_exp,
                                inputdata[i].inputlen,
                                inputdata[i].recover
                                );
        }

        return rv;
}

// Combinations for Single-Part CKM_MD2_RSA_PKCS Sign/Verify,
// which can take input of any size
CK_RV run_GenerateSignVerifyRSAMD2()
{
        int     i;
        CK_RV   rv = 0;

        struct  _inputparam {
                CK_MECHANISM_TYPE mechtype;
                CK_ULONG          mod_bits;
                CK_ULONG          publ_exp_len;
                CK_BYTE           publ_exp[4]; /* up to 4 bytes for publ_exp */
                CK_ULONG          inputlen;
                CK_BBOOL          recover;
        } inputdata[] = {
        /* PKCS#11 defines "Big number" as "a string of CK_BYTEs        *
         * representing an unsigned integer of arbitrary size,          *
         * most-significant byte first (e.g., the integer 32768 is      *
         * represented as the 2-byte string 0x80 0x00)".                *
         *                                                              *
         * This means that publ_exp must be in BIG ENDIAN byte-order    */

        // mod bits = 512.
                // publ exp = 3
                { CKM_MD2_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_MD2_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1000  , FALSE },
                // publ exp = 17 (big endian format)
                { CKM_MD2_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_MD2_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1000  , FALSE },
                // publ exp = 6510007
                { CKM_MD2_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_MD2_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1000  , FALSE },
        // mod bits = 768
                // publ exp = 3
                { CKM_MD2_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_MD2_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1000  , FALSE },
                // publ exp = 17 (big endian format)
                { CKM_MD2_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_MD2_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1000  , FALSE },
                // publ exp = 65537
                { CKM_MD2_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_MD2_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1000  , FALSE },
        // mod bits = 1024
                // publ exp = 3
                { CKM_MD2_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_MD2_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 1000 , FALSE },
                // publ exp = 17 (big endian format)
                { CKM_MD2_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_MD2_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 1000 , FALSE },
                // publ exp = 65537
                { CKM_MD2_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_MD2_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 1000 , FALSE },
        // mod bits = 2048
                // publ exp = 3
                { CKM_MD2_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_MD2_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 1000 , FALSE },
                // publ exp = 17 (big endian format)
                { CKM_MD2_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_MD2_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 1000 , FALSE },
                // publ exp = 65537
                { CKM_MD2_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_MD2_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 1000 , FALSE },
        // mod bits = 4096
                // publ exp = 3
                { CKM_MD2_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_MD2_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 1000 , FALSE },
                // publ exp = 17 (big endian format)
                { CKM_MD2_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_MD2_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 1000 , FALSE },
                // publ exp = 65537
                { CKM_MD2_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_MD2_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 1000 , FALSE },
        };



        for (i = 0;
                i < (sizeof(inputdata) / sizeof(struct _inputparam));
                i++) {
                rv |= do_GenerateSignVerifyRSA(
                                inputdata[i].mechtype,
                                inputdata[i].mod_bits,
                                inputdata[i].publ_exp_len,
                                inputdata[i].publ_exp,
                                inputdata[i].inputlen,
                                inputdata[i].recover
                                );
        }

        return rv;
}

// Combinations for Single-Part CKM_MD5_RSA_PKCS Sign/Verify,
// which can take input of any size
CK_RV run_GenerateSignVerifyRSAMD5()
{
        int     i;
        CK_RV   rv = 0;

        struct  _inputparam {
                CK_MECHANISM_TYPE mechtype;
                CK_ULONG          mod_bits;
                CK_ULONG          publ_exp_len;
                CK_BYTE           publ_exp[4]; /* up to 4 bytes for publ_exp */
                CK_ULONG          inputlen;
                CK_BBOOL          recover;
        } inputdata[] = {
        /* PKCS#11 defines "Big number" as "a string of CK_BYTEs        *
         * representing an unsigned integer of arbitrary size,          *
         * most-significant byte first (e.g., the integer 32768 is      *
         * represented as the 2-byte string 0x80 0x00)".                *
         *                                                              *
         * This means that publ_exp must be in BIG ENDIAN byte-order    */

        // mod bits = 512.
                // publ exp = 3
                { CKM_MD5_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_MD5_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1000  , FALSE },
                // publ exp = 17 (big endian format)
                { CKM_MD5_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_MD5_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1000  , FALSE },
                // publ exp = 6510007
                { CKM_MD5_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_MD5_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1000  , FALSE },
        // mod bits = 768
                // publ exp = 3
                { CKM_MD5_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_MD5_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1000  , FALSE },
                // publ exp = 17 (big endian format)
                { CKM_MD5_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_MD5_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1000  , FALSE },
                // publ exp = 65537
                { CKM_MD5_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_MD5_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1000  , FALSE },
        // mod bits = 1024
                // publ exp = 3
                { CKM_MD5_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_MD5_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 1000 , FALSE },
                // publ exp = 17 (big endian format)
                { CKM_MD5_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_MD5_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 1000 , FALSE },
                // publ exp = 65537
                { CKM_MD5_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_MD5_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 1000 , FALSE },
        // mod bits = 2048
                // publ exp = 3
                { CKM_MD5_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_MD5_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 1000 , FALSE },
                // publ exp = 17 (big endian format)
                { CKM_MD5_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_MD5_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 1000 , FALSE },
                // publ exp = 65537
                { CKM_MD5_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_MD5_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 1000 , FALSE },
        // mod bits = 4096
                // publ exp = 3
                { CKM_MD5_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_MD5_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 1000 , FALSE },
                // publ exp = 17 (big endian format)
                { CKM_MD5_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_MD5_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 1000 , FALSE },
                // publ exp = 65537
                { CKM_MD5_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_MD5_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 1000 , FALSE },
        };



        for (i = 0;
                i < (sizeof(inputdata) / sizeof(struct _inputparam));
                i++) {
                rv |= do_GenerateSignVerifyRSA(
                                inputdata[i].mechtype,
                                inputdata[i].mod_bits,
                                inputdata[i].publ_exp_len,
                                inputdata[i].publ_exp,
                                inputdata[i].inputlen,
                                inputdata[i].recover
                                );
        }

        return rv;
}

// Combinations for Single-Part CKM_SHA1_RSA_PKCS Sign/Verify,
// which can take input of any size
CK_RV run_GenerateSignVerifyRSASHA1()
{
        int     i;
        CK_RV   rv = 0;

        struct  _inputparam {
                CK_MECHANISM_TYPE mechtype;
                CK_ULONG          mod_bits;
                CK_ULONG          publ_exp_len;
                CK_BYTE           publ_exp[4]; /* up to 4 bytes for publ_exp */
                CK_ULONG          inputlen;
                CK_BBOOL          recover;
        } inputdata[] = {
        /* PKCS#11 defines "Big number" as "a string of CK_BYTEs        *
         * representing an unsigned integer of arbitrary size,          *
         * most-significant byte first (e.g., the integer 32768 is      *
         * represented as the 2-byte string 0x80 0x00)".                *
         *                                                              *
         * This means that publ_exp must be in BIG ENDIAN byte-order    */

        // mod bits = 512.
                // publ exp = 3
                { CKM_SHA1_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_SHA1_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1000  , FALSE },
                // publ exp = 17 (big endian format)
                { CKM_SHA1_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_SHA1_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1000  , FALSE },
                // publ exp = 6510007
                { CKM_SHA1_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_SHA1_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1000  , FALSE },
        // mod bits = 768
                // publ exp = 3
                { CKM_SHA1_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_SHA1_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1000  , FALSE },
                // publ exp = 17 (big endian format)
                { CKM_SHA1_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_SHA1_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1000  , FALSE },
                // publ exp = 65537
                { CKM_SHA1_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_SHA1_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1000  , FALSE },
        // mod bits = 1024
                // publ exp = 3
                { CKM_SHA1_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_SHA1_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 1000 , FALSE },
                // publ exp = 17 (big endian format)
                { CKM_SHA1_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_SHA1_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 1000 , FALSE },
                // publ exp = 65537
                { CKM_SHA1_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_SHA1_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 1000 , FALSE },
        // mod bits = 2048
                // publ exp = 3
                { CKM_SHA1_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_SHA1_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 1000 , FALSE },
                // publ exp = 17 (big endian format)
                { CKM_SHA1_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_SHA1_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 1000 , FALSE },
                // publ exp = 65537
                { CKM_SHA1_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_SHA1_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 1000 , FALSE },
        // mod bits = 4096
                // publ exp = 3
                { CKM_SHA1_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , FALSE },
                { CKM_SHA1_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 1000 , FALSE },
                // publ exp = 17 (big endian format)
                { CKM_SHA1_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , FALSE },
                { CKM_SHA1_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 1000 , FALSE },
                // publ exp = 65537
                { CKM_SHA1_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , FALSE },
                { CKM_SHA1_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 1000 , FALSE },
        };



        for (i = 0;
                i < (sizeof(inputdata) / sizeof(struct _inputparam));
                i++) {
                rv |= do_GenerateSignVerifyRSA(
                                inputdata[i].mechtype,
                                inputdata[i].mod_bits,
                                inputdata[i].publ_exp_len,
                                inputdata[i].publ_exp,
                                inputdata[i].inputlen,
                                inputdata[i].recover
                                );
        }

        return rv;
}


CK_RV run_GenerateMultipartSignVerifyRSAMD2()
{
        int     i;
        CK_RV   rv = 0;

        struct  _inputparam {
                CK_MECHANISM_TYPE mechtype;
                CK_ULONG          mod_bits;
                CK_ULONG          publ_exp_len;
                CK_BYTE           publ_exp[4]; /* up to 4 bytes for publ_exp */
                CK_ULONG          partsnum;
                CK_ULONG          partslens[4]; /* up to 4 parts */
        } inputdata[] = {
        /* PKCS#11 defines "Big number" as "a string of CK_BYTEs        *
         * representing an unsigned integer of arbitrary size,          *
         * most-significant byte first (e.g., the integer 32768 is      *
         * represented as the 2-byte string 0x80 0x00)".                *
         *                                                              *
         * This means that publ_exp must be in BIG ENDIAN byte-order    */

        // mod bits = 512. Input up to 64 bytes
                // publ exp = 3
                { CKM_MD2_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , {50} },
                { CKM_MD2_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 17 (big endian format)
                { CKM_MD2_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , {50} },
                { CKM_MD2_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 65537
                { CKM_MD2_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {50} },
                { CKM_MD2_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {10, 0, 10}  },
        // mod bits = 768. Input up to 64 bytes
                // publ exp = 3
                { CKM_MD2_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , {50} },
                { CKM_MD2_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 17 (big endian format)
                { CKM_MD2_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , {50} },
                { CKM_MD2_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 65537
                { CKM_MD2_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {50} },
                { CKM_MD2_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {10, 0, 10}  },
        // mod bits = 768. Input up to 64 bytes
                // publ exp = 3
                { CKM_MD2_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , {50} },
                { CKM_MD2_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 17 (big endian format)
                { CKM_MD2_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , {50} },
                { CKM_MD2_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 65537
                { CKM_MD2_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {50} },
                { CKM_MD2_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {10, 0, 10}  },
        // mod bits = 1024. Input up to 64 bytes
                // publ exp = 3
                { CKM_MD2_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , {50} },
                { CKM_MD2_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 17 (big endian format)
                { CKM_MD2_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , {50} },
                { CKM_MD2_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 65537
                { CKM_MD2_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {50} },
                { CKM_MD2_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {10, 0, 10}  },
        // mod bits = 2048. Input up to 64 bytes
                // publ exp = 3
                { CKM_MD2_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , {50} },
                { CKM_MD2_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 17 (big endian format)
                { CKM_MD2_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , {50} },
                { CKM_MD2_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 65537
                { CKM_MD2_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {50} },
                { CKM_MD2_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {10, 0, 10}  },
        // mod bits = 4096. Input up to 64 bytes
                // publ exp = 3
                { CKM_MD2_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , {50} },
                { CKM_MD2_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 17 (big endian format)
                { CKM_MD2_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , {50} },
                { CKM_MD2_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 65537
                { CKM_MD2_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {50} },
                { CKM_MD2_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {10, 0, 10}  },
        };



        for (i = 0;
                i < (sizeof(inputdata) / sizeof(struct _inputparam));
                i++) {
                rv |= do_GenerateMultipartSignVerifyRSA(
                                inputdata[i].mechtype,
                                inputdata[i].mod_bits,
                                inputdata[i].publ_exp_len,
                                inputdata[i].publ_exp,
                                inputdata[i].partsnum,
                                inputdata[i].partslens
                                );
        }

        return rv;
}

CK_RV run_GenerateMultipartSignVerifyRSAMD5()
{
        int     i;
        CK_RV   rv = 0;

        struct  _inputparam {
                CK_MECHANISM_TYPE mechtype;
                CK_ULONG          mod_bits;
                CK_ULONG          publ_exp_len;
                CK_BYTE           publ_exp[4]; /* up to 4 bytes for publ_exp */
                CK_ULONG          partsnum;
                CK_ULONG          partslens[4]; /* up to 4 parts */
        } inputdata[] = {
        /* PKCS#11 defines "Big number" as "a string of CK_BYTEs        *
         * representing an unsigned integer of arbitrary size,          *
         * most-significant byte first (e.g., the integer 32768 is      *
         * represented as the 2-byte string 0x80 0x00)".                *
         *                                                              *
         * This means that publ_exp must be in BIG ENDIAN byte-order    */

        // mod bits = 512. Input up to 64 bytes
                // publ exp = 3
                { CKM_MD5_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , {50} },
                { CKM_MD5_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 17 (big endian format)
                { CKM_MD5_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , {50} },
                { CKM_MD5_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 65537
                { CKM_MD5_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {50} },
                { CKM_MD5_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {10, 0, 10}  },
        // mod bits = 768. Input up to 64 bytes
                // publ exp = 3
                { CKM_MD5_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , {50} },
                { CKM_MD5_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 17 (big endian format)
                { CKM_MD5_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , {50} },
                { CKM_MD5_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 65537
                { CKM_MD5_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {50} },
                { CKM_MD5_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {10, 0, 10}  },
        // mod bits = 768. Input up to 64 bytes
                // publ exp = 3
                { CKM_MD5_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , {50} },
                { CKM_MD5_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 17 (big endian format)
                { CKM_MD5_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , {50} },
                { CKM_MD5_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 65537
                { CKM_MD5_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {50} },
                { CKM_MD5_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {10, 0, 10}  },
        // mod bits = 1024. Input up to 64 bytes
                // publ exp = 3
                { CKM_MD5_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , {50} },
                { CKM_MD5_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 17 (big endian format)
                { CKM_MD5_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , {50} },
                { CKM_MD5_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 65537
                { CKM_MD5_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {50} },
                { CKM_MD5_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {10, 0, 10}  },
        // mod bits = 2048. Input up to 64 bytes
                // publ exp = 3
                { CKM_MD5_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , {50} },
                { CKM_MD5_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 17 (big endian format)
                { CKM_MD5_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , {50} },
                { CKM_MD5_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 65537
                { CKM_MD5_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {50} },
                { CKM_MD5_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {10, 0, 10}  },
        // mod bits = 4096. Input up to 64 bytes
                // publ exp = 3
                { CKM_MD5_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , {50} },
                { CKM_MD5_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 17 (big endian format)
                { CKM_MD5_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , {50} },
                { CKM_MD5_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 65537
                { CKM_MD5_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {50} },
                { CKM_MD5_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {10, 0, 10}  },
        };



        for (i = 0;
                i < (sizeof(inputdata) / sizeof(struct _inputparam));
                i++) {
                rv |= do_GenerateMultipartSignVerifyRSA(
                                inputdata[i].mechtype,
                                inputdata[i].mod_bits,
                                inputdata[i].publ_exp_len,
                                inputdata[i].publ_exp,
                                inputdata[i].partsnum,
                                inputdata[i].partslens
                                );
        }

        return rv;
}


CK_RV run_GenerateMultipartSignVerifyRSASHA1()
{
        int     i;
        CK_RV   rv = 0;

        struct  _inputparam {
                CK_MECHANISM_TYPE mechtype;
                CK_ULONG          mod_bits;
                CK_ULONG          publ_exp_len;
                CK_BYTE           publ_exp[4]; /* up to 4 bytes for publ_exp */
                CK_ULONG          partsnum;
                CK_ULONG          partslens[4]; /* up to 4 parts */
        } inputdata[] = {
        /* PKCS#11 defines "Big number" as "a string of CK_BYTEs        *
         * representing an unsigned integer of arbitrary size,          *
         * most-significant byte first (e.g., the integer 32768 is      *
         * represented as the 2-byte string 0x80 0x00)".                *
         *                                                              *
         * This means that publ_exp must be in BIG ENDIAN byte-order    */

        // mod bits = 512. Input up to 64 bytes
                // publ exp = 3
                { CKM_SHA1_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , {50} },
                { CKM_SHA1_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 17 (big endian format)
                { CKM_SHA1_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , {50} },
                { CKM_SHA1_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 65537
                { CKM_SHA1_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {50} },
                { CKM_SHA1_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {10, 0, 10}  },
        // mod bits = 768. Input up to 64 bytes
                // publ exp = 3
                { CKM_SHA1_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , {50} },
                { CKM_SHA1_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 17 (big endian format)
                { CKM_SHA1_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , {50} },
                { CKM_SHA1_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 65537
                { CKM_SHA1_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {50} },
                { CKM_SHA1_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {10, 0, 10}  },
        // mod bits = 768. Input up to 64 bytes
                // publ exp = 3
                { CKM_SHA1_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , {50} },
                { CKM_SHA1_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 17 (big endian format)
                { CKM_SHA1_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , {50} },
                { CKM_SHA1_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 65537
                { CKM_SHA1_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {50} },
                { CKM_SHA1_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {10, 0, 10}  },
        // mod bits = 1024. Input up to 64 bytes
                // publ exp = 3
                { CKM_SHA1_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , {50} },
                { CKM_SHA1_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 17 (big endian format)
                { CKM_SHA1_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , {50} },
                { CKM_SHA1_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 65537
                { CKM_SHA1_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {50} },
                { CKM_SHA1_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {10, 0, 10}  },
        // mod bits = 2048. Input up to 64 bytes
                // publ exp = 3
                { CKM_SHA1_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , {50} },
                { CKM_SHA1_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 17 (big endian format)
                { CKM_SHA1_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , {50} },
                { CKM_SHA1_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 65537
                { CKM_SHA1_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {50} },
                { CKM_SHA1_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {10, 0, 10}  },
        // mod bits = 4096. Input up to 64 bytes
                // publ exp = 3
                { CKM_SHA1_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , {50} },
                { CKM_SHA1_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 17 (big endian format)
                { CKM_SHA1_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , {50} },
                { CKM_SHA1_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 3   , {10, 0, 10}  },
                // publ exp = 65537
                { CKM_SHA1_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {50} },
                { CKM_SHA1_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , {10, 0, 10}  },
        };



        for (i = 0;
                i < (sizeof(inputdata) / sizeof(struct _inputparam));
                i++) {
                rv |= do_GenerateMultipartSignVerifyRSA(
                                inputdata[i].mechtype,
                                inputdata[i].mod_bits,
                                inputdata[i].publ_exp_len,
                                inputdata[i].publ_exp,
                                inputdata[i].partsnum,
                                inputdata[i].partslens
                                );
        }

        return rv;
}



CK_RV run_GenerateWrapUnwrapRSAPKCS()
{
        int     i;
        CK_RV   rv = 0;

        struct  _inputparam {
                CK_MECHANISM_TYPE mechtype;
                CK_ULONG          mod_bits;
                CK_ULONG          publ_exp_len;
                CK_BYTE           publ_exp[4]; /* up to 4 bytes for publ_exp */
                CK_ULONG          keylen;
                CK_MECHANISM_TYPE keytype;
        } inputdata[] = {
        /* PKCS#11 defines "Big number" as "a string of CK_BYTEs        *
         * representing an unsigned integer of arbitrary size,          *
         * most-significant byte first (e.g., the integer 32768 is      *
         * represented as the 2-byte string 0x80 0x00)".                *
         *                                                              *
         * This means that publ_exp must be in BIG ENDIAN byte-order    */

        // mod bits = 512. Secret keys up to 64 bytes
                // publ exp = 3
                { CKM_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 64  , CKM_GENERIC_SECRET_KEY_GEN  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 64  , CKM_GENERIC_SECRET_KEY_GEN  },
                // publ exp = 65537
                { CKM_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 64  , CKM_GENERIC_SECRET_KEY_GEN  },
        // mod bits = 768. Secret keys up to 96 bytes
                // publ exp = 3
                { CKM_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 96  , CKM_GENERIC_SECRET_KEY_GEN  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 96  , CKM_GENERIC_SECRET_KEY_GEN  },
                // publ exp = 65537
                { CKM_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 96  , CKM_GENERIC_SECRET_KEY_GEN  },
        // mod bits = 1024. Secret keys up to 128 bytes
                // publ exp = 3
                { CKM_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 128 , CKM_GENERIC_SECRET_KEY_GEN  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 128 , CKM_GENERIC_SECRET_KEY_GEN  },
                // publ exp = 65537
                { CKM_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 128 , CKM_GENERIC_SECRET_KEY_GEN  },
        // mod bits = 2048. Secret keys up to 256 bytes
                // publ exp = 3
                { CKM_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 256 , CKM_GENERIC_SECRET_KEY_GEN  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 256 , CKM_GENERIC_SECRET_KEY_GEN  },
                // publ exp = 65537
                { CKM_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 256 , CKM_GENERIC_SECRET_KEY_GEN  },
        // mod bits = 4096. Secret keys up to 512 bytes
                // publ exp = 3
                { CKM_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 512 , CKM_GENERIC_SECRET_KEY_GEN  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 512 , CKM_GENERIC_SECRET_KEY_GEN  },
                // publ exp = 65537
                { CKM_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_PKCS, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 512 , CKM_GENERIC_SECRET_KEY_GEN  },
        };



        for (i = 0;
                i < (sizeof(inputdata) / sizeof(struct _inputparam));
                i++) {
                rv |= do_GenerateWrapUnwrapRSA(
                                inputdata[i].mechtype,
                                inputdata[i].mod_bits,
                                inputdata[i].publ_exp_len,
                                inputdata[i].publ_exp,
                                inputdata[i].keylen,
                                inputdata[i].keytype
                                );
        }

        return rv;
}


CK_RV run_GenerateWrapUnwrapRSAX509()
{
        int     i;
        CK_RV   rv = 0;

        struct  _inputparam {
                CK_MECHANISM_TYPE mechtype;
                CK_ULONG          mod_bits;
                CK_ULONG          publ_exp_len;
                CK_BYTE           publ_exp[4]; /* up to 4 bytes for publ_exp */
                CK_ULONG          keylen;
                CK_MECHANISM_TYPE keytype;
        } inputdata[] = {
        /* PKCS#11 defines "Big number" as "a string of CK_BYTEs        *
         * representing an unsigned integer of arbitrary size,          *
         * most-significant byte first (e.g., the integer 32768 is      *
         * represented as the 2-byte string 0x80 0x00)".                *
         *                                                              *
         * This means that publ_exp must be in BIG ENDIAN byte-order    */

        // mod bits = 512. Secret keys up to 64 bytes
                // publ exp = 3
                { CKM_RSA_X_509, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_X_509, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_X_509, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_X_509, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_X_509, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 512 , 1, { 0x03, 0x00, 0x00, 0x00 }, 64  , CKM_GENERIC_SECRET_KEY_GEN  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_X_509, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_X_509, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_X_509, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_X_509, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_X_509, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 512 , 2, { 0x00, 0x11, 0x00, 0x00 }, 64  , CKM_GENERIC_SECRET_KEY_GEN  },
                // publ exp = 65537
                { CKM_RSA_X_509, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_X_509, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_X_509, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_X_509, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_X_509, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 512 , 3, { 0x01, 0x00, 0x01, 0x00 }, 64  , CKM_GENERIC_SECRET_KEY_GEN  },
        // mod bits = 768. Secret keys up to 96 bytes
                // publ exp = 3
                { CKM_RSA_X_509, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_X_509, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_X_509, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_X_509, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_X_509, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 768 , 1, { 0x03, 0x00, 0x00, 0x00 }, 96  , CKM_GENERIC_SECRET_KEY_GEN  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_X_509, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_X_509, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_X_509, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_X_509, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_X_509, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 768 , 2, { 0x00, 0x11, 0x00, 0x00 }, 96  , CKM_GENERIC_SECRET_KEY_GEN  },
                // publ exp = 65537
                { CKM_RSA_X_509, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_X_509, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_X_509, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_X_509, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_X_509, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 768 , 3, { 0x01, 0x00, 0x01, 0x00 }, 96  , CKM_GENERIC_SECRET_KEY_GEN  },
        // mod bits = 1024. Secret keys up to 128 bytes
                // publ exp = 3
                { CKM_RSA_X_509, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_X_509, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_X_509, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_X_509, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_X_509, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 1024, 1, { 0x03, 0x00, 0x00, 0x00 }, 128 , CKM_GENERIC_SECRET_KEY_GEN  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_X_509, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_X_509, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_X_509, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_X_509, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_X_509, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 1024, 2, { 0x00, 0x11, 0x00, 0x00 }, 128 , CKM_GENERIC_SECRET_KEY_GEN  },
                // publ exp = 65537
                { CKM_RSA_X_509, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_X_509, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_X_509, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_X_509, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_X_509, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 1024, 3, { 0x01, 0x00, 0x01, 0x00 }, 128 , CKM_GENERIC_SECRET_KEY_GEN  },
        // mod bits = 2048. Secret keys up to 256 bytes
                // publ exp = 3
                { CKM_RSA_X_509, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_X_509, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_X_509, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_X_509, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_X_509, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 2048, 1, { 0x03, 0x00, 0x00, 0x00 }, 256 , CKM_GENERIC_SECRET_KEY_GEN  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_X_509, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_X_509, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_X_509, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_X_509, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_X_509, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 2048, 2, { 0x00, 0x11, 0x00, 0x00 }, 256 , CKM_GENERIC_SECRET_KEY_GEN  },
                // publ exp = 65537
                { CKM_RSA_X_509, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_X_509, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_X_509, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_X_509, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_X_509, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 2048, 3, { 0x01, 0x00, 0x01, 0x00 }, 256 , CKM_GENERIC_SECRET_KEY_GEN  },
        // mod bits = 4096. Secret keys up to 512 bytes
                // publ exp = 3
                { CKM_RSA_X_509, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_X_509, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_X_509, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_X_509, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_X_509, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 4096, 1, { 0x03, 0x00, 0x00, 0x00 }, 512 , CKM_GENERIC_SECRET_KEY_GEN  },
                // publ exp = 17 (big endian format)
                { CKM_RSA_X_509, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_X_509, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_X_509, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_X_509, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_X_509, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 4096, 2, { 0x00, 0x11, 0x00, 0x00 }, 512 , CKM_GENERIC_SECRET_KEY_GEN  },
                // publ exp = 65537
                { CKM_RSA_X_509, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 1   , CKM_GENERIC_SECRET_KEY_GEN  },
                { CKM_RSA_X_509, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 8   , CKM_CDMF_KEY_GEN            },
                { CKM_RSA_X_509, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 8   , CKM_DES_KEY_GEN             },
                { CKM_RSA_X_509, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 24  , CKM_DES3_KEY_GEN            },
                { CKM_RSA_X_509, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 16  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 32  , CKM_AES_KEY_GEN             },
                { CKM_RSA_X_509, 4096, 3, { 0x01, 0x00, 0x01, 0x00 }, 512 , CKM_GENERIC_SECRET_KEY_GEN  },
        };



        for (i = 0;
                i < (sizeof(inputdata) / sizeof(struct _inputparam));
                i++) {
                rv |= do_GenerateWrapUnwrapRSA(
                                inputdata[i].mechtype,
                                inputdata[i].mod_bits,
                                inputdata[i].publ_exp_len,
                                inputdata[i].publ_exp,
                                inputdata[i].keylen,
                                inputdata[i].keytype
                                );
        }

        return rv;
}

int main(int argc, char **argv)
{
	CK_C_INITIALIZE_ARGS cinit_args;
	int rc;
	CK_RV rv = 0;

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

        rv = run_GenerateEncryptDecryptRSAPKCS();
        rv |= run_GenerateSignVerifyRSAPKCS();
        rv |= run_GenerateEncryptDecryptRSAX509();
        rv |= run_GenerateSignVerifyRSAX509();
        rv |= run_GenerateWrapUnwrapRSAPKCS();
        rv |= run_GenerateWrapUnwrapRSAX509();
        rv |= run_GenerateSignVerifyRSAMD2();
        rv |= run_GenerateSignVerifyRSAMD5();
        rv |= run_GenerateSignVerifyRSASHA1();
        rv |= run_GenerateMultipartSignVerifyRSAMD2();
        rv |= run_GenerateMultipartSignVerifyRSAMD5();
        rv |= run_GenerateMultipartSignVerifyRSASHA1();

	/* make sure we return non-zero if rv is non-zero */
	return ((rv==0) || (rv % 256) ? rv : -1);
}
