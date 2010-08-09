
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <dlfcn.h>
#include <pkcs11types.h>
#include "slotmgr.h"
#include "regress.h"

CK_RV init(void);
void test_crypto_usage(void);
CK_RV verify_slot(unsigned long slot_num);
CK_RV test_crypto(long slot_num);
int test_ecb_des(CK_SESSION_HANDLE hSession);
int test_cbc_des(CK_SESSION_HANDLE hSession);
int test_ecb_3des(CK_SESSION_HANDLE hSession);
int test_cbc_3des(CK_SESSION_HANDLE hSession);
int test_rsa_encryption(CK_SESSION_HANDLE hSession);
int test_rsa_signature(CK_SESSION_HANDLE hSession);
CK_RV symmetric_encryption(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey, 
      CK_MECHANISM mechanism, CK_CHAR *data, CK_ULONG data_sz, 
      CK_CHAR **encryptedData, CK_ULONG *encryptedData_sz);

void *dllPtr;
CK_FUNCTION_LIST_PTR   funcs = NULL;
Slot_Mgr_Shr_t         *shmp = NULL;


int main(int argc, char *argv[]) {
   CK_RV rc = 1;
   unsigned long slot_num = 0;  
   int c;

   /* parse the command line parameters */

   while ((c = getopt(argc, argv, "hc:")) != (-1)) {
      switch (c) {
         case 'h':
            test_crypto_usage();
	    return 0;
	    break;
         case 'c':  /* a specific card (slot) is specified */
            slot_num = atol(optarg);
            break;
         default:   /* if something else was passed in it is an error */
            test_crypto_usage();
	    return 0;
      }
   }
   
   /* load the PKCS11 library */
   rc = init();
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR calling init, rc = %p.\n", (void *)rc);
      exit (1);
   }

   /* verify the slot number */
   rc = verify_slot(slot_num);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR invalid slot ID, rc = %p.\n", (void *)rc);
      exit (1);
   }

   /* test the crypto functions */
   rc = test_crypto(slot_num);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR call to test_crytpo failed.\n");
      exit (1);
   }

   exit (0);
}

void test_crypto_usage(void)
{
   fprintf(stderr, "Usage:  test_crypto [-c <slotId>]\n"
      "Default slotID is 0\n"
      "To get a list of slotIDs, call %s/pkcsconf -s\n", SBIN_PATH);
   exit(1);
}

CK_RV init(void) 
{
   CK_RV rc;
   void (*funcPtr)();   // Pointer to function for the DLL
   char *error;

   /* Open the PKCS11 API */
   dllPtr = dlopen( "libopencryptoki.so", RTLD_NOW);
   if (! dllPtr) {
      fprintf(stderr, "%s\n", dlerror());
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   /* Get a pointer to the function that gets the list of PKCS11 functions this token supports */
   funcPtr = (void (*)())dlsym(dllPtr, "C_GetFunctionList");
   if ((error = dlerror()) != NULL) {
      fprintf(stderr, "%s\n", error);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }
   else if (! funcPtr) {
      fprintf(stderr, "Error, C_GetFunctionList is NULL\n");
      rc = CKR_GENERAL_ERROR;
      goto done;
   }

   /* get the list of functions */
   funcPtr(&funcs);

   rc = funcs->C_Initialize(NULL);
   if (rc != CKR_OK) {
      goto done;
   }

   rc = CKR_OK;

done:
   if (rc != CKR_OK) {
      /* call C_Finalize and close the dyn. linked lib */
      if (funcs) {
         funcs->C_Finalize(NULL);
      }
      if (dllPtr) {
         dlclose(dllPtr);
      }
   }

   return rc;
}

CK_RV verify_slot(unsigned long slot_num) 
{
   CK_RV rc;
   CK_SLOT_ID_PTR pSlotWithTokenList;
   CK_ULONG ulSlotWithTokenCount;
   unsigned int i;

   rc = funcs->C_GetSlotList(TRUE, NULL_PTR, &ulSlotWithTokenCount); 
   if (rc == CKR_OK) {
      pSlotWithTokenList = (CK_SLOT_ID_PTR)malloc(ulSlotWithTokenCount*sizeof(CK_SLOT_ID));
      rc = funcs->C_GetSlotList(TRUE, pSlotWithTokenList, &ulSlotWithTokenCount);
      if (rc != CKR_OK) {
         fprintf(stderr, "Error geting list of slots with token\n");
         return rc;
      }
   }
   else {
      fprintf(stderr, "Error getting number of slots with token.\n");
      return rc;
   }

   for (i = 0; i < ulSlotWithTokenCount; i ++) {
      if (slot_num == pSlotWithTokenList[i]) {
         /* slot id is valid */
         return CKR_OK;
      }
   }

   /* if we are here, slot ID is invalid */
   fprintf(stderr, "Error:   Slot ID is invalid\n");
   return CKR_GENERAL_ERROR;
}



CK_RV test_crypto(long slot_num) 
{
   CK_RV rc;
   CK_SESSION_HANDLE hSession;
   CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
   CK_ULONG user_pin_len;

   if (get_user_pin(user_pin))
	   return CKR_FUNCTION_FAILED;
   user_pin_len = (CK_ULONG)strlen((char *)user_pin);

   /* open a R/W cryptoki session, CKR_SERIAL_SESSION is a legacy bit we have to set */
   rc = funcs->C_OpenSession(slot_num, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL_PTR,
         NULL_PTR, &hSession);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR call to C_OpenSession failed, rc = %p\n", (void *)rc);
      goto out;
   }

   /* log in as normal user */
   rc = funcs->C_Login(hSession, CKU_USER, user_pin, user_pin_len);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR call to C_Login failed, rc = %p\n", (void *)rc);
      goto out_close;
   }

#if 1
   rc = test_ecb_des(hSession);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR DES_ECB failed, rc = %p\n", (void *)rc);
   }
   fprintf(stderr, "CKM_DES_ECB test passed.\n");

   rc = test_cbc_des(hSession);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR DES_CBC failed, rc = %p\n", (void *)rc);
   }
   fprintf(stderr, "CKM_DES_CBC test passed.\n");

   rc = test_ecb_3des(hSession);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR, DES3_ECB failed, rc = %p\n", (void *)rc);
   }
   fprintf(stderr, "CKM_DES3_ECB test passed.\n");

   rc = test_cbc_3des(hSession);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR, DES3_CBC failed, rc = %p\n", (void *)rc);
   }
   fprintf(stderr, "CKM_DES3_CBC test passed.\n");

#endif

   rc = test_rsa_encryption(hSession);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR, RSA encryption failed, rc = %p\n", (void *)rc);
   } 
   fprintf(stderr, "CKM_RSA_PKCS_KEY_PAIR_GEN and CKM_RSA_PKCS tests passed.\n");

   rc = test_rsa_signature(hSession);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR, RSA signature failed, rc = %p\n", (void *)rc);
   }

out_close:
   if( (rc = funcs->C_CloseSession(hSession)) != CKR_OK ) {
      fprintf(stderr, "Error: C_CloseSession failed with %p\n", (void *)rc);
   }

out:
   return rc;
}


/* 
 * test the CKM_RSA_PKCS_KEY_PAIR_GEN and CKM_RSA_PKCS mechanisms 
 */
int test_rsa_encryption(CK_SESSION_HANDLE hSession)
{
   CK_RV rc, rc2;
   CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
   CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};
   CK_MECHANISM mechanism_encr = {CKM_RSA_PKCS, NULL, 0};
   CK_BYTE pData[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0xC0, 0xC0, 0xCA, 0xFE};
   CK_ULONG ulDataLen = 8;
   CK_BYTE_PTR pEncryptedData;
   CK_BYTE_PTR pDecryptedData;
   CK_ULONG encryptedDataLen = 0;
   CK_ULONG decryptedDataLen = 0;
   /* pub and priv key template declarations */
   CK_BBOOL true = TRUE;
   CK_ULONG modulusBits = 768;
   CK_BYTE publicExponent[] = {0x01, 0x00, 0x01 };
   CK_BYTE subject[] = {'p', 'e', 'a', 'c', 'e'};
   CK_BYTE id[] = {123};
   CK_ATTRIBUTE publicKeyTemplate[] = {
      {CKA_ENCRYPT, &true, sizeof(true)},
      {CKA_VERIFY, &true, sizeof(true)},
      {CKA_WRAP, &true, sizeof(true)},
      {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
      {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)}
   };
   CK_ATTRIBUTE privateKeyTemplate[] = {
      {CKA_TOKEN, &true, sizeof(true)},
      {CKA_PRIVATE, &true, sizeof(true)},
      {CKA_SUBJECT, subject, sizeof(subject)},
      {CKA_ID, id, sizeof(id)},
      {CKA_SENSITIVE, &true, sizeof(true)},
      {CKA_DECRYPT, &true, sizeof(true)},
      {CKA_SIGN, &true, sizeof(true)},
      {CKA_SIGN, &true, sizeof(true)},
      {CKA_UNWRAP, &true, sizeof(true)}
   };
   CK_MECHANISM_INFO info;

   /* generate a new key */
   rc = funcs->C_GenerateKeyPair(
         hSession, &mechanism, 
         publicKeyTemplate, 5, 
         privateKeyTemplate, 8,
         &hPublicKey, &hPrivateKey);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR:  call to C_GenerateKeyPair failed.\n");
      goto out;
   }

   /* get information on CKM_RSA_PKS mechanism */
   rc = funcs->C_GetMechanismInfo(0, CKM_RSA_PKCS, &info);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR:  call to C_GetMechanismInfo faile.\n");
      goto out_delkeys;
   }

   fprintf(stderr, "* Minimum key size:  %ld\n* Maximum key size:  %ld\n", info.ulMinKeySize, info.ulMaxKeySize);

   /* encrypt something */
   rc = funcs->C_EncryptInit(hSession, &mechanism_encr, hPublicKey);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR: call to C_EncryptInit failed.\n");
      goto out_delkeys;
   }
   rc = funcs->C_Encrypt(hSession, pData, ulDataLen, NULL, &encryptedDataLen);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR: call to C_Encrypt to get size of encryptedData failed.\n");
      goto out_delkeys;
   }
   pEncryptedData = (CK_BYTE_PTR)malloc(encryptedDataLen);
   rc = funcs->C_Encrypt(hSession, pData, ulDataLen, pEncryptedData, &encryptedDataLen);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR: call to C_Encrypt failed.\n");
      goto out_delkeys;
   }

   /* now try decrypting */
   rc = funcs->C_DecryptInit(hSession, &mechanism_encr, hPrivateKey);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR: call to C_EncryptInit failed.\n");
      goto out_delkeys;
   }
   rc = funcs->C_Decrypt(hSession, pEncryptedData, encryptedDataLen, NULL, &decryptedDataLen);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR: call to C_Encrypt failed.\n");
      goto out_delkeys;
   }
   pDecryptedData = (CK_BYTE_PTR)malloc(decryptedDataLen);
   rc = funcs->C_Decrypt(hSession, pEncryptedData, encryptedDataLen, pDecryptedData, &decryptedDataLen);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR: call to C_Encrypt failed.\n");
      goto out_delkeys;
   }

   if (0 != memcmp(pDecryptedData, pData, ulDataLen)) {
      fprintf(stderr, "Decryption text is not equal to initial plaintext.\n");
      rc = -1;
   }

out_delkeys:
   rc2 = funcs->C_DestroyObject(hSession, hPublicKey);
   if (rc2 != CKR_OK) {
      fprintf(stderr, "Error deleting public key...\n");
      if (rc == CKR_OK)
         rc = rc2;
   }
   rc2 = funcs->C_DestroyObject(hSession, hPrivateKey);
   if (rc2 != CKR_OK) {
      fprintf(stderr, "Error deleting private key...\n");
      if (rc == CKR_OK)
         rc = rc2;
   }

out:
   return rc;
}

int test_rsa_signature(CK_SESSION_HANDLE hSession)
{
   return CKR_OK;
}



/* 
 * test the CKM_DES_ECB mechanism 
 */ 
int test_ecb_des(CK_SESSION_HANDLE hSession) 
{
   CK_RV rc, rc2;
   CK_OBJECT_CLASS class = CKO_SECRET_KEY;
   CK_KEY_TYPE keyType = CKK_DES;
   CK_CHAR label[] = "A DES secret key object";
   CK_BYTE value[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
   CK_BBOOL true = TRUE;
   CK_ATTRIBUTE template[] = {
      {CKA_CLASS, &class, sizeof(class)},
      {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
      {CKA_TOKEN, &true, sizeof(true)},
      {CKA_LABEL, label, sizeof(label)},
      {CKA_ENCRYPT, &true, sizeof(true)},
      {CKA_VALUE, value, sizeof(value)}
   };
   CK_OBJECT_HANDLE hKey;
   CK_CHAR plain[] = {0x4e, 0x6f, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74,
      0x6a, 0x2a, 0x19, 0xf4, 0x1e, 0xca, 0x85, 0x4b};
   /* expected result */
   CK_CHAR cipher[] = {0x3f, 0xa4, 0x0e, 0x8a, 0x98, 0x4d, 0x48, 0x15,
      0xa8, 0x89, 0x70, 0xdb, 0xeb, 0xa2, 0x4d, 0x80};
   CK_CHAR *encryptedData = NULL;
   CK_ULONG encryptedDataLen = 0;
   CK_MECHANISM mechanism = {
      CKM_DES_ECB, NULL, 0
   };

   /* create DES secret key object */
   rc = funcs->C_CreateObject(hSession, 
         template, 
         sizeof(template) / sizeof (CK_ATTRIBUTE),
         &hKey);
   if (rc != CKR_OK) {
     fprintf(stderr, "ERROR call to C_CreateObject failed, rc = %p\n", (void *)rc);
      return rc;
   }

   rc = symmetric_encryption(hSession, hKey, mechanism, plain, sizeof(plain), &encryptedData, &encryptedDataLen);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR call to symmetric_encryption failed, rc =%p\n", (void *)rc);
      rc = CKR_GENERAL_ERROR;
      goto done;
   }

   /* known answer test */
   rc = memcmp(cipher, encryptedData, sizeof(cipher));
   if (rc != 0) {
      fprintf(stderr, "ERROR test vector failed.\n");
      rc = CKR_GENERAL_ERROR;
      goto done;
   }

   rc = CKR_OK;

done:
   if (encryptedData) {
      free(encryptedData);
   }
   rc2 = funcs->C_DestroyObject(hSession, hKey);
   if (rc2 != CKR_OK) {
      fprintf(stderr, "Error deleting DES key...\n");
      if (rc == CKR_OK)
         rc = rc2;
   }


   return rc;
}

/* 
 * test CKM_DES_CBC mechanism
 */

int test_cbc_des(CK_SESSION_HANDLE hSession) 
{
   CK_RV rc, rc2;
   CK_OBJECT_CLASS class = CKO_SECRET_KEY;
   CK_KEY_TYPE keyType = CKK_DES;
   CK_CHAR label[] = "A DES secret key object";
   CK_BYTE value[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xCA, 0xFE};
   CK_BBOOL true = TRUE;
   CK_ATTRIBUTE template[] = {
      {CKA_CLASS, &class, sizeof(class)},
      {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
      {CKA_TOKEN, &true, sizeof(true)},
      {CKA_LABEL, label, sizeof(label)},
      {CKA_ENCRYPT, &true, sizeof(true)},
      {CKA_VALUE, value, sizeof(value)}
   };

   CK_OBJECT_HANDLE hKey;
   CK_BYTE iv[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11};
   CK_CHAR data[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xC0, 0xC0, 0xCA, 0xFE, 0x11, 0x22, 0x33, 0x44};
   /* expected result */
   CK_CHAR cipher[] = {0x28, 0x16, 0xA1, 0x0C, 0x76, 0xAC, 0x4E, 0x67, 0xBC, 0x3F, 0x17, 0xC1, 0xD1, 0x2F, 0x4B, 0x92};
   CK_CHAR *encryptedData = NULL;
   CK_ULONG encryptedDataLen = 0;
   CK_MECHANISM mechanism = {
      CKM_DES_CBC, iv, sizeof(iv)
   };

   /* create DES secret key object */
   rc = funcs->C_CreateObject(hSession, 
         template, 
         sizeof(template) / sizeof (CK_ATTRIBUTE),
         &hKey);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR call to C_CreateObject failed, rc = %p\n", (void *)rc);
      return rc;
   }

   rc = symmetric_encryption(hSession, hKey, mechanism, data, sizeof(data), &encryptedData, &encryptedDataLen);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR call to symmetric_encryption failed, rc =%p\n", (void *)rc);
      rc = CKR_GENERAL_ERROR;
      goto done;
   }

   /* known answer test */
   rc = memcmp(cipher, encryptedData, sizeof(cipher));
   if (rc != 0) {
      fprintf(stderr, "ERROR test vector failed.\n");
      rc = CKR_GENERAL_ERROR;
      goto done;
   }

   rc = CKR_OK;

done:
   if (encryptedData) {
      free(encryptedData);
   }
   rc2 = funcs->C_DestroyObject(hSession, hKey);
   if (rc2 != CKR_OK) {
      fprintf(stderr, "Error deleting DES key...\n");
      if (rc == CKR_OK)
         rc = rc2;
   }

   return rc;
}

/* 
 * test CKM_DES3_ECB mechanism 
 */

int test_ecb_3des(CK_SESSION_HANDLE hSession) 
{
   CK_RV rc, rc2;
   CK_OBJECT_CLASS class = CKO_SECRET_KEY;
   CK_KEY_TYPE keyType = CKK_DES3;
   CK_CHAR label[] = "A DES3 ECB secret key object";
   CK_BYTE value[24] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF};
   CK_BBOOL true = TRUE;
   CK_ATTRIBUTE template[] = {
      {CKA_CLASS, &class, sizeof(class)},
      {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
      {CKA_TOKEN, &true, sizeof(true)},
      {CKA_LABEL, label, sizeof(label)},
      {CKA_ENCRYPT, &true, sizeof(true)},
      {CKA_VALUE, value, sizeof(value)}
   };

   CK_OBJECT_HANDLE hKey;
   CK_CHAR data[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xC0, 0xC0, 0xCA, 0xFE, 0x11, 0x22, 0x33, 0x44};
   /* expected result */
   CK_CHAR cipher[] = {0x5E, 0x69, 0x7E, 0x64, 0xE6, 0x16, 0xF5, 0x79, 0x7A, 0xD6, 0x0E, 0xDC, 0xED, 0x4A, 0xE9, 0x24};
   CK_CHAR *encryptedData = NULL;
   CK_ULONG encryptedDataLen = 0;
   CK_MECHANISM mechanism = {
      CKM_DES3_ECB, NULL, 0
   };

   /* create DES secret key object */
   rc = funcs->C_CreateObject(hSession, 
         template, 
         sizeof(template) / sizeof (CK_ATTRIBUTE),
         &hKey);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR call to C_CreateObject failed, rc = %p\n", (void *)rc);
      return rc;
   }

   rc = symmetric_encryption(hSession, hKey, mechanism, data, sizeof(data), &encryptedData, &encryptedDataLen);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR call to symmetric_encryption failed, rc =%p\n", (void *)rc);
      rc = CKR_GENERAL_ERROR;
      goto done;
   }

   /* known answer test */
   rc = memcmp(cipher, encryptedData, sizeof(cipher));
   if (rc != 0) {
      fprintf(stderr, "ERROR test vector failed.\n");
      rc = CKR_GENERAL_ERROR;
      goto done;
   }  

   rc = CKR_OK;

done:
   if (encryptedData) {
      free(encryptedData);
   }
   rc2 = funcs->C_DestroyObject(hSession, hKey);
   if (rc2 != CKR_OK) {
      fprintf(stderr, "Error deleting 3DES key...\n");
      if (rc == CKR_OK)
         rc = rc2;
   }

   return rc;
}

/* 
 * test CMK_DES3_CBC mechanism
 */

int test_cbc_3des(CK_SESSION_HANDLE hSession) 
{
   CK_RV rc, rc2;
   CK_OBJECT_CLASS class = CKO_SECRET_KEY;
   CK_KEY_TYPE keyType = CKK_DES3;
   CK_CHAR label[] = "A DES3 secret key object";
   CK_BYTE value[24] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF};
   CK_BBOOL true = TRUE;
   CK_ATTRIBUTE template[] = {
      {CKA_CLASS, &class, sizeof(class)},
      {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
      {CKA_TOKEN, &true, sizeof(true)},
      {CKA_LABEL, label, sizeof(label)},
      {CKA_ENCRYPT, &true, sizeof(true)},
      {CKA_VALUE, value, sizeof(value)}
   };

   CK_OBJECT_HANDLE hKey;
   CK_BYTE iv[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11};
   CK_CHAR data[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xC0, 0xC0, 0xCA, 0xFE, 0x11, 0x22, 0x33, 0x44};
   /* expected result */
   CK_CHAR cipher[] = {0xA6, 0x19, 0xA1, 0xB1, 0x36, 0x07, 0xCB, 0x31, 0x83, 0x48, 0xDB, 0x30, 0x63, 0xC0, 0x12, 0xBB };
   CK_CHAR *encryptedData = NULL;
   CK_ULONG encryptedDataLen = 0;
   CK_MECHANISM mechanism = {
      CKM_DES3_CBC, iv, sizeof(iv)
   };
   /* create DES secret key object */
   rc = funcs->C_CreateObject(hSession, 
         template, 
         sizeof(template) / sizeof (CK_ATTRIBUTE),
         &hKey);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR call to C_CreateObject failed, rc = %p\n", (void *)rc);
      return rc;
   }

   rc = symmetric_encryption(hSession, hKey, mechanism, data, sizeof(data), &encryptedData, &encryptedDataLen);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR call to symmetric_encryption failed, rc =%p\n", (void *)rc);
      rc = CKR_GENERAL_ERROR;
      goto done;
   }

   /* known answer test */
   rc = memcmp(cipher, encryptedData, sizeof(cipher));
   if (rc != 0) {
      fprintf(stderr, "ERROR test vector failed.\n");
      rc = CKR_GENERAL_ERROR;
      goto done;
   }  

   rc = CKR_OK;

done:
   if (encryptedData) {
      free(encryptedData);
   }
   rc2 = funcs->C_DestroyObject(hSession, hKey);
   if (rc2 != CKR_OK) {
      fprintf(stderr, "Error deleting 3DES key...\n");
      if (rc == CKR_OK)
         rc = rc2;
   }

   return rc;
}



/* General symmetric encryption, given a handle to a key object and a mechanism */
/* Caller needs to free memory for encryptedData */

CK_RV symmetric_encryption(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey, 
      CK_MECHANISM mechanism, CK_CHAR *data, CK_ULONG data_sz, 
      CK_CHAR **encryptedData, CK_ULONG *encryptedData_sz)
{
   CK_RV rc;
   CK_CHAR *this_encryptedData;

   /* init */
   rc = funcs->C_EncryptInit(hSession, &mechanism, hKey);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR call to C_EncryptInit failed, rc = %p\n", (void *)rc);
      return rc;
   }

   rc = funcs->C_Encrypt(hSession, data, data_sz, NULL, encryptedData_sz);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR failed to get size of encrypted data calling C_Encrypt, rc = %p\n", (void *)rc);
      return rc;
   }

   this_encryptedData = (CK_CHAR *)malloc((*encryptedData_sz)*sizeof(CK_CHAR));

   /* encrypt */
   rc = funcs->C_Encrypt(hSession, data, data_sz, this_encryptedData, encryptedData_sz);
   if (rc != CKR_OK) {
      fprintf(stderr, "ERROR call to C_EncryptUpdate failed, rc = %p\n", (void *)rc);
      return rc;
   }

   *encryptedData = this_encryptedData;

   rc = CKR_OK;
   return rc;
}
