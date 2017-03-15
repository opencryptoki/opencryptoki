 /*
  * COPYRIGHT (c) International Business Machines Corp. 2001-2017
  *
  * This program is provided under the terms of the Common Public License,
  * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
  * software constitutes recipient's acceptance of CPL-1.0 terms which can be
  * found in the file LICENSE file or at
  * https://opensource.org/licenses/cpl1.0.php
  */

#ifndef _STDLL_PKCS_FUNCTIONS_H
#define _STDLL_PKCS_FUNCTIONS_H

extern CK_RV SC_GetTokenInfo();
extern CK_RV SC_GetMechanismList();
extern CK_RV SC_GetMechanismInfo();
extern CK_RV SC_OpenSession();
extern CK_RV SC_CloseSession();
extern CK_RV SC_GetSessionInfo();
extern CK_RV SC_Login();
extern CK_RV SC_Logout();
extern CK_RV SC_CreateObject();
extern CK_RV SC_CopyObject();
extern CK_RV SC_DestroyObject();
extern CK_RV SC_GetAttributeValue();
extern CK_RV SC_SetAttributeValue();
extern CK_RV SC_FindObjectsInit();
extern CK_RV SC_FindObjects();
extern CK_RV SC_FindObjectsFinal();
extern CK_RV SC_EncryptInit();
extern CK_RV SC_Encrypt();
extern CK_RV SC_DecryptInit();
extern CK_RV SC_Decrypt();
extern CK_RV SC_SignInit();
extern CK_RV SC_Sign();
extern CK_RV SC_Verify();
extern CK_RV SC_VerifyRecover();
extern CK_RV SC_GenerateKey();
extern CK_RV SC_GenerateKeyPair();
extern CK_RV SC_WrapKey();
extern CK_RV SC_UnwrapKey();
extern CK_RV SC_GenerateRandom();

#endif
