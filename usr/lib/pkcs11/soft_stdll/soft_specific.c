/* (C) COPYRIGHT International Business Machines Corp. 2006          */

/***************************************************************************
                          Change Log
                          ==========
       10/16/06   Daniel H Jones (danjones@us.ibm.com)
                  Initial file created.
 
****************************************************************************/
#include "pkcs11types.h"
#include "tok_struct.h"

CK_CHAR manuf[] = "IBM Corp.";
CK_CHAR model[] = "IBM SoftTok ";
CK_CHAR descr[] = "IBM PKCS#11 Soft token";
CK_CHAR label[] = "IBM OS PKCS#11   ";


CK_RV T_Initialize(char * Correlator, CK_SLOT_ID SlotNumber, TOKEN_STRUCT ** token_functions)
{
   *token_functions = &swtok_specific;
   return CKR_OK;
}

CK_RV T_GetMechanismList(CK_MECHANISM_TYPE_PTR pMechanismList,
			 CK_ULONG_PTR pulCount)
{
    (*pulCount) = 0;
    
    return CKR_OK;
}

CK_RV T_GetMechanismInfo(CK_MECHANISM_TYPE type, 
			 CK_MECHANISM_INFO_PTR pInfo)
{
    return CKR_MECHANISM_INVALID;
}
