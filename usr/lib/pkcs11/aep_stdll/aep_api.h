/* 
 * Copyright (c) 1999-2002 AEP Systems Ltd.
 * Bray Business Park, Southern Cross Route, Bray, Co. Wicklow, Ireland.
 * All Rights Reserved.
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, 
 * this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation 
 * and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of AEP Systems Ltd. nor the names of its contributors 
 * may be used to endorse or promote products derived from this software 
 * without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
 * 
 */

/****************************************************************/
/*							      	*/
/* Filename:	aep_api.h				      	*/
/* Description:	AEP API Include file, fxn prototypes for the	*/
/*		AEP API.					*/
/*	      							*/
/****************************************************************/

#ifndef aep_api_H 
#define aep_api_H 1

#include "aep_lib.h"
#include "aep_defs.h"
#include "aep_types.h"

AEP_SLIB_CALLING_CONVENTION 
AEP_RV AEP_Initialize( AEP_VOID_PTR pInitArgs);


AEP_SLIB_CALLING_CONVENTION 
AEP_RV AEP_Finalize( );

AEP_SLIB_CALLING_CONVENTION 
AEP_RV AEP_SetBNCallBacks( AEP_RV (*GetBigNumSizeFunc)(),
			   AEP_RV (*MakeAEPBigNumFunc)(),
			   AEP_RV (*ConverAEPBigNumFunc)() );

AEP_SLIB_CALLING_CONVENTION
AEP_RV AEP_OpenConnection( AEP_CONNECTION_HNDL_PTR phConnection);

AEP_SLIB_CALLING_CONVENTION 
AEP_RV AEP_CloseConnection( AEP_CONNECTION_HNDL hConnection);

AEP_SLIB_CALLING_CONVENTION 
AEP_RV AEP_ModExp( AEP_CONNECTION_HNDL  hConnection,
		   AEP_VOID_PTR	        pA,
		   AEP_VOID_PTR	        pP,
		   AEP_VOID_PTR		pN,
		   AEP_VOID_PTR		pResult,
		   AEP_TRANSACTION_ID*	pidTransID);

AEP_SLIB_CALLING_CONVENTION 
AEP_RV AEP_ModExpCrt( AEP_CONNECTION_HNDL	hConnection,
		      AEP_VOID_PTR		pA,
		      AEP_VOID_PTR		pP,
		      AEP_VOID_PTR		pQ,
		      AEP_VOID_PTR		pDmp1,
		      AEP_VOID_PTR		pDmq1,
		      AEP_VOID_PTR		pIqmp,
		      AEP_VOID_PTR		pResult,
		      AEP_TRANSACTION_ID*	pidTransId );


AEP_SLIB_CALLING_CONVENTION 
AEP_RV AEP_GenRandom( AEP_CONNECTION_HNDL	hConnection,
		      AEP_U32			Len,
		      AEP_U32			Type,
		      AEP_VOID_PTR		pResult,
		      AEP_TRANSACTION_ID*	pidTransID );

AEP_SLIB_CALLING_CONVENTION char ** AEP_GetAPIVersion ();

#endif
