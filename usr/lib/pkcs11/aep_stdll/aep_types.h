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
/*								*/
/* Filename:	aep_types.h					*/
/* Description:	AEP typedefs					*/
/*								*/
/****************************************************************/


#ifndef aep_types_H 
#define aep_types_H 1


typedef unsigned char		AEP_U8;
typedef char			AEP_CHAR;
typedef AEP_U8			AEP_BBOOL;

typedef unsigned short  	AEP_U16;
typedef unsigned int		AEP_U32;

#if defined(AEP_Win32)

typedef unsigned _int64		AEP_U64;

#elif defined(AEP_GENERIC)

typedef unsigned long long	AEP_U64;

#endif


typedef AEP_U32		AEP_FLAGS;
typedef AEP_U8	    	*AEP_U8_PTR;
typedef AEP_CHAR    	*AEP_CHAR_PTR;
typedef AEP_U16		*AEP_U16_PTR;
typedef AEP_U32		*AEP_U32_PTR;
typedef AEP_U64		*AEP_U64_PTR;
typedef void        	*AEP_VOID_PTR;


typedef AEP_VOID_PTR 	        *AEP_VOID_PTR_PTR;
typedef AEP_U32		        AEP_CONNECTION_HNDL;

typedef AEP_CONNECTION_HNDL 	*AEP_CONNECTION_HNDL_PTR;
typedef AEP_U64			AEP_TRANSACTION_HNDL;

typedef AEP_TRANSACTION_HNDL	*AEP_TRANSACTION_HNDL_PTR;

typedef AEP_U32			AEP_TRANSACTION_ID;

typedef AEP_TRANSACTION_ID 	*AEP_TRANSACTION_ID_PTR;

typedef AEP_U64			AEP_KEY_ID;
typedef AEP_U64			AEP_CONTEXT_ID;

typedef AEP_U32			AEP_RV;

typedef struct AEP_BYTEBLOCK {
	AEP_U32		Len;
	AEP_U8_PTR	ptr;
} AEP_BYTEBLOCK;


#endif
