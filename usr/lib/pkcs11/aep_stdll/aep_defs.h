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
/* Filename:	aep_defs.h					*/
/* Description:	Contains various constants used in the AEP API	*/
/*								*/
/****************************************************************/


#ifndef AEPdefs_H 
#define AEPdefs_H 1

#define AEP_INVALID_HANDLE	0

/*******Return Values / Error Codes************/


#define AEP_R_OK                                0x00000000
#define AEP_R_GENERAL_ERROR                     0x10000001
#define AEP_R_HOST_MEMORY                       0x10000002
#define AEP_R_FUNCTION_FAILED                   0x10000006
#define AEP_R_ARGUMENTS_BAD                     0x10020000
#define AEP_R_SIGNATURE_INVALID			0x10020001
#define AEP_R_NO_TARGET_RESOURCES		0x10030000
#define AEP_R_SOCKERROR				0x10000010
#define AEP_R_SOCKEOF				0x10000011
#define AEP_R_CONNECTION_HANDLE_INVALID         0x100000B3
#define AEP_R_TRANSACTION_HANDLE_INVALID	0x10040000
#define AEP_R_TRANSACTION_NOT_READY		0x00010000
#define AEP_R_TRANSACTION_CLAIMED		0x10050000
#define AEP_R_TIMED_OUT				0x10060000
#define AEP_R_FXN_NOT_IMPLEMENTED		0x10070000
#define AEP_R_TARGET_ERROR			0x10080000
#define AEP_R_DAEMON_ERROR			0x10090000
#define AEP_R_KEY_NOT_FOUND			0x100a0000
#define AEP_R_INVALID_CTX_ID			0x10009000
#define AEP_R_NO_KEY_MANAGER			0x1000a000
#define AEP_R_MUTEX_BAD                         0x000001A0
#define AEP_R_AEPAPI_NOT_INITIALIZED		0x10000190
#define AEP_R_AEPAPI_ALREADY_INITIALIZED	0x10000191
#define AEP_R_NO_MORE_CONNECTION_HNDLS		0x10000200
#define AEP_R_MISSING_REGISTRY_ENTRY		0x10000201

/*If not defined, define various constants*/
#ifndef NULL_PTR
#define NULL_PTR	0
#endif

#ifndef NULL
#define NULL		0
#endif

#ifndef FALSE
#define FALSE		0
#endif

#ifndef TRUE
#define TRUE		1
#endif

#define AEP_COND_ATTR_TRUE  TRUE
#define AEP_COND_ATTR_FALSE FALSE
#define SEM_LOCKED          1
#define SEM_UNLOCKED        0

#define AEP_IO_ERROR	 	-1
#define AEP_IO_ERROR_TIMEOUT	-2	
#define AEP_IO_ERROR_NO_SPACE	-3

#endif




