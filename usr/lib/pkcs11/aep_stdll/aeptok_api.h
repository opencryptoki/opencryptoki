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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS'
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

#include <unistd.h>

#include "aep_api.h"
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "openssl/bio.h"

typedef enum{
	NotConnected=	0,
	Connected=		1,
	InUse=			2
} AEP_CONNECTION_STATE;

#define MAX_PROCESS_CONNECTIONS 512
#define RAND_BLK_SIZE 1024

typedef struct AEP_CONNECTION_ENTRY{
	AEP_CONNECTION_STATE 	conn_state;
	AEP_CONNECTION_HNDL	 	conn_hndl;
} AEP_CONNECTION_ENTRY;

static
AEP_RV GetAEPConnection(AEP_CONNECTION_HNDL *hConnection);
static
AEP_RV ReturnAEPConnection(AEP_CONNECTION_HNDL hConnection);

int AEP_RSA_public_encrypt(unsigned long in_data_len, unsigned char *in_data,
			   unsigned char *out_data, RSA *rsa);
int AEP_RSA_private_decrypt(unsigned long in_data_len, unsigned char *in_data,
			    unsigned char *out_data, RSA *rsa);

AEP_RV GetBigNumSize(void* ArbBigNum, AEP_U32* BigNumSize);
AEP_RV MakeAEPBigNum(void* ArbBigNum, AEP_U32 BigNumSize, 
		     unsigned char* AEP_BigNum);
AEP_RV ConvertAEPBigNum(void* ArbBigNum, AEP_U32 BigNumSize, 
			unsigned char* AEP_BigNum);
static
void invert(unsigned char* dest, unsigned char* orig, int len);
