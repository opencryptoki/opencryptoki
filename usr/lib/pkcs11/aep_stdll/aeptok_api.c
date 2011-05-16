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

#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "aeptok_api.h"

extern int cryptoki_aep_avail;

static int aep_initialised = FALSE;

static AEP_CONNECTION_ENTRY aep_app_conn_table[MAX_PROCESS_CONNECTIONS];
static pid_t	recorded_pid = 0;

static pthread_mutex_t AEP_ThreadPool_mutex=PTHREAD_MUTEX_INITIALIZER;


static
AEP_RV 
GetAEPConnection(AEP_CONNECTION_HNDL *hConnection)
{
	int count;
	AEP_RV rv = AEP_R_OK;
	pid_t curr_pid = getpid();
	
	pthread_mutex_lock(&AEP_ThreadPool_mutex);
	
	// Check if this is the first time this is being called
	// from the current process
	//	if (recorded_pid != curr_pid) {

	if (aep_initialised != TRUE) {
		aep_initialised = TRUE;		
		recorded_pid = curr_pid;

		AEP_Finalize();
		
		/*Initialise the AEP API*/
		if ( (rv = AEP_Initialize(NULL)) != AEP_R_OK) {
			aep_initialised = FALSE;		
			recorded_pid = 0;
			goto end;
		}
		
		/*Set the AEP big num call back functions*/	
		rv = AEP_SetBNCallBacks(&GetBigNumSize, &MakeAEPBigNum,
					&ConvertAEPBigNum);
		
		if (rv != AEP_R_OK) {
			aep_initialised = FALSE;		
			recorded_pid = 0;
			goto end;
		}
		
		/*Init the structures*/
		for (count = 0;count < MAX_PROCESS_CONNECTIONS;count ++) {
			aep_app_conn_table[count].conn_state = NotConnected;
			aep_app_conn_table[count].conn_hndl  = 0;
		}
		
		
		if ( (rv = AEP_OpenConnection(hConnection)) != AEP_R_OK) {
			/* a problem here, assume AEP subsystem is dead ! */
			cryptoki_aep_avail = FALSE;
			aep_initialised = FALSE;
			recorded_pid = 0;
			OCK_LOG_ERR(ERR_DEVICE_ERROR);
			goto end;
		}
		
		aep_app_conn_table[0].conn_state = InUse;
		aep_app_conn_table[0].conn_hndl = *hConnection;
		goto end;
	}
	for (count = 0;count < MAX_PROCESS_CONNECTIONS;count ++) {
		if (aep_app_conn_table[count].conn_state == Connected) {
			aep_app_conn_table[count].conn_state = InUse;
			*hConnection = aep_app_conn_table[count].conn_hndl;
			goto end;
		}
	}
	
	/*If no connections available, we try to open a new one*/
	for (count = 0;count < MAX_PROCESS_CONNECTIONS;count ++) {
		if (aep_app_conn_table[count].conn_state == NotConnected) {
			rv = AEP_OpenConnection(hConnection);
			
			if ( rv != AEP_R_OK){
				// a problem here, assume AEP subsystem is dead !
				cryptoki_aep_avail = FALSE;
				OCK_LOG_ERR(ERR_DEVICE_ERROR);
				goto end;
			}
			aep_app_conn_table[count].conn_state = InUse;		
			aep_app_conn_table[count].conn_hndl = *hConnection;
			goto end;
		}
	}
	rv = AEP_R_GENERAL_ERROR;
 end:
	pthread_mutex_unlock(&AEP_ThreadPool_mutex);
	return rv;
}


static
AEP_RV ReturnAEPConnection(AEP_CONNECTION_HNDL hConnection) 
{
	int count;
	
	pthread_mutex_lock(&AEP_ThreadPool_mutex);
	
	/*Find the connection */
	for(count = 0;count < MAX_PROCESS_CONNECTIONS;count ++) {
		if (aep_app_conn_table[count].conn_hndl == hConnection) {
			aep_app_conn_table[count].conn_state = Connected;
			break;
		}
	}
	
	pthread_mutex_unlock(&AEP_ThreadPool_mutex);	
	return AEP_R_OK;	
}


int
AEP_RSA_public_encrypt(unsigned long in_data_len,
		       unsigned char *in_data,
		       unsigned char *out_data,
		       RSA *rsa)
{
	AEP_RV rv;
	AEP_CONNECTION_HNDL hConnection;
	BIGNUM rr;
	BIGNUM *a;

	if ( GetAEPConnection(&hConnection) != AEP_R_OK) {
		ReturnAEPConnection(hConnection);
		return 0;
	}
	
	if ( (a = BN_new()) == NULL) {
		ReturnAEPConnection(hConnection);
		return 0;
	}
	
	BN_bin2bn( in_data, in_data_len, a);
	
	rv = AEP_ModExp(hConnection, (void*)a, (void*) rsa->e,
			(void*) rsa->n, (void*)&rr, NULL);
	
	if (rv!=AEP_R_OK) {
		ReturnAEPConnection(hConnection);
		BN_free(a);
		return 0;
	}
	
	memset(out_data, 0, in_data_len);
	if ( rr.top * 4 > in_data_len) {
		ReturnAEPConnection(hConnection);
		BN_free(a);
		return 0;
	}
	invert( out_data, (unsigned char*) rr.d, rr.top*4);
	
	ReturnAEPConnection(hConnection);
	BN_free(a);
	return 1;
}

int
AEP_RSA_private_decrypt(unsigned long in_data_len,
			unsigned char *in_data,
			unsigned char *out_data,
			RSA *rsa)
{
	AEP_RV rv ;
	AEP_CONNECTION_HNDL hConnection;
	BIGNUM rr;
	BIGNUM* a;

	if ( GetAEPConnection(&hConnection) != AEP_R_OK) {	
		ReturnAEPConnection(hConnection);	
		return 0;
	}
	
	if(!rsa->d || !rsa->n )	{
		ReturnAEPConnection(hConnection);
		return 0;
	}
	if ( (a = BN_new()) == NULL) {
		ReturnAEPConnection(hConnection);	
		return 0;
	}
	
	BN_bin2bn( in_data, in_data_len, a);			
	
	if(!rsa->p || !rsa->q || !rsa->dmp1 || !rsa->dmq1 || !rsa->iqmp) {
		rv = AEP_ModExp(hConnection, (void *)a,
				(void *)(rsa->d), (void *)(rsa->n),
				(void *)&rr, NULL);
	} else {
		rv = AEP_ModExpCrt(hConnection, (void *)a, (void *)(rsa->p),
				   (void *)(rsa->q), (void *)(rsa->dmp1),
				   (void *)(rsa->dmq1), (void *)(rsa->iqmp),
				   (void *)&rr, NULL);
	}

	if (rv!=AEP_R_OK) {
		ReturnAEPConnection(hConnection);
		BN_free(a);
		return 0;
	}

	memset(out_data, 0, in_data_len);
	if ( rr.top * 4 > in_data_len) {
		ReturnAEPConnection(hConnection);
		BN_free(a);
		return 0;
	}
	invert( out_data, (unsigned char *) rr.d, rr.top*4);

	ReturnAEPConnection(hConnection);	
	BN_free(a);

	return 1;
}	
	
/* BigNum call back functions, used to convert OpenSSL 
 * bignums into AEP bignums
 */

AEP_RV
GetBigNumSize(void* ArbBigNum, AEP_U32* BigNumSize)
{
	BIGNUM* bn;

	/*Cast the ArbBigNum pointer to our BIGNUM struct*/
	bn = (BIGNUM*) ArbBigNum;

	/*Size of the bignum in bytes is equal to the bn->top
	  (no of 32 bit words) multiplies by 4*/
	*BigNumSize = bn->top << 2;

	return AEP_R_OK;
}

AEP_RV MakeAEPBigNum(void* ArbBigNum,
		     AEP_U32 BigNumSize,
		     unsigned char* AEP_BigNum)
{
	BIGNUM* bn;
	unsigned char* buf;
	int i;

	/*Cast the ArbBigNum pointer to our BIGNUM struct*/
	bn = (BIGNUM*) ArbBigNum;

	if (BigNumSize != bn->top * 4) 
		return AEP_R_GENERAL_ERROR;
	
	memcpy(AEP_BigNum, (unsigned char *) bn->d, BigNumSize);

	return AEP_R_OK;
}

AEP_RV ConvertAEPBigNum(void* ArbBigNum,
			AEP_U32 BigNumSize,
			unsigned char* AEP_BigNum)
{
	BIGNUM* bn;
	int i;

	bn = (BIGNUM*)ArbBigNum;

	/*Make sure big num is a multiple of 4*/
	if (BigNumSize & 3 != 0) {
		exit(1);
	}
	bn->top = BigNumSize >> 2;
	
	bn->d = (unsigned long*)AEP_malloc(BigNumSize);

	memcpy( (unsigned char *) bn->d, AEP_BigNum, BigNumSize);
	
	return AEP_R_OK;
}

static
void
invert(unsigned char* dest, unsigned char* orig, int len)
{
  while (len--)
    *dest++ = orig[len];
}
