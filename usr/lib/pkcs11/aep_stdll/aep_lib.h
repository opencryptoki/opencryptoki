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
/* Filename:	aep_lib.h					*/
/* Description:	Contains OS specific details			*/
/*								*/
/****************************************************************/


#ifndef AEPlib_H 
#define AEPlib_H 1

#if defined(AEP_Win32) 

#define AEP_THR_FN_CALLING_CONVENTION DWORD WINAPI

# if defined(AEPAPI_DLL_EXPORT)

# define AEPAPI_FDEF(rtype,name,params) \
	__declspec(dllexport) rtype name params

# elif defined(AEPAPI_DLL_LOAD)

# define AEPAPI_FDEF(rtype,name,params) \
	typedef rtype (*name##_ft)params; \
	extern name##_ft name

# define AEPAPI_FDEF_INIT(name) name##_ft name = NULL;

# define AEPAPI_GETPROCADDRESS(hModule, name) \
	name = (name##_ft) GetProcAddress(hModule, #name)

extern BOOL AEP_LoadDLL(char *path);

# else	/* Default to import */

# define AEPAPI_FDEF(rtype,name,params) \
	__declspec(dllimport) rtype name params

# endif /* if defined(AEP_DLL_EXPORT) */

#elif defined(AEP_GENERIC)

#define AEP_SLIB_CALLING_CONVENTION

#else
#error no OS type defined (needs to be one of AEP_Win32, AEP_Win16, AEP_GENERIC)
#endif /* OS Type */
     
#endif /* ifndef AEPlib_H */

