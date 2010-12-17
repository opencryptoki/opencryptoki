
/*
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2005 International Business
 * Machines Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the Common Public License as published by
 * IBM Corporation; either version 1 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Common Public License for more details.
 *
 * You should have received a copy of the Common Public License
 * along with this program; if not, a copy can be viewed at
 * http://www.opensource.org/licenses/cpl1.0.php.
 */

/* (C) COPYRIGHT International Business Machines Corp. 2001, 2002, 2005 */

/***************************************************************************
                          Change Log
                          ==========
       4/25/03    Kapil Sood (kapil@corrent.com)
                  Added DH key pair generation and DH shared key derivation
                  functions.
****************************************************************************/


#include <pthread.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <grp.h>

#include <pkcs11/pkcs11types.h>
#include <pkcs11/stdll.h>

#include "defs.h"
#include "host_defs.h"
#include "tok_spec_struct.h"
#include "h_extern.h"
#include <pkcs11/pkcs32.h>

#include "tpm_specific.h"

#include "log.h"

#include "../api/apiproto.h"

/* Declared in obj_mgr.c */
extern pthread_rwlock_t obj_list_rw_mutex;

char *pk_dir;
void SC_SetFunctionList(void);

//#define SESSION_MGR_FIND(x)   session_mgr_find(x,0) // All these need to get the lock
#define SESSION_MGR_FIND(x)   session_mgr_find(x) // All these need to get the lock

// Both of the strings below have a length of 32 chars and must be
// padded with spaces, and non-null terminated.
//
#if 0
#define PKW_CRYPTOKI_VERSION_MAJOR      2
#define PKW_CRYPTOKI_VERSION_MINOR      1
#define PKW_CRYPTOKI_MANUFACTURER       "IBM Corp.                       "
#define PKW_CRYPTOKI_LIBDESC            "PKCS#11 LIGHTWT   for IBM 4758  "
#define PKW_CRYPTOKI_LIB_VERSION_MAJOR  1
#define PKW_CRYPTOKI_LIB_VERSION_MINOR  0
#endif

// Maximum number of supported devices (rather arbitrary)
//
#define PKW_MAX_DEVICES                10

// Netscape/SSL is fairly timing-sensitive so can't always use a debugger
//
// If the CRYPTOKI_DEBUG environment variable is defined, information
// about each successful PKCS#11 call made is written to the file named
// in that environment variable.
//
// If the CRYPTOKI_PROFILE environment variable is defined, information
// about the amount of time spent in each PKCS#11 API during a "run"
//
// If the CRYPTOKI_DEBUG environment variable is defined, information
// about each successful PKCS#11 call made is written to the file named
// in that environment variable.
//
// If the CRYPTOKI_PROFILE environment variable is defined, information
// about the amount of time spent in each PKCS#11 API during a "run"
// (i.e., from _DLL_InitTerm init call to _DLL_InitTerm term call) is
// appended to the file named in that environment variable.
//
// If the CRYPTOKI_STATS_FILE environment variable is defined, information
// about various internal metrics at the end of a "run" is appended to
// the file named in that environment variable.  The CRYPTOKI_STATS
// environment variable specifies the argument(s) that are passed to
// the function that returns the metrics to specify which metric(s) are
// returned.
//
#define MAXFILENAME 1024

static char  *debugfilepathbuffer;
static int  debugon = 1;
int  debugfile = 0;
#define FFLUSH(x) 

pid_t  initedpid=0;  // for initialized pid


CK_ULONG  usage_count = 0; // variable for number of times the DLL has been used.

CK_C_INITIALIZE_ARGS cinit_args = { NULL, NULL, NULL, NULL, 0, NULL };

CK_BBOOL
st_Initialized()
{
  if (initialized == FALSE ) return FALSE;
#if !(LINUX)
  if (initedpid != getpid()) return FALSE;
#endif
  return TRUE;

}


#ifdef SPINXPL
extern int spinxplfd;
extern int spin_created;
#endif

// ----------- SAB XXX XXX
//
void
Fork_Initializer(void)
{
  //    initialized == FALSE; // Get the initialization to be not true

#ifdef SPINXPL
	spinxplfd = -1;
	spin_created = 0;
#endif


          // Force logout.  This cleans out the private session and list
          // and cleans out the private object map
      session_mgr_logout_all();

          // Clean out the public object map
          // First parm is no longer used..
      object_mgr_purge_map((SESSION *)0xFFFF, PUBLIC);
      object_mgr_purge_map((SESSION *)0xFFFF, PRIVATE);

          // This should clear the entire session list out
      session_mgr_close_all_sessions();


      //next_session_handle = 1; // Make is so sessions start with 1
      //next_object_handle = 1;

      // Clean out the global login state variable
      // When implemented...  Although logout_all should clear this up.

      // Once the object_map is flushed, the obj_lists (public and private) are
      // both just linked lists that have to be freed up...
      //logit("%s:%d:  tokenobj  publ 0x%08x  priv 0x%08x",__FILE__,__LINE__,publ_token_obj_list, priv_token_obj_list);

      while (priv_token_obj_list) {
            priv_token_obj_list = dlist_remove_node(priv_token_obj_list,
                                                  priv_token_obj_list);
      }

      //logit("%s:%d:1  tokenobj  publ 0x%08x  priv 0x%08x",__FILE__,__LINE__,publ_token_obj_list, priv_token_obj_list);

      while (publ_token_obj_list) {
            publ_token_obj_list = dlist_remove_node(publ_token_obj_list,publ_token_obj_list);
      }

      //logit("%s:%d:2  tokenobj  publ 0x%08x  priv 0x%08x",__FILE__,__LINE__,publ_token_obj_list, priv_token_obj_list);


      // Need to do something to prevent the shared memory from having the
      // objects loaded again.... The most likely place is in the obj_mgr file
      // where the object is added to shared memory (object_mgr_add_to_shm) a
      // query should be done to the appropriate object list....

}
// ----------- SAB XXX XXX XXX END


#ifdef ALLLOCK
   #define LOCKIT   pthread_mutex_lock(&native_mutex)
   #define LLOCK
   #define UNLOCKIT   pthread_mutex_unlock(&native_mutex)
#else
#ifdef DEBLOCK
         #define LOCKIT
         #define LLOCK   pthread_mutex_lock(&native_mutex)
         #define UNLOCKIT   pthread_mutex_unlock(&native_mutex)
#else
         #define LOCKIT
         #define LLOCK
         #define UNLOCKIT
#endif
#endif

int
APISlot2Local(snum)
   CK_SLOT_ID  snum;
{
   int i;

   return(token_specific.t_slot2local(snum));

}


#define  SLT_CHECK  \
   CK_SLOT_ID     slot_id; \
   int            sid1; \
 \
   if ( (sid1 = APISlot2Local(sid)) != -1 ){ \
      slot_id = sid1; \
   } else { \
      return CKR_ARGUMENTS_BAD; \
   }


#define SESSION_HANDLE   sSession.sessionh
#define SLOTID    APISlot2Local(sSession.slotID)

#define  SESS_SET \
   CK_SESSION_HANDLE  hSession; \
\
   hSession = sSession.sessionh;


// More efficient long reverse

CK_ULONG long_reverse( CK_ULONG x )
{
#ifdef _POWER   // Power Architecture requires reversal to talk to adapter
         return (
               ((0x000000FF & x)<<24) |
               ((0x0000FF00 & x)<<8) |
               ((0x00FF0000 & x)>>8) |
               ((0xFF000000 & x)>>24) );
#else
         return (x); // Others don't require  reversal.
#endif

}



// verify that the mech specified is in the
// mech list for this token... Common code requires this 
// to be added
CK_RV 
validate_mechanism(CK_MECHANISM_PTR  pMechanism)
{
   CK_ULONG i;
   
   for (i=0; i< mech_list_len;i++){
      if ( pMechanism->mechanism == mech_list[i].mech_type){
	return CKR_OK;
      }
   }
   ock_log_err(OCK_E_MECH_INV);
   return CKR_MECHANISM_INVALID;
}


#define VALID_MECH(p) \
   if ( validate_mechanism(p) != CKR_OK){ \
      rc = CKR_MECHANISM_INVALID; \
      goto done; \
   } \


// Defines to allow NT code to work correctly
#define WaitForSingleObject(x,y)  pthread_mutex_lock(&(x))
#define ReleaseMutex(x)           pthread_mutex_unlock(&(x))

//
//
//

void
init_data_store(char *directory)
{
	char *pkdir;

	if ( (pkdir = getenv("PKCS_APP_STORE")) != NULL) {
		pk_dir =  (char *) malloc(strlen(pkdir)+1024);
		memset(pk_dir, 0, strlen(pkdir)+1024);
		sprintf(pk_dir,"%s/%s",pkdir,SUB_DIR);
		ock_log_err_ex(OCK_E_GENERIC, "Using custom data store location: %s", pk_dir);
	} else {
		pk_dir  = (char *)malloc(strlen(directory)+25);
		memset(pk_dir, 0, strlen(directory)+25);
		sprintf(pk_dir,"%s",directory);
	}
}


#include <pwd.h>  // SAB XXX XXX XXX
//
//
//In an STDLL this is called once for each card in the system
//therefore the initialized only flags certain one time things
//However in the case of  a lightened accelerator, the cards
//are all  agregated together in a single token.  Therefore
//the correlator should be a list of device names which have
//either the correct clu or the crypt light adapter...
//
CK_RV ST_Initialize( void **FunctionList,
                     CK_SLOT_ID SlotNumber,
                     char *Correlator)
{
	int    i, j;
	CK_RV  rc = CKR_OK;
	char   tstr[2048];
	char *pkdir;
	struct passwd  *pw,*epw; // SAB XXX XXX
	uid_t    userid,euserid;



	// Check for root user or Group PKCS#11 Membershp
	// Only these are qllowed.
	userid = getuid();
	euserid = geteuid();

	if ( userid != 0 && euserid != 0 ) { // Root or effective Root is ok
		struct group *grp;
		char *name,*g;
		int   rc = 0;
		int   index = 0;
		gid_t  gid,egid;
		grp = getgrnam("pkcs11");
		if ( grp ) {
			// Check for member of group..

			// SAB  get login seems to not work with some instances
			// of application invocations (particularly when forked).  So
			// we need to get the group informatiion.  
			// Really need to take the uid and map it to a name.
			pw = getpwuid(userid);
			epw = getpwuid(euserid);
			gid = getgid();
			egid = getegid();

			if ( gid == grp->gr_gid || egid == grp->gr_gid){
				rc = 1;
			} else {
				i = 0;
				while (grp->gr_mem[i]) {
					if (pw) {
						if ( strncmp(pw->pw_name, grp->gr_mem[i],strlen(pw->pw_name)) == 0 ){
							rc = 1;
							break;
						}
					}
					if (epw) {
						if ( strncmp(epw->pw_name, grp->gr_mem[i],strlen(epw->pw_name)) == 0 ){
							rc = 1;
							break;
						}
					}
					i++;
				}
			}
			if (rc == 0 ){
				ock_log_err(OCK_E_FUNC);
				return CKR_FUNCTION_FAILED;
			}
		} else {
			ock_log_err(OCK_E_FUNC);
			return CKR_FUNCTION_FAILED;
		}
	}

#if !(LINUX)
	// Linux we will assume that the upper level has filtered
	// this and we need to initialize the code
	// go through this only once for each application
	if (st_Initialized() == TRUE){
		return CKR_OK;
	}
#elif (LINUX)
	// assume that the upper API prevents multiple calls of initialize
	// since that only happens on C_Initialize and that is the
	// resonsibility of the upper layer..
	initialized = FALSE; /// So the rest of the code works correctly
#endif

	// If we're not already initialized, grab the mutex and do the
	// initialization.  Check to see if another thread did so while we
	// were waiting...
	//
	// One of the things we do during initialization is create the mutex for
	// PKCS#11 operations; until we do so, we have to use the native mutex...
	//
	WaitForSingleObject( native_mutex, INFINITE );

#if !(LINUX)
	// check for other completing this before creating mutexes...
	// make sure that the same process tried to to the init...
	// thread issues should be caught up above...
	if (st_Initialized() == TRUE){
		ock_log_err(OCK_E_TOKEN_ALREADY_INIT);
		goto done;
	}
#endif

	// SAB need to call Fork_Initializer here
	// instead of at the end of the loop...
	// it may also need to call destroy of the following 3 mutexes..
	// it may not matter...
	Fork_Initializer();


	MY_CreateMutex( &pkcs_mutex      );
	MY_CreateMutex( &obj_list_mutex  );
	if (pthread_rwlock_init(&obj_list_rw_mutex, NULL)) {
		ock_log_err(OCK_E_TOKEN_SPECIFIC_INIT);
	}
	MY_CreateMutex( &sess_list_mutex );
	MY_CreateMutex( &login_mutex     );


	if ( (debugfilepathbuffer = getenv( "CRYPTOKI_DEBUG")) != NULL) {
		debugon=1;
	}

	init_data_store((char *)PK_DIR);


	// Handle global initialization issues first if we have not
	// been initialized.
	if (st_Initialized() == FALSE){
#if SYSVSEM
		xproclock = (void *)&xprocsemid;
		CreateXProcLock(xproclock);
#endif
		if ( (rc = attach_shm()) != CKR_OK) {
			ock_log_err(OCK_E_CANNOT_ATTACH_SHMEM);
			goto done;
		}

		nv_token_data = &global_shm->nv_token_data;

		//stloginit();

		initialized = TRUE;
		initedpid = getpid();
		SC_SetFunctionList();

		// Always call the token_specific_init function....
		rc =  token_specific.t_init(Correlator,SlotNumber);
		if (rc != 0) {   // Zero means success, right?!?
			*FunctionList = NULL;
			ock_log_err(OCK_E_TOKEN_SPECIFIC_INIT);
			goto done;
		}
	}

	rc = load_token_data();
	if (rc != CKR_OK) {
		*FunctionList = NULL;
		ock_log_err(OCK_E_TOKEN_SPECIFIC_INIT);
		goto done;
	}

	/* no need to check for error here, we load what we can and syslog the rest */
	load_public_token_objects();

	XProcLock( xproclock );
	global_shm->publ_loaded = TRUE;
	XProcUnLock( xproclock );

	init_slotInfo();

	usage_count++;
	(*FunctionList) = &function_list;

done:
	ReleaseMutex( native_mutex );
	if (rc != 0)
		ock_log_err(OCK_E_TOKEN_SPECIFIC_INIT);
	return rc;
}


//
// What does this really have to do in this new token...
// probably need to close the adapters that are opened, and
// clear the other stuff
CK_RV SC_Finalize( CK_SLOT_ID sid )
{
   CK_ULONG       req_len, repl_len;
   CK_ULONG       i;
   CK_RV          rc, rc2;
   SLT_CHECK

   if (st_Initialized() == FALSE) {	
      ock_log_err(OCK_E_API_NOT_INIT);
      return CKR_CRYPTOKI_NOT_INITIALIZED;
   }

   rc = MY_LockMutex( &pkcs_mutex );
   if (rc != CKR_OK){
      ock_log_err(OCK_E_MUTEX_LOCK);
      return rc;
   } 
   // If somebody else has taken care of things, leave...
   //
   if (st_Initialized() == FALSE) {
      MY_UnlockMutex( &pkcs_mutex ); // ? Somebody else has also destroyed the mutex...
      ock_log_err(OCK_E_API_NOT_INIT);
      return CKR_CRYPTOKI_NOT_INITIALIZED;
   }

   usage_count --;
   if (usage_count == 0){
      initialized = FALSE;
   }

   session_mgr_close_all_sessions();
   object_mgr_purge_token_objects();

   detach_shm();
   // close spin lock file
   if (spin_created)
     close(spinxplfd);
   if ( token_specific.t_final != NULL) {
      token_specific.t_final();
   }


   rc = MY_UnlockMutex( &pkcs_mutex );
   if (rc != CKR_OK){
      ock_log_err(OCK_E_MUTEX_UNLOCK);
      return rc;
   }
   return CKR_OK;
}


//
//
CK_RV SC_GetTokenInfo( CK_SLOT_ID         sid,
                       CK_TOKEN_INFO_PTR  pInfo )
{
   CK_RV             rc = CKR_OK;
   time_t now;

   SLT_CHECK

   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pInfo) {
      ock_log_err(OCK_E_FUNC);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   if (slot_id > MAX_SLOT_ID) {
      ock_log_err(OCK_E_SLOT_INV);
      rc = CKR_SLOT_ID_INVALID;
      goto done;
   }
#ifdef PKCS64
   memcpy( pInfo, &nv_token_data->token_info, sizeof(CK_TOKEN_INFO_32));
   pInfo->flags = nv_token_data->token_info.flags;

   if ( nv_token_data->token_info.ulMaxSessionCount == (CK_ULONG_32)CK_UNAVAILABLE_INFORMATION ) {
     pInfo->ulMaxSessionCount = (CK_ULONG)CK_UNAVAILABLE_INFORMATION;
   } else {
     pInfo->ulMaxSessionCount = nv_token_data->token_info.ulMaxSessionCount;
   }
   if ( nv_token_data->token_info.ulSessionCount == (CK_ULONG_32)CK_UNAVAILABLE_INFORMATION ) {
     pInfo->ulSessionCount = (CK_ULONG)CK_UNAVAILABLE_INFORMATION;
   } else {
     pInfo->ulSessionCount = nv_token_data->token_info.ulSessionCount;
   }
   if ( nv_token_data->token_info.ulMaxRwSessionCount == (CK_ULONG_32)CK_UNAVAILABLE_INFORMATION ) {
     pInfo->ulMaxRwSessionCount = (CK_ULONG)CK_UNAVAILABLE_INFORMATION;
   } else {
     pInfo->ulMaxRwSessionCount = 	nv_token_data->token_info.ulMaxRwSessionCount;
   }
   if ( nv_token_data->token_info.ulRwSessionCount == (CK_ULONG_32)CK_UNAVAILABLE_INFORMATION ) {
     pInfo->ulRwSessionCount = (CK_ULONG)CK_UNAVAILABLE_INFORMATION;
   } else {
     pInfo->ulRwSessionCount = nv_token_data->token_info.ulRwSessionCount;
   }

   pInfo->ulMaxPinLen = nv_token_data->token_info.ulMaxPinLen;
   pInfo->ulMinPinLen = nv_token_data->token_info.ulMinPinLen;

   if ( nv_token_data->token_info.ulTotalPublicMemory == (CK_ULONG_32)CK_UNAVAILABLE_INFORMATION ) {
     pInfo->ulTotalPublicMemory = (CK_ULONG)CK_UNAVAILABLE_INFORMATION;
   } else {
     pInfo->ulTotalPublicMemory = nv_token_data->token_info.ulTotalPublicMemory;
   }
   if ( nv_token_data->token_info.ulFreePublicMemory == (CK_ULONG_32)CK_UNAVAILABLE_INFORMATION ) {
     pInfo->ulFreePublicMemory = (CK_ULONG)CK_UNAVAILABLE_INFORMATION;
   } else {
     pInfo->ulFreePublicMemory = nv_token_data->token_info.ulFreePublicMemory;
   }
   if ( nv_token_data->token_info.ulTotalPrivateMemory == (CK_ULONG_32)CK_UNAVAILABLE_INFORMATION ) {
     pInfo->ulTotalPrivateMemory = (CK_ULONG)CK_UNAVAILABLE_INFORMATION;
   } else {
     pInfo->ulTotalPrivateMemory = nv_token_data->token_info.ulTotalPrivateMemory;
   }
   if ( nv_token_data->token_info.ulFreePrivateMemory == (CK_ULONG_32)CK_UNAVAILABLE_INFORMATION ) {
     pInfo->ulFreePrivateMemory = (CK_ULONG)CK_UNAVAILABLE_INFORMATION;
   } else {
     pInfo->ulFreePrivateMemory = nv_token_data->token_info.ulFreePrivateMemory;
   }

   pInfo->hardwareVersion = nv_token_data->token_info.hardwareVersion;
   pInfo->firmwareVersion = nv_token_data->token_info.firmwareVersion;
//   pInfo->utcTime = nv_token_data->token_info.utcTime[16];

   pInfo->flags = long_reverse(pInfo->flags);
   pInfo->ulMaxSessionCount = long_reverse(pInfo->ulMaxSessionCount);
   pInfo->ulSessionCount = long_reverse(pInfo->ulSessionCount);
   pInfo->ulMaxRwSessionCount = long_reverse(pInfo->ulMaxRwSessionCount);
   pInfo->ulRwSessionCount = long_reverse(pInfo->ulRwSessionCount);
   pInfo->ulMaxPinLen = long_reverse(pInfo->ulMaxPinLen);
   pInfo->ulMinPinLen = long_reverse(pInfo->ulMinPinLen);
   pInfo->ulTotalPublicMemory = long_reverse(pInfo->ulTotalPublicMemory);
   pInfo->ulFreePublicMemory = long_reverse(pInfo->ulFreePublicMemory);
   pInfo->ulTotalPrivateMemory = long_reverse(pInfo->ulTotalPrivateMemory);
   pInfo->ulFreePrivateMemory = long_reverse(pInfo->ulFreePrivateMemory);

#else
   memcpy( pInfo, &nv_token_data->token_info, sizeof(CK_TOKEN_INFO) );
#endif


   // Set the time
   now = time ((time_t *)NULL);
   strftime( (char *)pInfo->utcTime, 16, "%X", localtime(&now) );

done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = 0x%08x\n", "C_GetTokenInfo", rc );

   }

   UNLOCKIT;
   return rc;
}


//
//
CK_RV SC_WaitForSlotEvent( CK_FLAGS        flags,
                          CK_SLOT_ID_PTR  pSlot,
                          CK_VOID_PTR     pReserved )
{
   if (st_Initialized() == FALSE){
      ock_log_err(OCK_E_API_NOT_INIT);
      return CKR_CRYPTOKI_NOT_INITIALIZED;
   }
   ock_log_err(OCK_E_FUNCTION_NOT_SUPP);
   return CKR_FUNCTION_NOT_SUPPORTED;
}


//
//
CK_RV SC_GetMechanismList( CK_SLOT_ID             sid,
                          CK_MECHANISM_TYPE_PTR  pMechList,
                          CK_ULONG_PTR           count )
{
   CK_ULONG   i;
   CK_RV      rc = CKR_OK;
   char        *envrn;
   SLT_CHECK


      LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (count == NULL) {
      ock_log_err(OCK_E_FUNC);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   if (slot_id > MAX_SLOT_ID) {
      ock_log_err(OCK_E_SLOT_INV);
      rc = CKR_SLOT_ID_INVALID;
      goto done;
   }

   if (pMechList == NULL) {
      *count = mech_list_len;
      rc = CKR_OK;
      goto done;
   }

   if (*count < mech_list_len) {
      *count = mech_list_len;
      ock_log_err(OCK_E_TOKEN_SPECIFIC_RNG);
      rc = CKR_BUFFER_TOO_SMALL;
      goto done;
   }

   for (i=0; i < mech_list_len; i++)
      pMechList[i] = mech_list[i].mech_type;

#if 1
   //  For Netscape  we want to not support the
   //  SSL3 mechs since the native ones perform much better
   //  Force those slots to be RSA... it's ugly but it works
   if ( (envrn = getenv("NS_SERVER_HOME"))!= NULL) {
      for (i=0; i<mech_list_len; i++){
           switch (pMechList[i]) {

           case CKM_SSL3_PRE_MASTER_KEY_GEN:
           case CKM_SSL3_MASTER_KEY_DERIVE:
           case CKM_SSL3_KEY_AND_MAC_DERIVE:
           case CKM_SSL3_MD5_MAC:
           case CKM_SSL3_SHA1_MAC:
                   pMechList[i]=CKM_RSA_PKCS;
                   break;
           }
      }
   }
#endif


   *count = mech_list_len;
   rc = CKR_OK;

done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = 0x%08x, # mechanisms:  %d\n", "C_GetMechanismList", rc, *count );
   }
  UNLOCKIT;
   return rc;
}


//
//
CK_RV SC_GetMechanismInfo( CK_SLOT_ID             sid,
                          CK_MECHANISM_TYPE      type,
                          CK_MECHANISM_INFO_PTR  pInfo )
{
   CK_ULONG  i;
   CK_RV     rc = CKR_OK;
   SLT_CHECK

      LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (pInfo == NULL) {
      ock_log_err(OCK_E_FUNC);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   if (slot_id > MAX_SLOT_ID) {
      ock_log_err(OCK_E_SLOT_INV);
      rc = CKR_SLOT_ID_INVALID;
      goto done;
   }

   for (i=0; i < mech_list_len; i++) {
      if (mech_list[i].mech_type == type) {
         memcpy( pInfo, &mech_list[i].mech_info, sizeof(CK_MECHANISM_INFO) );
         rc = CKR_OK;
         goto done;
      }
   }

   ock_log_err(OCK_E_MECH_INV);
   rc = CKR_MECHANISM_INVALID;

done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = 0x%08x, mech type = 0x%08x\n", "C_GetMechanismInfo", rc, type );
   }

   UNLOCKIT;
   return rc;
}


// this routine should only be called if no other processes are attached to
//         the token.  we need to somehow check that this is the only process
// Meta API should prevent this since it knows session states in the shared
// memory.
//
CK_RV SC_InitToken( CK_SLOT_ID   sid,
                    CK_CHAR_PTR  pPin,
                    CK_ULONG     ulPinLen,
                    CK_CHAR_PTR  pLabel )
{
   CK_RV      rc = CKR_OK;
   CK_BYTE    hash_sha[SHA1_HASH_SIZE];
   CK_SLOT_ID slotID;
   char       s[2*PATH_MAX];
   struct passwd *pw = NULL;

   SLT_CHECK;

   slotID = slot_id;

   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pPin || !pLabel) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   if (nv_token_data->token_info.flags & CKF_SO_PIN_LOCKED) {
      ock_log_err(OCK_E_PIN_LOCK);
      rc = CKR_PIN_LOCKED;
      goto done;
   }

   rc = token_specific.t_verify_so_pin(pPin, ulPinLen);
   if (rc != CKR_OK) {
      ock_log_err(OCK_E_PIN_WRONG);
      rc = CKR_PIN_INCORRECT;
      goto done;
   }

#if 0
   rc = compute_sha( pPin, ulPinLen, hash_sha );
   if (memcmp(nv_token_data->so_pin_sha, hash_sha, SHA1_HASH_SIZE) != 0) {
      ock_log_err(OCK_E_PIN_WRONG);
      rc = CKR_PIN_INCORRECT;
      goto done;
   }
   rc  = rng_generate( master_key, 3 * DES_KEY_SIZE );
   if (rc != CKR_OK) {
      ock_log_err(OCK_E_FUNC);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }
#endif

   errno = 0;
   if ((pw = getpwuid(getuid())) == NULL) {
	   ock_log_err_ex(OCK_E_GENERIC, "%s: Error getting username: %s", __FUNCTION__, strerror(errno));
	   rc = CKR_FUNCTION_FAILED;
	   goto done;
   }

   // Before we reconstruct all the data, we should delete the
   // token objects from the filesystem.
   //
   // Construct a string to delete the token objects.
   //
   object_mgr_destroy_token_objects();

   // delete the TOK_OBJ data files
   sprintf(s, "%s %s/%s/%s/* > /dev/null 2>&1", DEL_CMD, pk_dir, pw->pw_name,
						PK_LITE_OBJ_DIR);
   system(s);

   // delete the OpenSSL backup keys
   sprintf(s, "%s %s/%s/%s > /dev/null 2>&1", DEL_CMD, pk_dir, pw->pw_name,
						TPMTOK_PUB_ROOT_KEY_FILE);
   system(s);
   sprintf(s, "%s %s/%s/%s > /dev/null 2>&1", DEL_CMD, pk_dir, pw->pw_name,
						TPMTOK_PRIV_ROOT_KEY_FILE);
   system(s);

   // delete the masterkey
   sprintf(s, "%s %s/%s/%s > /dev/null 2>&1", DEL_CMD, pk_dir, pw->pw_name,
						TPMTOK_MASTERKEY_PRIVATE);
   system(s);

   //
   //META This should be fine since the open session checking should occur at
   //the API not the STDLL

   init_token_data();
   init_slotInfo();

   memcpy( nv_token_data->token_info.label, pLabel, 32 );
   memcpy( nv_token_data->so_pin_sha, hash_sha, SHA1_HASH_SIZE);

   // XXX New for v2.11 - KEY
   nv_token_data->token_info.flags |= CKF_TOKEN_INITIALIZED;

   rc = save_token_data();
   if (rc != CKR_OK){
      ock_log_err(OCK_E_SAVE_TOKEN);
      goto done;
   }
#if 0
   rc = save_masterkey_so();
   if (rc != CKR_OK){
      st_err_log(149, __FILE__, __LINE__, __FUNCTION__);
      goto done;
   }
#endif

done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = 0x%08x\n", "C_InitToken", rc );
   }
   UNLOCKIT;

   return rc;
}


//
//
CK_RV SC_InitPIN( ST_SESSION_HANDLE  sSession,
                  CK_CHAR_PTR        pPin,
                  CK_ULONG           ulPinLen )
{
   SESSION         * sess = NULL;
   CK_BYTE           hash_sha[SHA1_HASH_SIZE];
   CK_BYTE           hash_md5[MD5_HASH_SIZE];
   CK_RV             rc = CKR_OK;
   CK_FLAGS_32     * flags = NULL;
   SESS_SET

      LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pPin) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (pin_locked(&sess->session_info, nv_token_data->token_info.flags) == TRUE) {
      ock_log_err(OCK_E_PIN_LOCK);
      rc = CKR_PIN_LOCKED;
      goto done;
   }

   if (sess->session_info.state != CKS_RW_SO_FUNCTIONS) {
      ock_log_err(OCK_E_USER_NOT_LOGGED_IN);
      rc = CKR_USER_NOT_LOGGED_IN;
      goto done;
   }

#if 0
   if ((ulPinLen < MIN_PIN_LEN) || (ulPinLen > MAX_PIN_LEN)) {
      ock_log_err(OCK_E_PIN_LEN);
      rc = CKR_PIN_LEN_RANGE;
      goto done;
   }
#endif

   rc = token_specific.t_init_pin(pPin, ulPinLen);
   if (rc == CKR_OK){
      flags = &nv_token_data->token_info.flags;

      *flags &=       ~(CKF_USER_PIN_LOCKED |
		      CKF_USER_PIN_FINAL_TRY |
		      CKF_USER_PIN_COUNT_LOW);

      rc = save_token_data();
      if (rc != CKR_OK){
	 ock_log_err(OCK_E_SAVE_TOKEN);
	 goto done;
      }
   }

#if 0
   // compute the SHA and MD5 hashes of the user pin
   //
   rc  = compute_sha( pPin, ulPinLen, hash_sha );
   rc |= compute_md5( pPin, ulPinLen, hash_md5 );
   if (rc != CKR_OK){
      ock_log_err(OCK_E_HASH);
      goto done;
   }
   rc = XProcLock( xproclock );
   if (rc != CKR_OK){
      ock_log_err(OCK_E_PROCESS_LOCK);
      goto done;
   }
      memcpy( nv_token_data->user_pin_sha, hash_sha, SHA1_HASH_SIZE );
      nv_token_data->token_info.flags |= CKF_USER_PIN_INITIALIZED;
   XProcUnLock( xproclock );

   memcpy( user_pin_md5, hash_md5, MD5_HASH_SIZE  );

   rc = save_token_data();
   if (rc != CKR_OK){
      ock_log_err(OCK_E_SAVE_TOKEN);
      goto done;
   }
   rc = save_masterkey_user();
   if (rc != CKR_OK){
      ock_log_err(OCK_E_SAVE_MASTERKEY);
   }
#endif

done:
   LLOCK;

   if (debugfile) {
      ock_log_debug( "%-25s:  session = %08x\n", "C_InitPin", rc, hSession );
   }

   UNLOCKIT;
   return rc;
}


//
//
CK_RV SC_SetPIN( ST_SESSION_HANDLE  sSession,
                 CK_CHAR_PTR        pOldPin,
                 CK_ULONG           ulOldLen,
                 CK_CHAR_PTR        pNewPin,
                 CK_ULONG           ulNewLen )
{
   SESSION         * sess = NULL;
   CK_BYTE	     old_hash_sha[SHA1_HASH_SIZE];
   CK_BYTE           new_hash_sha[SHA1_HASH_SIZE];
   CK_BYTE           hash_md5[MD5_HASH_SIZE];
   CK_MECHANISM      mech;
   DIGEST_CONTEXT    digest_ctx;
   CK_ULONG          hash_len;
   CK_RV             rc = CKR_OK;
   SESS_SET

      LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (pin_locked(&sess->session_info, nv_token_data->token_info.flags) == TRUE) {
      ock_log_err(OCK_E_PIN_LOCK);
      rc = CKR_PIN_LOCKED;
      goto done;
   }

   rc = token_specific.t_set_pin(sSession, pOldPin, ulOldLen, pNewPin, ulNewLen);

#if 0
   if ((ulNewLen < MIN_PIN_LEN) || (ulNewLen > MAX_PIN_LEN)) {
      ock_log_err(OCK_E_PIN_LEN);
      rc = CKR_PIN_LEN_RANGE;
      goto done;
   }

   rc = compute_sha( pOldPin, ulOldLen, old_hash_sha );
   if (rc != CKR_OK){
      ock_log_err(OCK_E_HASH);
      goto done;
   }
   if (sess->session_info.state == CKS_RW_USER_FUNCTIONS) {
      if (memcmp(nv_token_data->user_pin_sha, old_hash_sha, SHA1_HASH_SIZE) != 0) {
         ock_log_err(OCK_E_PIN_WRONG);
         rc = CKR_PIN_INCORRECT;
         goto done;
      }

      rc  = compute_sha( pNewPin, ulNewLen, new_hash_sha );
      rc |= compute_md5( pNewPin, ulNewLen, hash_md5 );
      if (rc != CKR_OK){
         ock_log_err(OCK_E_HASH);
         goto done;
      }

      /* The old PIN matches, now make sure its different than the new.
       * If so, reset the CKF_USER_PIN_TO_BE_CHANGED flag. -KEY 
       */
      if (memcmp(old_hash_sha, new_hash_sha, SHA1_HASH_SIZE) == 0) {
	 ock_log_err(OCK_E_PIN_INV);
	 rc = CKR_PIN_INVALID;
	 goto done;
      }
      
      rc = XProcLock( xproclock );
      if (rc != CKR_OK){
         ock_log_err(OCK_E_PROCESS_LOCK);
         goto done;
      }
         memcpy( nv_token_data->user_pin_sha, new_hash_sha, SHA1_HASH_SIZE );
         memcpy( user_pin_md5, hash_md5, MD5_HASH_SIZE );

	 // New in v2.11 - XXX KEY
	 sess->session_info.flags &= ~(CKF_USER_PIN_TO_BE_CHANGED);
      
         XProcUnLock( xproclock );
         rc = save_token_data();

      if (rc != CKR_OK){
          ock_log_err(OCK_E_SAVE_TOKEN);
          goto done;
      }
      rc = save_masterkey_user();
   }
   else if (sess->session_info.state == CKS_RW_SO_FUNCTIONS) {
      if (memcmp(nv_token_data->so_pin_sha, old_hash_sha, SHA1_HASH_SIZE) != 0) {
         rc = CKR_PIN_INCORRECT;
         ock_log_err(OCK_E_PIN_WRONG);
         goto done;
      }

      rc  = compute_sha( pNewPin, ulNewLen, new_hash_sha );
      rc |= compute_md5( pNewPin, ulNewLen, hash_md5 );
      if (rc != CKR_OK){
         ock_log_err(OCK_E_HASH);
         goto done;
      }

      /* The old PIN matches, now make sure its different than the new.
       * If so, reset the CKF_SO_PIN_TO_BE_CHANGED flag. - KEY 
       */
      if (memcmp(old_hash_sha, new_hash_sha, SHA1_HASH_SIZE) == 0) {
	 ock_log_err(OCK_E_PIN_INV);
	 rc = CKR_PIN_INVALID;
	 goto done;
      }
      
      rc = XProcLock( xproclock );
      if (rc != CKR_OK){
         ock_log_err(OCK_E_PROCESS_LOCK);
         goto done;
      }
         memcpy( nv_token_data->so_pin_sha, new_hash_sha, SHA1_HASH_SIZE );
         memcpy( so_pin_md5, hash_md5, MD5_HASH_SIZE );
      
	 // New in v2.11 - XXX KEY      
	 sess->session_info.flags &= ~(CKF_SO_PIN_TO_BE_CHANGED);

   	 XProcUnLock( xproclock );
         rc = save_token_data();

      if (rc != CKR_OK){
          ock_log_err(OCK_E_SAVE_TOKEN);
         goto done;
      }
      
      rc = save_masterkey_so();
   }
   else{
      ock_log_err(OCK_E_FUNCTION_NOT_SUPP);
      rc = CKR_SESSION_READ_ONLY;
   }
#endif

done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  session = %08x\n", "C_SetPin", rc, hSession );
   }

   UNLOCKIT;
   if (rc != CKR_SESSION_READ_ONLY && rc != CKR_OK)
      ock_log_err(OCK_E_SAVE_MASTERKEY);
   return rc;
}


//
//
CK_RV SC_OpenSession( CK_SLOT_ID             sid,
                     CK_FLAGS               flags,
                     CK_SESSION_HANDLE_PTR  phSession )
{
   SESSION              * sess;
   CK_BBOOL               locked = FALSE;
   CK_RV                  rc = CKR_OK;
   SLT_CHECK



      LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (phSession == NULL) {
      ock_log_err(OCK_E_FUNC);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   if (slot_id > MAX_SLOT_ID) {
      ock_log_err(OCK_E_SLOT_INV);
      rc = CKR_SLOT_ID_INVALID;
      goto done;
   }

   if ((flags & CKF_SERIAL_SESSION) == 0) {
      ock_log_err(OCK_E_PARALLEL_SESS);
      rc = CKR_SESSION_PARALLEL_NOT_SUPPORTED;
      goto done;
   }

   if ((flags & CKF_RW_SESSION) == 0) {
      if (session_mgr_so_session_exists()) {
         ock_log_err(OCK_E_SESS_READWRITE_EXISTS);
         rc = CKR_SESSION_READ_WRITE_SO_EXISTS;
         goto done;
      }
   }

   // Get the mutex because we may modify the pid_list
   //
   rc = MY_LockMutex( &pkcs_mutex );
   if (rc != CKR_OK){
         ock_log_err(OCK_E_MUTEX_LOCK);
         goto done;
   }
   locked = TRUE;

   token_specific.t_session(slot_id);

   MY_UnlockMutex( &pkcs_mutex );
   locked = FALSE;

   rc = session_mgr_new( flags, &sess );
   if (rc != CKR_OK){
      ock_log_err(OCK_E_SESS_MGR_NEW);
      goto done;
   }
   *phSession = (CK_SESSION_HANDLE_PTR) sess;
   // Set the correct slot ID here. Was hard coded to 1. - KEY
   sess->session_info.slotID = sid;

done:
   if (locked)
      MY_UnlockMutex( &pkcs_mutex );

   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = 0x%08x  ", "C_OpenSession", rc );
      if (rc == CKR_OK)
	ock_log_debug( "sess = %d", (sess == NULL)?-1:(CK_LONG)sess->handle );
      ock_log_debug( "\n");
   }

   UNLOCKIT;
   return rc;
}


//
//
CK_RV SC_CloseSession( ST_SESSION_HANDLE  sSession )
{
   SESSION  * sess = NULL;
   CK_RV      rc = CKR_OK;
   SESS_SET

      LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   rc = session_mgr_close_session( sess );

done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = 0x%08x  sess = %d\n", "C_CloseSession", rc, hSession );
   }

   UNLOCKIT;
   return rc;
}


//
//
CK_RV SC_CloseAllSessions( CK_SLOT_ID  sid )
{
   CK_RV rc = CKR_OK;
   SLT_CHECK

      LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   rc = session_mgr_close_all_sessions();
   if (rc != CKR_OK){
      ock_log_err(OCK_E_CLOSE_ALL_SESS);
   }
	
done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = 0x%08x  slot = %d\n", "C_CloseAllSessions", rc, slot_id );
   }

   UNLOCKIT;
   return rc;
}


//
//
CK_RV SC_GetSessionInfo( ST_SESSION_HANDLE   sSession,
                        CK_SESSION_INFO_PTR pInfo )
{
   SESSION  * sess = NULL;
   CK_RV      rc = CKR_OK;
   SESS_SET

      LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pInfo) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   memcpy( pInfo, &sess->session_info, sizeof(CK_SESSION_INFO) );

done:
   if (debugfile) {
      ock_log_debug( "%-25s:  session = %08d\n", "C_GetSessionInfo", hSession );
   }
   UNLOCKIT;
   return rc;
}


//
//
CK_RV SC_GetOperationState( ST_SESSION_HANDLE  sSession,
                           CK_BYTE_PTR        pOperationState,
                           CK_ULONG_PTR       pulOperationStateLen )
{
   SESSION  * sess = NULL;
   CK_BBOOL   length_only = FALSE;
   CK_RV      rc = CKR_OK;
   SESS_SET


      LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pulOperationStateLen) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   if (!pOperationState)
      length_only = TRUE;

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }


   rc = session_mgr_get_op_state( sess, length_only,
                                  pOperationState,
                                  pulOperationStateLen );
   if (rc != CKR_OK){
      ock_log_err(OCK_E_SESS_MGR_GET_OK_STATE);
   }
done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  session = %08x\n", "C_GetOperationState", rc, hSession );
   }

   UNLOCKIT;
   return rc;
}


//
//
CK_RV SC_SetOperationState( ST_SESSION_HANDLE  sSession,
                           CK_BYTE_PTR        pOperationState,
                           CK_ULONG           ulOperationStateLen,
                           CK_OBJECT_HANDLE   hEncryptionKey,
                           CK_OBJECT_HANDLE   hAuthenticationKey )
{
   SESSION  * sess = NULL;
   CK_RV      rc = CKR_OK;
   SESS_SET


      LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pOperationState || (ulOperationStateLen == 0)) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   rc = session_mgr_set_op_state( sess,
                                  hEncryptionKey,  hAuthenticationKey,
                                  pOperationState, ulOperationStateLen );

   if (rc != CKR_OK){
      ock_log_err(OCK_E_SESS_MGR_GET_OK_STATE);
   }
done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  session = %08x\n", "C_SetOperationState", rc, hSession );
   }

   UNLOCKIT;
   return rc;
}



//
//
CK_RV SC_Login( ST_SESSION_HANDLE   sSession,
                CK_USER_TYPE        userType,
                CK_CHAR_PTR         pPin,
                CK_ULONG            ulPinLen )
{
	SESSION        * sess = NULL;
	CK_FLAGS_32    * flags = NULL;
	CK_BYTE          hash_sha[SHA1_HASH_SIZE];
	CK_RV            rc = CKR_OK;

	SESS_SET
	LOCKIT;
	// In v2.11, logins should be exclusive, since token
	// specific flags may need to be set for a bad login. - KEY
	rc = MY_LockMutex( &login_mutex );
	if (rc != CKR_OK){
	        ock_log_err(OCK_E_MUTEX_LOCK);
		return CKR_FUNCTION_FAILED;
	}

	if (st_Initialized() == FALSE) {
		ock_log_err(OCK_E_API_NOT_INIT);
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = SESSION_MGR_FIND( hSession );
	if (!sess) {
		ock_log_err(OCK_E_SESS_HANDLE_INV);
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}
	flags = &nv_token_data->token_info.flags;

	if (!pPin || ulPinLen > MAX_PIN_LEN) {
		set_login_flags(userType, flags);
		ock_log_err(OCK_E_PIN_WRONG);
		rc = CKR_PIN_INCORRECT;
		goto done;
	}

	// PKCS #11 v2.01 requires that all sessions have the same login status:
	//    --> all sessions are public, all are SO or all are USER
	//
	if (userType == CKU_USER) {
		if (session_mgr_so_session_exists()){
			ock_log_err(OCK_E_ANOTHER_USER_ALREADY_LOGGED_IN);
			rc = CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
		}
		if (session_mgr_user_session_exists()){
			ock_log_err(OCK_E_USER_ALREADY_LOGGED_IN);
			rc = CKR_USER_ALREADY_LOGGED_IN;
		}
	}
	else if (userType == CKU_SO) {
		if (session_mgr_user_session_exists()){
			ock_log_err(OCK_E_ANOTHER_USER_ALREADY_LOGGED_IN);
			rc = CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
		}
		if (session_mgr_so_session_exists()){
			ock_log_err(OCK_E_USER_ALREADY_LOGGED_IN);
			rc = CKR_USER_ALREADY_LOGGED_IN;
		}
		if (session_mgr_readonly_session_exists()){
			ock_log_err(OCK_E_FUNCTION_NOT_SUPP);
			rc = CKR_SESSION_READ_ONLY_EXISTS;
		}
	}
	else {
		rc = CKR_USER_TYPE_INVALID;
		ock_log_err(OCK_E_USER_TYPE_INV);
	}
	if (rc != CKR_OK)
		goto done;

	if (userType == CKU_USER) {
		if (*flags & CKF_USER_PIN_LOCKED) {
			ock_log_err(OCK_E_PIN_LOCK);
			rc = CKR_PIN_LOCKED;
			goto done;
		}

		// call the pluggable login function here - KEY
		rc = token_specific.t_login(userType, pPin, ulPinLen);
		if (rc == CKR_OK) {
			*flags &=       ~(CKF_USER_PIN_LOCKED |
					CKF_USER_PIN_FINAL_TRY |
					CKF_USER_PIN_COUNT_LOW);
		} else if (rc == CKR_PIN_INCORRECT) {
			set_login_flags(userType, flags);
			goto done;
		} else {
			goto done;
		}
	} else {
		if (*flags & CKF_SO_PIN_LOCKED) {
			ock_log_err(OCK_E_PIN_LOCK);
			rc = CKR_PIN_LOCKED;
			goto done;
		}

		// call the pluggable login function here - KEY
		rc = token_specific.t_login(userType, pPin, ulPinLen);
		if (rc == CKR_OK) {
			*flags &=       ~(CKF_SO_PIN_LOCKED |
					CKF_SO_PIN_FINAL_TRY |
					CKF_SO_PIN_COUNT_LOW);
		} else if (rc == CKR_PIN_INCORRECT) {
			set_login_flags(userType, flags);
			goto done;
		} else {
			goto done;
		}
	}

	rc = session_mgr_login_all( userType );
	if (rc != CKR_OK) {
		ock_log_err(OCK_E_SESS_MGR);
	}

done:
	LLOCK;
	if (debugfile) {
		ock_log_debug( "%-25s:  rc = 0x%08x\n", "C_Login", rc );
	}

	UNLOCKIT;
	save_token_data();
	MY_UnlockMutex( &login_mutex );
	return rc;
}


//
//
CK_RV SC_Logout( ST_SESSION_HANDLE  sSession )
{
	SESSION  * sess = NULL;
	CK_RV      rc = CKR_OK;

	SESS_SET

	LOCKIT;
	if (st_Initialized() == FALSE) {
		ock_log_err(OCK_E_API_NOT_INIT);
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = SESSION_MGR_FIND( hSession );
	if (!sess) {
		ock_log_err(OCK_E_SESS_HANDLE_INV);
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	// all sessions have the same state so we just have to check one
	//
	if (session_mgr_public_session_exists()) {
		ock_log_err(OCK_E_USER_NOT_LOGGED_IN);
		rc = CKR_USER_NOT_LOGGED_IN;
		goto done;
	}

	rc = session_mgr_logout_all();
	if (rc != CKR_OK){
		ock_log_err(OCK_E_USER_NOT_LOGGED_IN);
	}

	rc = token_specific.t_logout();
#if 0
	memset( user_pin_md5, 0x0, MD5_HASH_SIZE );
	memset( so_pin_md5,   0x0, MD5_HASH_SIZE );

	object_mgr_purge_private_token_objects();
#endif
done:
	LLOCK;
	if (debugfile) {
		ock_log_debug( "%-25s:  rc = 0x%08x\n", "C_Logout", rc );
	}

	UNLOCKIT; return rc;
}


// This is a Leeds-Lite solution so we have to store objects on the host.
//
CK_RV SC_CreateObject( ST_SESSION_HANDLE    sSession,
                      CK_ATTRIBUTE_PTR     pTemplate,
                      CK_ULONG             ulCount,
                      CK_OBJECT_HANDLE_PTR phObject )
{
   SESSION               * sess = NULL;
   CK_ULONG                i;
   CK_RV                   rc = CKR_OK;
   SESS_SET

   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (pin_expired(&sess->session_info, nv_token_data->token_info.flags) == TRUE) {
      ock_log_err(OCK_E_PIN_EXP);
      rc = CKR_PIN_EXPIRED;
      goto done;
   }
   
   rc = object_mgr_add( sess, pTemplate, ulCount, phObject );
   if (rc != CKR_OK) {
      ock_log_err(OCK_E_OBJ_MGR_ADD_TO_MAP);
   }

done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x\n", "C_CreateObject", rc );

      for (i = 0; i < ulCount; i++) {
         if (pTemplate[i].type == CKA_CLASS)
           ock_log_debug( "%28s:  0x%02x\n", "Object Type", *(CK_ULONG *)pTemplate[i].pValue );
      }
      if (rc == CKR_OK)
        ock_log_debug( "%28s:  %d\n", "Handle", *phObject );

   }

   UNLOCKIT; return rc;
}



//
//
CK_RV  SC_CopyObject( ST_SESSION_HANDLE    sSession,
                     CK_OBJECT_HANDLE     hObject,
                     CK_ATTRIBUTE_PTR     pTemplate,
                     CK_ULONG             ulCount,
                     CK_OBJECT_HANDLE_PTR phNewObject )
{
   SESSION              * sess = NULL;
   CK_RV                  rc = CKR_OK;
   SESS_SET

   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }
   
   if (pin_expired(&sess->session_info, nv_token_data->token_info.flags) == TRUE) {
      ock_log_err(OCK_E_PIN_EXP);
      rc = CKR_PIN_EXPIRED;
      goto done;
   }
   
   rc = object_mgr_copy( sess, pTemplate, ulCount, hObject, phNewObject );
   if (rc != CKR_OK) {
      ock_log_err(OCK_E_OBJ_COPY);
   }

done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, old handle = %d, new handle = %d\n", "C_CopyObject", rc, hObject, *phNewObject );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_DestroyObject( ST_SESSION_HANDLE  sSession,
                       CK_OBJECT_HANDLE   hObject )
{
   SESSION               * sess = NULL;
   CK_RV                   rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (pin_expired(&sess->session_info, nv_token_data->token_info.flags) == TRUE) {
      ock_log_err(OCK_E_PIN_EXP);
      rc = CKR_PIN_EXPIRED;
      goto done;
   }
   
   rc = object_mgr_destroy_object( sess, hObject );
   if (rc != CKR_OK){
      ock_log_err(OCK_E_OBJ_MGR_DESTROY);
   }
done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, handle = %d\n", "C_DestroyObject", rc, hObject );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_GetObjectSize( ST_SESSION_HANDLE  sSession,
                       CK_OBJECT_HANDLE   hObject,
                       CK_ULONG_PTR       pulSize )
{
   SESSION               * sess = NULL;
   CK_RV                   rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   rc = object_mgr_get_object_size( hObject, pulSize );
   if (rc != CKR_OK){
      ock_log_err(OCK_E_OBJ_MGR_GET_SIZE);
   }

done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, handle = %d\n", "C_GetObjectSize", rc, hObject );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_GetAttributeValue( ST_SESSION_HANDLE  sSession,
                           CK_OBJECT_HANDLE   hObject,
                           CK_ATTRIBUTE_PTR   pTemplate,
                           CK_ULONG           ulCount )
{
   SESSION        * sess = NULL;
   CK_ATTRIBUTE   * attr = NULL;
   CK_BYTE        * ptr  = NULL;
   CK_ULONG         i;
   CK_RV            rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   rc = object_mgr_get_attribute_values( sess, hObject, pTemplate, ulCount );
   if (rc != CKR_OK){
      ock_log_err(OCK_E_OBJ_GET_ATTR_VALUE);
   }


done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, handle = %d\n", "C_GetAttributeValue", rc, hObject );

      attr = pTemplate;
      for (i = 0; i < ulCount; i++, attr++) {
         ptr = (CK_BYTE *)attr->pValue;

         ock_log_debug( "   %3d:  Attribute type:  0x%08x\n", i, attr->type );
         ock_log_debug( "         Value Length:    %08d\n",   attr->ulValueLen );

         if (attr->ulValueLen != (CK_ULONG)(-1) && (ptr != NULL))
            ock_log_debug( "         First 4 bytes:   %02x %02x %02x %02x", ptr[0], ptr[1], ptr[2], ptr[3] );

         ock_log_debug( "\n\n");
      }

   }

   UNLOCKIT; return rc;
}


//
//
CK_RV  SC_SetAttributeValue( ST_SESSION_HANDLE    sSession,
                            CK_OBJECT_HANDLE     hObject,
                            CK_ATTRIBUTE_PTR     pTemplate,
                            CK_ULONG             ulCount )
{
   SESSION       * sess = NULL;
   CK_ATTRIBUTE  * attr = NULL;
   CK_ULONG        i;
   CK_RV           rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   rc = object_mgr_set_attribute_values( sess, hObject, pTemplate, ulCount);
   if (rc != CKR_OK){
      ock_log_err(OCK_E_OBJ_SET_ATTR);
   }

done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, handle = %d\n", "C_SetAttributeValue", rc, hObject );

      attr = pTemplate;
      for (i = 0; i < ulCount; i++, attr++) {
         CK_BYTE *ptr = (CK_BYTE *)attr->pValue;

         ock_log_debug( "   %3d:  Attribute type:  0x%08x\n", i, attr->type );
         ock_log_debug( "         Value Length:    %08d\n",   attr->ulValueLen );

         if (attr->ulValueLen != (CK_ULONG)(-1) && (ptr != NULL))
            ock_log_debug( "         First 4 bytes:   %02x %02x %02x %02x", ptr[0], ptr[1], ptr[2], ptr[3] );

         ock_log_debug( "\n\n");
      }

   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_FindObjectsInit( ST_SESSION_HANDLE   sSession,
                         CK_ATTRIBUTE_PTR    pTemplate,
                         CK_ULONG            ulCount )
{
   SESSION        * sess  = NULL;
   CK_ATTRIBUTE   * attr = NULL;
   CK_ULONG         i;
   CK_RV            rc = CKR_OK;
   SESS_SET

   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (pin_expired(&sess->session_info, nv_token_data->token_info.flags) == TRUE) {
      ock_log_err(OCK_E_PIN_EXP);
      rc = CKR_PIN_EXPIRED;
      goto done;
   }
   
   if (sess->find_active == TRUE) {
      ock_log_err(OCK_E_OP_ACTIVE);
      rc = CKR_OPERATION_ACTIVE;
      goto done;
   }

   rc = object_mgr_find_init( sess, pTemplate, ulCount );
   if (rc != CKR_OK){
      ock_log_err(OCK_E_OBJ_MGR_FIND_INIT);
   }

done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x\n", "C_FindObjectsInit", rc );

      attr = pTemplate;
      for (i = 0; i < ulCount; i++, attr++) {
         CK_BYTE *ptr = (CK_BYTE *)attr->pValue;

         ock_log_debug( "   %3d:  Attribute type:  0x%08x\n", i, attr->type );
         ock_log_debug( "         Value Length:    %08d\n",   attr->ulValueLen );

         if (attr->ulValueLen != (CK_ULONG)(-1) && (ptr != NULL))
            ock_log_debug( "         First 4 bytes:   %02x %02x %02x %02x", ptr[0], ptr[1], ptr[2], ptr[3] );

         ock_log_debug( "\n\n");
      }

   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_FindObjects( ST_SESSION_HANDLE     sSession,
                     CK_OBJECT_HANDLE_PTR  phObject,
                     CK_ULONG              ulMaxObjectCount,
                     CK_ULONG_PTR          pulObjectCount )
{
   SESSION    * sess  = NULL;
   CK_ULONG     count = 0;
   CK_RV        rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!phObject || !pulObjectCount) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (sess->find_active == FALSE) {
      ock_log_err(OCK_E_OP_NOT_INIT);
      rc = CKR_OPERATION_NOT_INITIALIZED;
      goto done;
   }

   if (!sess->find_list) {
      ock_log_err(OCK_E_FUNC);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }
   count = MIN(ulMaxObjectCount, (sess->find_count - sess->find_idx));

   memcpy( phObject, sess->find_list + sess->find_idx, count * sizeof(CK_OBJECT_HANDLE) );
   *pulObjectCount = count;

   sess->find_idx += count;
   rc = CKR_OK;

done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, returned %d objects\n", "C_FindObjects", rc, count );
   }

   UNLOCKIT; return rc;
}



//
//
CK_RV SC_FindObjectsFinal( ST_SESSION_HANDLE  sSession )
{
   SESSION     * sess = NULL;
   CK_RV         rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (sess->find_active == FALSE) {
      ock_log_err(OCK_E_OP_NOT_INIT);
      rc = CKR_OPERATION_NOT_INITIALIZED;
      goto done;
   }

   if (sess->find_list)
      free( sess->find_list );

   sess->find_list   = NULL;
   sess->find_len    = 0;
   sess->find_idx    = 0;
   sess->find_active = FALSE;

   rc = CKR_OK;

done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x\n", "C_FindObjectsFinal", rc );
   }

   UNLOCKIT; return rc;
}



//
//
CK_RV SC_EncryptInit( ST_SESSION_HANDLE  sSession,
                     CK_MECHANISM_PTR   pMechanism,
                     CK_OBJECT_HANDLE   hKey )
{
   SESSION               * sess = NULL;
   CK_RV                   rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pMechanism) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   VALID_MECH(pMechanism);

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (pin_expired(&sess->session_info, nv_token_data->token_info.flags) == TRUE) {
      ock_log_err(OCK_E_PIN_EXP);
      rc = CKR_PIN_EXPIRED;
      goto done;
   }
   
   if (sess->encr_ctx.active == TRUE) {
      ock_log_err(OCK_E_OP_ACTIVE);
      rc = CKR_OPERATION_ACTIVE;
      goto done;
   }

   rc = encr_mgr_init( sess, &sess->encr_ctx, OP_ENCRYPT_INIT, pMechanism, hKey );
   if (rc != CKR_OK) {
      ock_log_err(OCK_E_ENCRYPT_MGR_INIT);
   }
done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d, key = %d, mech = 0x%x\n", "C_EncryptInit", rc,(sess == NULL)?-1:(CK_LONG)sess->handle, hKey, pMechanism->mechanism );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_Encrypt( ST_SESSION_HANDLE  sSession,
                 CK_BYTE_PTR        pData,
                 CK_ULONG           ulDataLen,
                 CK_BYTE_PTR        pEncryptedData,
                 CK_ULONG_PTR       pulEncryptedDataLen )
{
   SESSION        * sess = NULL;
   CK_BBOOL         length_only = FALSE;
   CK_RV            rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pData || !pulEncryptedDataLen) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (sess->encr_ctx.active == FALSE) {
      ock_log_err(OCK_E_OP_NOT_INIT);
      rc = CKR_OPERATION_NOT_INITIALIZED;
      goto done;
   }

   if (!pEncryptedData)
      length_only = TRUE;

   rc = encr_mgr_encrypt( sess,           length_only,
                         &sess->encr_ctx,
                          pData,          ulDataLen,
                          pEncryptedData, pulEncryptedDataLen );
   if (rc != CKR_OK) {
      ock_log_err(OCK_E_ENCRYPT_MGR_ENCRYPT);
   }

done:
   LLOCK;
   if (rc != CKR_BUFFER_TOO_SMALL && (rc != CKR_OK || length_only != TRUE))
      encr_mgr_cleanup( &sess->encr_ctx );

   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d, amount = %d\n", "C_Encrypt", rc, (sess == NULL)?-1:(CK_LONG)sess->handle, ulDataLen );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_EncryptUpdate( ST_SESSION_HANDLE  sSession,
                       CK_BYTE_PTR        pPart,
                       CK_ULONG           ulPartLen,
                       CK_BYTE_PTR        pEncryptedPart,
                       CK_ULONG_PTR       pulEncryptedPartLen )
{
   SESSION        * sess = NULL;
   CK_BBOOL         length_only = FALSE;
   CK_RV            rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pPart || !pulEncryptedPartLen) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (sess->encr_ctx.active == FALSE) {
      ock_log_err(OCK_E_OP_NOT_INIT);
      rc = CKR_OPERATION_NOT_INITIALIZED;
      goto done;
   }

   if (!pEncryptedPart)
      length_only = TRUE;

   rc = encr_mgr_encrypt_update( sess,           length_only,
                                &sess->encr_ctx,
                                 pPart,          ulPartLen,
                                 pEncryptedPart, pulEncryptedPartLen );
   if (rc != CKR_OK) {
      ock_log_err(OCK_E_ENCRYPT_MGR_ENCRYPT_UPDATE);
   }

done:
   LLOCK;
   if (rc != CKR_OK && rc != CKR_BUFFER_TOO_SMALL)
      encr_mgr_cleanup( &sess->encr_ctx );

   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d, amount = %d\n", "C_EncryptUpdate", rc, (sess == NULL)?-1:(CK_LONG)sess->handle, ulPartLen );
   }

   UNLOCKIT; return rc;
}


// I think RSA goofed when designing the specification for C_EncryptFinal.
// This function is supposed to follow the Cryptoki standard that if
// pLastEncryptedPart == NULL then the user is requesting only the length
// of the output.
//
// But it's quite possible that no output will be returned (say the user
// specifies a total of 64 bytes of input data throughout the multi-part
// encryption).  The same thing can happen during an EncryptUpdate.
//
// ie:
//
//    1) user calls C_EncryptFinal to get the needed length
//       --> we return "0 bytes required"
//    2) user passes in a NULL pointer for pLastEncryptedPart
//       --> we think the user is requesting the length again <--
//
// So the user needs to pass in a non-NULL pointer even though we're not
// going to return anything in it.  It would have been cleaner if RSA would
// have simply included a "give-me-the-length-only flag" as an argument.
//
//
CK_RV SC_EncryptFinal( ST_SESSION_HANDLE  sSession,
                      CK_BYTE_PTR        pLastEncryptedPart,
                      CK_ULONG_PTR       pulLastEncryptedPartLen )
{
   SESSION     * sess = NULL;
   CK_BBOOL      length_only = FALSE;
   CK_RV         rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pulLastEncryptedPartLen) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (sess->encr_ctx.active == FALSE) {
      ock_log_err(OCK_E_OP_NOT_INIT);
      rc = CKR_OPERATION_NOT_INITIALIZED;
      goto done;
   }

   if (!pLastEncryptedPart)
      length_only = TRUE;

   rc = encr_mgr_encrypt_final( sess,  length_only, &sess->encr_ctx,
                                pLastEncryptedPart, pulLastEncryptedPartLen );
   if (rc != CKR_OK) {
      ock_log_err(OCK_E_ENCRYPT_MGR_ENCRYPT_FINAL);
   }

done:
   LLOCK;
   if (rc != CKR_BUFFER_TOO_SMALL && (rc != CKR_OK || length_only != TRUE))
      encr_mgr_cleanup( &sess->encr_ctx );

   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d\n", "C_EncryptFinal", rc, (sess == NULL)?-1:(CK_LONG)sess->handle );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_DecryptInit( ST_SESSION_HANDLE  sSession,
                     CK_MECHANISM_PTR   pMechanism,
                     CK_OBJECT_HANDLE   hKey )
{
   SESSION   * sess = NULL;
   CK_RV       rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pMechanism) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }
   VALID_MECH(pMechanism);

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (pin_expired(&sess->session_info, nv_token_data->token_info.flags) == TRUE) {
      ock_log_err(OCK_E_PIN_EXP);
      rc = CKR_PIN_EXPIRED;
      goto done;
   }
   
   if (sess->decr_ctx.active == TRUE) {
      ock_log_err(OCK_E_OP_ACTIVE);
      rc = CKR_OPERATION_ACTIVE;
      goto done;
   }

   rc = decr_mgr_init( sess, &sess->decr_ctx, OP_DECRYPT_INIT, pMechanism, hKey );
   if (rc != CKR_OK) {
      ock_log_err(OCK_E_DECRYPT_MGR_INIT);
   }

done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d, key = %d, mech = 0x%x\n", "C_DecryptInit", rc, (sess == NULL)?-1:(CK_LONG)sess->handle, hKey, pMechanism->mechanism );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_Decrypt( ST_SESSION_HANDLE  sSession,
                 CK_BYTE_PTR        pEncryptedData,
                 CK_ULONG           ulEncryptedDataLen,
                 CK_BYTE_PTR        pData,
                 CK_ULONG_PTR       pulDataLen )
{
   SESSION  * sess = NULL;
   CK_BBOOL   length_only = FALSE;
   CK_RV      rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pEncryptedData || !pulDataLen) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (sess->decr_ctx.active == FALSE) {
      ock_log_err(OCK_E_OP_NOT_INIT);
      rc = CKR_OPERATION_NOT_INITIALIZED;
      goto done;
   }

   if (!pData)
      length_only = TRUE;

   rc = decr_mgr_decrypt( sess,           length_only,
                         &sess->decr_ctx,
                          pEncryptedData, ulEncryptedDataLen,
                          pData,          pulDataLen );
   if (rc != CKR_OK) {
      ock_log_err(OCK_E_DECRYPT_MGR_DECRYPT);
   }

done:
   LLOCK;
   if (rc != CKR_BUFFER_TOO_SMALL && (rc != CKR_OK || length_only != TRUE))
      decr_mgr_cleanup( &sess->decr_ctx );

   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d, amount = %d\n", "C_Decrypt", rc, (sess == NULL)?-1:(CK_LONG)sess->handle, ulEncryptedDataLen );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_DecryptUpdate( ST_SESSION_HANDLE  sSession,
                       CK_BYTE_PTR        pEncryptedPart,
                       CK_ULONG           ulEncryptedPartLen,
                       CK_BYTE_PTR        pPart,
                       CK_ULONG_PTR       pulPartLen )
{
   SESSION   * sess = NULL;
   CK_BBOOL    length_only = FALSE;
   CK_RV       rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pEncryptedPart || !pulPartLen) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (sess->decr_ctx.active == FALSE) {
      ock_log_err(OCK_E_OP_NOT_INIT);
      rc = CKR_OPERATION_NOT_INITIALIZED;
      goto done;
   }

   if (!pPart)
      length_only = TRUE;

   rc = decr_mgr_decrypt_update( sess,           length_only,
                                &sess->decr_ctx,
                                 pEncryptedPart, ulEncryptedPartLen,
                                 pPart,          pulPartLen );
   if (rc != CKR_OK) {
      ock_log_err(OCK_E_DECRYPT_MGR_UPDATE);
   }

done:
   LLOCK;
   if (rc != CKR_OK && rc != CKR_BUFFER_TOO_SMALL)
      decr_mgr_cleanup( &sess->decr_ctx );

   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d, amount = %d\n", "C_DecryptUpdate", rc, (sess == NULL)?-1:(CK_LONG)sess->handle, ulEncryptedPartLen );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_DecryptFinal( ST_SESSION_HANDLE  sSession,
                      CK_BYTE_PTR        pLastPart,
                      CK_ULONG_PTR       pulLastPartLen )
{
   SESSION   * sess = NULL;
   CK_BBOOL    length_only = FALSE;
   CK_RV       rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pulLastPartLen) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (sess->decr_ctx.active == FALSE) {
      ock_log_err(OCK_E_OP_NOT_INIT);
      rc = CKR_OPERATION_NOT_INITIALIZED;
      goto done;
   }

   if (!pLastPart)
      length_only = TRUE;

   rc = decr_mgr_decrypt_final( sess,      length_only,
                               &sess->decr_ctx,
                                pLastPart, pulLastPartLen );

   if (rc != CKR_OK) {
      ock_log_err(OCK_E_DECRYPT_MGR_FINAL);
   }
done:
   LLOCK;
   if (rc != CKR_BUFFER_TOO_SMALL && (rc != CKR_OK || length_only != TRUE))
      decr_mgr_cleanup( &sess->decr_ctx );

   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d, amount = %d\n", "C_DecryptFinal", rc, (sess == NULL)?-1:(CK_LONG)sess->handle, *pulLastPartLen );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_DigestInit( ST_SESSION_HANDLE  sSession,
                    CK_MECHANISM_PTR   pMechanism )
{
   SESSION   * sess = NULL;
   CK_RV       rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }
   if (!pMechanism) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   VALID_MECH(pMechanism);


   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (pin_expired(&sess->session_info, nv_token_data->token_info.flags) == TRUE) {
      ock_log_err(OCK_E_PIN_EXP);
      rc = CKR_PIN_EXPIRED;
      goto done;
   }
   
   if (sess->digest_ctx.active == TRUE) {
      ock_log_err(OCK_E_OP_ACTIVE);
      rc = CKR_OPERATION_ACTIVE;
      goto done;
   }

   rc = digest_mgr_init( sess, &sess->digest_ctx, pMechanism );
   if (rc != CKR_OK) {
      ock_log_err(OCK_E_DIGEST_INIT);
   }

done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d, mech = %x\n", "C_DigestInit", rc, (sess == NULL)?-1:(CK_LONG)sess->handle, pMechanism->mechanism );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_Digest( ST_SESSION_HANDLE  sSession,
                CK_BYTE_PTR        pData,
                CK_ULONG           ulDataLen,
                CK_BYTE_PTR        pDigest,
                CK_ULONG_PTR       pulDigestLen )
{
   SESSION  * sess = NULL;
   CK_BBOOL   length_only = FALSE;
   CK_RV      rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   // Netscape has been known to pass a null pData to DigestUpdate
   // but never for Digest.  It doesn't really make sense to allow it here
   //
   if (!pData || !pulDigestLen) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (sess->digest_ctx.active == FALSE) {
      ock_log_err(OCK_E_FUNCTION_NOT_PERMITTED);
      rc = CKR_OPERATION_NOT_INITIALIZED;
      goto done;
   }

   if (!pDigest)
      length_only = TRUE;

   rc = digest_mgr_digest( sess,    length_only,
                          &sess->digest_ctx,
                           pData,   ulDataLen,
                           pDigest, pulDigestLen );
   if (rc != CKR_OK) {
      ock_log_err(OCK_E_DIGEST);
   }

done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d, datalen = %d\n", "C_Digest", rc, (sess == NULL)?-1:(CK_LONG)sess->handle, ulDataLen );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_DigestUpdate( ST_SESSION_HANDLE  sSession,
                      CK_BYTE_PTR        pPart,
                      CK_ULONG           ulPartLen )
{
   SESSION  * sess = NULL;
   CK_RV      rc   = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   // Netscape has been known to pass a null pPart with ulPartLen == 0...
   //
   if (!pPart && ulPartLen != 0) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (sess->digest_ctx.active == FALSE) {
      ock_log_err(OCK_E_OP_NOT_INIT);
      rc = CKR_OPERATION_NOT_INITIALIZED;
      goto done;
   }

   if (pPart){
      rc = digest_mgr_digest_update( sess, &sess->digest_ctx, pPart, ulPartLen );
      if (rc != CKR_OK) {
         ock_log_err(OCK_E_DIGEST);
      }
   }
done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d, datalen = %d\n", "C_DigestUpdate", rc, (sess == NULL)?-1:(CK_LONG)sess->handle, ulPartLen );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_DigestKey( ST_SESSION_HANDLE  sSession,
                   CK_OBJECT_HANDLE   hKey )
{
   SESSION  * sess = NULL;
   CK_RV      rc = CKR_OK;
   SESS_SET

   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (sess->digest_ctx.active == FALSE) {
      ock_log_err(OCK_E_OP_NOT_INIT);
      rc = CKR_OPERATION_NOT_INITIALIZED;
      goto done;
   }

   rc = digest_mgr_digest_key( sess, &sess->digest_ctx, hKey );
   if (rc != CKR_OK){ 
      ock_log_err(OCK_E_DIGEST);
   }

done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d, key = %d\n", "C_DigestKey", rc, (sess == NULL)?-1:(CK_LONG)sess->handle, hKey );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_DigestFinal( ST_SESSION_HANDLE  sSession,
                     CK_BYTE_PTR        pDigest,
                     CK_ULONG_PTR       pulDigestLen )
{
   SESSION  * sess = NULL;
   CK_BBOOL   length_only = FALSE;
   CK_RV      rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pulDigestLen) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (sess->digest_ctx.active == FALSE) {
      ock_log_err(OCK_E_OP_NOT_INIT);
      rc = CKR_OPERATION_NOT_INITIALIZED;
      goto done;
   }

   if (!pDigest)
      length_only = TRUE;

   rc = digest_mgr_digest_final( sess,    length_only,
                                &sess->digest_ctx,
                                 pDigest, pulDigestLen );
   if (rc != CKR_OK){ 
      ock_log_err(OCK_E_DIGEST_FINAL);
   }

done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d\n", "C_DigestFinal", rc, (sess == NULL)?-1:(CK_LONG)sess->handle );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_SignInit( ST_SESSION_HANDLE  sSession,
                  CK_MECHANISM_PTR   pMechanism,
                  CK_OBJECT_HANDLE   hKey )
{
   SESSION   * sess = NULL;
   CK_RV       rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pMechanism ){
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }
   VALID_MECH(pMechanism);

   if (pin_expired(&sess->session_info, nv_token_data->token_info.flags) == TRUE) {
      ock_log_err(OCK_E_PIN_EXP);
      rc = CKR_PIN_EXPIRED;
      goto done;
   }
   
   if (sess->sign_ctx.active == TRUE) {
      rc = CKR_OPERATION_ACTIVE;
      ock_log_err(OCK_E_OP_ACTIVE);
      goto done;
   }

   rc = sign_mgr_init( sess, &sess->sign_ctx, pMechanism, FALSE, hKey );
   if (rc != CKR_OK){ 
      ock_log_err(OCK_E_SIGN_INIT);
   }

done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d, mech = %x\n", "C_SignInit", rc, (sess == NULL)?-1:(CK_LONG)sess->handle, pMechanism->mechanism );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_Sign( ST_SESSION_HANDLE  sSession,
              CK_BYTE_PTR        pData,
              CK_ULONG           ulDataLen,
              CK_BYTE_PTR        pSignature,
              CK_ULONG_PTR       pulSignatureLen )
{
   SESSION  * sess = NULL;
   CK_BBOOL   length_only = FALSE;
   CK_RV      rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pData || !pulSignatureLen) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (sess->sign_ctx.active == FALSE) {
      ock_log_err(OCK_E_OP_NOT_INIT);
      rc = CKR_OPERATION_NOT_INITIALIZED;
      goto done;
   }

   if (!pSignature)
      length_only = TRUE;

   rc = sign_mgr_sign( sess,       length_only,
                      &sess->sign_ctx,
                       pData,      ulDataLen,
                       pSignature, pulSignatureLen );
   if (rc != CKR_OK){ 
      ock_log_err(OCK_E_SIGN);
   }

done:
   if (rc != CKR_BUFFER_TOO_SMALL && (rc != CKR_OK || length_only != TRUE))
      sign_mgr_cleanup( &sess->sign_ctx );

   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d, datalen = %d\n", "C_Sign", rc, (sess == NULL)?-1:(CK_LONG)sess->handle, ulDataLen );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_SignUpdate( ST_SESSION_HANDLE  sSession,
                    CK_BYTE_PTR        pPart,
                    CK_ULONG           ulPartLen )
{
   SESSION  * sess = NULL;
   CK_RV      rc   = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pPart) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (sess->sign_ctx.active == FALSE) {
      ock_log_err(OCK_E_OP_NOT_INIT);
      rc = CKR_OPERATION_NOT_INITIALIZED;
      goto done;
   }

   rc = sign_mgr_sign_update( sess, &sess->sign_ctx, pPart, ulPartLen );
   if (rc != CKR_OK){ 
      ock_log_err(OCK_E_SIGN_UPDATE);
   }

done:
   if (rc != CKR_OK)
      sign_mgr_cleanup( &sess->sign_ctx );

   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d, datalen = %d\n", "C_SignUpdate", rc, (sess == NULL)?-1:(CK_LONG)sess->handle, ulPartLen );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_SignFinal( ST_SESSION_HANDLE  sSession,
                   CK_BYTE_PTR        pSignature,
                   CK_ULONG_PTR       pulSignatureLen )
{
   SESSION  * sess = NULL;
   CK_BBOOL   length_only = FALSE;
   CK_RV      rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pulSignatureLen) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (sess->sign_ctx.active == FALSE) {
      ock_log_err(OCK_E_OP_NOT_INIT);
      rc = CKR_OPERATION_NOT_INITIALIZED;
      goto done;
   }

   if (!pSignature)
      length_only = TRUE;

   rc = sign_mgr_sign_final( sess,       length_only,
                            &sess->sign_ctx,
                             pSignature, pulSignatureLen );
   if (rc != CKR_OK){ 
      ock_log_err(OCK_E_SIGN_FINAL);
   }

done:
   if (rc != CKR_BUFFER_TOO_SMALL && (rc != CKR_OK || length_only != TRUE))
      sign_mgr_cleanup( &sess->sign_ctx );

   LLOCK;
   if (debugfile)
   {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d\n", "C_SignFinal", rc, (sess == NULL)?-1:(CK_LONG)sess->handle );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_SignRecoverInit( ST_SESSION_HANDLE  sSession,
                         CK_MECHANISM_PTR   pMechanism,
                         CK_OBJECT_HANDLE   hKey )
{
   SESSION   * sess = NULL;
   CK_RV       rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }
   if (!pMechanism ){
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }
   VALID_MECH(pMechanism);

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (pin_expired(&sess->session_info, nv_token_data->token_info.flags) == TRUE) {
      ock_log_err(OCK_E_PIN_EXP);
      rc = CKR_PIN_EXPIRED;
      goto done;
   }
   
   if (sess->sign_ctx.active == TRUE) {
      rc = CKR_OPERATION_ACTIVE;
      ock_log_err(OCK_E_OP_ACTIVE);
      goto done;
   }

   rc = sign_mgr_init( sess, &sess->sign_ctx, pMechanism, TRUE, hKey );
   if (rc != CKR_OK){ 
      ock_log_err(OCK_E_SIGN_INIT);
   }

done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d, mech = %x\n", "C_SignRecoverInit", rc, (sess == NULL)?-1:(CK_LONG)sess->handle, pMechanism->mechanism );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_SignRecover( ST_SESSION_HANDLE  sSession,
                     CK_BYTE_PTR        pData,
                     CK_ULONG           ulDataLen,
                     CK_BYTE_PTR        pSignature,
                     CK_ULONG_PTR       pulSignatureLen )
{
   SESSION  * sess = NULL;
   CK_BBOOL   length_only = FALSE;
   CK_RV      rc = CKR_OK;
   SESS_SET


   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
   LOCKIT;
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pData || !pulSignatureLen) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if ((sess->sign_ctx.active == FALSE) || (sess->sign_ctx.recover == FALSE)) {
      rc = CKR_OPERATION_NOT_INITIALIZED;
      ock_log_err(OCK_E_OP_NOT_INIT);
      goto done;
   }

   if (!pSignature)
      length_only = TRUE;

   rc = sign_mgr_sign_recover( sess,       length_only,
                              &sess->sign_ctx,
                               pData,      ulDataLen,
                               pSignature, pulSignatureLen );
   if (rc != CKR_OK){ 
      ock_log_err(OCK_E_SIGN_RECOVER);
   }

done:
   if (rc != CKR_BUFFER_TOO_SMALL && (rc != CKR_OK || length_only != TRUE))
      sign_mgr_cleanup( &sess->sign_ctx );

   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d, datalen = %d\n", "C_SignRecover", rc, (sess == NULL)?-1:(CK_LONG)sess->handle, ulDataLen );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_VerifyInit( ST_SESSION_HANDLE  sSession,
                    CK_MECHANISM_PTR   pMechanism,
                    CK_OBJECT_HANDLE   hKey )
{
   SESSION   * sess = NULL;
   CK_RV       rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }
   if (!pMechanism ){
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }
   VALID_MECH(pMechanism);

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (pin_expired(&sess->session_info, nv_token_data->token_info.flags) == TRUE) {
      ock_log_err(OCK_E_PIN_EXP);
      rc = CKR_PIN_EXPIRED;
      goto done;
   }
   
   if (sess->verify_ctx.active == TRUE) {
      rc = CKR_OPERATION_ACTIVE;
      ock_log_err(OCK_E_OP_ACTIVE);
      goto done;
   }

   rc = verify_mgr_init( sess, &sess->verify_ctx, pMechanism, FALSE, hKey );
   if (rc != CKR_OK){ 
      ock_log_err(OCK_E_VERIFY_INIT);
   }

done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d, mech = %x\n", "C_VerifyInit", rc, (sess == NULL)?-1:(CK_LONG)sess->handle, pMechanism->mechanism );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_Verify( ST_SESSION_HANDLE  sSession,
                CK_BYTE_PTR        pData,
                CK_ULONG           ulDataLen,
                CK_BYTE_PTR        pSignature,
                CK_ULONG           ulSignatureLen )
{
   SESSION  * sess = NULL;
   CK_RV      rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pData || !pSignature) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (sess->verify_ctx.active == FALSE) {
      rc = CKR_OPERATION_NOT_INITIALIZED;
      ock_log_err(OCK_E_OP_NOT_INIT);
      goto done;
   }

   rc = verify_mgr_verify( sess,
                          &sess->verify_ctx,
                           pData,      ulDataLen,
                           pSignature, ulSignatureLen );
   if (rc != CKR_OK){ 
      ock_log_err(OCK_E_VERIFY);
   }

done:
   verify_mgr_cleanup( &sess->verify_ctx );

   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d, datalen = %d\n", "C_Verify", rc, (sess == NULL)?-1:(CK_LONG)sess->handle, ulDataLen );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_VerifyUpdate( ST_SESSION_HANDLE  sSession,
                      CK_BYTE_PTR        pPart,
                      CK_ULONG           ulPartLen )
{
   SESSION  * sess = NULL;
   CK_RV      rc   = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pPart) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (sess->verify_ctx.active == FALSE) {
      rc = CKR_OPERATION_NOT_INITIALIZED;
      ock_log_err(OCK_E_OP_NOT_INIT);
      goto done;
   }

   rc = verify_mgr_verify_update( sess, &sess->verify_ctx, pPart, ulPartLen );
   if (rc != CKR_OK){ 
      ock_log_err(OCK_E_VERIFY_UPDATE);
   }

done:
   if (rc != CKR_OK)
      verify_mgr_cleanup( &sess->verify_ctx );

   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d, datalen = %d\n", "C_VerifyUpdate", rc, (sess == NULL)?-1:(CK_LONG)sess->handle, ulPartLen );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_VerifyFinal( ST_SESSION_HANDLE  sSession,
                     CK_BYTE_PTR        pSignature,
                     CK_ULONG           ulSignatureLen )
{
   SESSION  * sess = NULL;
   CK_RV      rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pSignature) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (sess->verify_ctx.active == FALSE) {
      rc = CKR_OPERATION_NOT_INITIALIZED;
      ock_log_err(OCK_E_OP_NOT_INIT);
      goto done;
   }

   rc = verify_mgr_verify_final( sess, &sess->verify_ctx, pSignature, ulSignatureLen );
   if (rc != CKR_OK){ 
      ock_log_err(OCK_E_VERIFY_FINAL);
   }

done:
   verify_mgr_cleanup( &sess->verify_ctx );

   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d\n", "C_VerifyFinal", rc, (sess == NULL)?-1:(CK_LONG)sess->handle );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_VerifyRecoverInit( ST_SESSION_HANDLE  sSession,
                           CK_MECHANISM_PTR   pMechanism,
                           CK_OBJECT_HANDLE   hKey )
{
   SESSION   * sess = NULL;
   CK_RV       rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }
   if (!pMechanism ){
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }
   VALID_MECH(pMechanism);

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (pin_expired(&sess->session_info, nv_token_data->token_info.flags) == TRUE) {
      ock_log_err(OCK_E_PIN_EXP);
      rc = CKR_PIN_EXPIRED;
      goto done;
   }
   
   if (sess->verify_ctx.active == TRUE) {
      rc = CKR_OPERATION_ACTIVE;
      ock_log_err(OCK_E_OP_ACTIVE);
      goto done;
   }

   rc = verify_mgr_init( sess, &sess->verify_ctx, pMechanism, TRUE, hKey );
   if (rc != CKR_OK){ 
      ock_log_err(OCK_E_VERIFY_INIT);
   }

done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d, mech = %x\n", "C_VerifyRecoverInit", rc, (sess == NULL)?-1:(CK_LONG)sess->handle, pMechanism->mechanism );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_VerifyRecover( ST_SESSION_HANDLE  sSession,
                       CK_BYTE_PTR        pSignature,
                       CK_ULONG           ulSignatureLen,
                       CK_BYTE_PTR        pData,
                       CK_ULONG_PTR       pulDataLen )
{
   SESSION  * sess = NULL;
   CK_BBOOL   length_only = FALSE;
   CK_RV      rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pSignature || !pulDataLen) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if ((sess->verify_ctx.active == FALSE) || (sess->verify_ctx.recover == FALSE)) {
      rc = CKR_OPERATION_NOT_INITIALIZED;
      ock_log_err(OCK_E_OP_NOT_INIT);
      goto done;
   }


   if (!pData)
      length_only = TRUE;

   rc = verify_mgr_verify_recover( sess,       length_only,
                                  &sess->verify_ctx,
                                   pSignature, ulSignatureLen,
                                   pData,      pulDataLen );
   if (rc != CKR_OK){ 
      ock_log_err(OCK_E_VERIFY_RECOVER);
   }

done:
   if (rc != CKR_BUFFER_TOO_SMALL && (rc != CKR_OK || length_only != TRUE))
      verify_mgr_cleanup( &sess->verify_ctx );

   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d, recover len = %d, length_only = %d\n", "C_VerifyRecover", rc, (sess == NULL)?-1:(CK_LONG)sess->handle, *pulDataLen, length_only );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_DigestEncryptUpdate( ST_SESSION_HANDLE  sSession,
                             CK_BYTE_PTR        pPart,
                             CK_ULONG           ulPartLen,
                             CK_BYTE_PTR        pEncryptedPart,
                             CK_ULONG_PTR       pulEncryptedPartLen )
{
   SESS_SET
   if (st_Initialized() == FALSE){
      ock_log_err(OCK_E_API_NOT_INIT);
      return CKR_CRYPTOKI_NOT_INITIALIZED;
   }
   ock_log_err(OCK_E_FUNCTION_NOT_SUPP);
   return CKR_FUNCTION_NOT_SUPPORTED;
}


//
//
CK_RV SC_DecryptDigestUpdate( ST_SESSION_HANDLE  sSession,
                             CK_BYTE_PTR        pEncryptedPart,
                             CK_ULONG           ulEncryptedPartLen,
                             CK_BYTE_PTR        pPart,
                             CK_ULONG_PTR       pulPartLen )
{
   SESS_SET
   if (st_Initialized() == FALSE){
      ock_log_err(OCK_E_API_NOT_INIT);
      return CKR_CRYPTOKI_NOT_INITIALIZED;
   }

   ock_log_err(OCK_E_FUNCTION_NOT_SUPP);
   return CKR_FUNCTION_NOT_SUPPORTED;
}


//
//
CK_RV SC_SignEncryptUpdate( ST_SESSION_HANDLE  sSession,
                           CK_BYTE_PTR        pPart,
                           CK_ULONG           ulPartLen,
                           CK_BYTE_PTR        pEncryptedPart,
                           CK_ULONG_PTR       pulEncryptedPartLen )
{
   SESS_SET
   if (st_Initialized() == FALSE){
      ock_log_err(OCK_E_API_NOT_INIT);
      return CKR_CRYPTOKI_NOT_INITIALIZED;
   }
   ock_log_err(OCK_E_FUNCTION_NOT_SUPP);
   return CKR_FUNCTION_NOT_SUPPORTED;
}


//
//
CK_RV SC_DecryptVerifyUpdate( ST_SESSION_HANDLE  sSession,
                             CK_BYTE_PTR        pEncryptedPart,
                             CK_ULONG           ulEncryptedPartLen,
                             CK_BYTE_PTR        pPart,
                             CK_ULONG_PTR       pulPartLen )
{
   SESS_SET
   if (st_Initialized() == FALSE){
      ock_log_err(OCK_E_API_NOT_INIT);
      return CKR_CRYPTOKI_NOT_INITIALIZED;
   }
   ock_log_err(OCK_E_FUNCTION_NOT_SUPP);
   return CKR_FUNCTION_NOT_SUPPORTED;
}


//
//
CK_RV SC_GenerateKey( ST_SESSION_HANDLE     sSession,
                     CK_MECHANISM_PTR      pMechanism,
                     CK_ATTRIBUTE_PTR      pTemplate,
                     CK_ULONG              ulCount,
                     CK_OBJECT_HANDLE_PTR  phKey )
{
   SESSION       * sess = NULL;
   CK_RV           rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pMechanism || !phKey || (pTemplate == NULL && ulCount != 0)) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }
   VALID_MECH(pMechanism);

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (pin_expired(&sess->session_info, nv_token_data->token_info.flags) == TRUE) {
      ock_log_err(OCK_E_PIN_EXP);
      rc = CKR_PIN_EXPIRED;
      goto done;
   }
   
   rc = key_mgr_generate_key( sess, pMechanism, pTemplate, ulCount, phKey );
   if (rc != CKR_OK){ 
      ock_log_err(OCK_E_KEY_GENERATION);
   }

done:
   LLOCK;
   if (debugfile) {
      CK_ATTRIBUTE *attr = pTemplate;
      CK_ULONG      i;

      ock_log_debug( "%-25s:  rc = %08x, sess = %d, handle = %d, mech = %x\n", "C_GenerateKey", rc, (sess == NULL)?-1:(CK_LONG)sess->handle, *phKey, pMechanism->mechanism );

      for (i = 0; i < ulCount; i++, attr++) {
         CK_BYTE *ptr = (CK_BYTE *)attr->pValue;

         ock_log_debug( "   %3d:  Attribute type:  0x%08x\n", i, attr->type );
         ock_log_debug( "         Value Length:    %08d\n",   attr->ulValueLen );

         if (attr->ulValueLen != (CK_ULONG)(-1) && (ptr != NULL))
            ock_log_debug( "         First 4 bytes:   %02x %02x %02x %02x", ptr[0], ptr[1], ptr[2], ptr[3] );

         ock_log_debug( "\n\n");
      }

   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_GenerateKeyPair( ST_SESSION_HANDLE     sSession,
                         CK_MECHANISM_PTR      pMechanism,
                         CK_ATTRIBUTE_PTR      pPublicKeyTemplate,
                         CK_ULONG              ulPublicKeyAttributeCount,
                         CK_ATTRIBUTE_PTR      pPrivateKeyTemplate,
                         CK_ULONG              ulPrivateKeyAttributeCount,
                         CK_OBJECT_HANDLE_PTR  phPublicKey,
                         CK_OBJECT_HANDLE_PTR  phPrivateKey )
{
   SESSION       * sess = NULL;
   CK_RV           rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pMechanism || !phPublicKey || !phPrivateKey ||
      (!pPublicKeyTemplate && (ulPublicKeyAttributeCount != 0)) ||
      (!pPrivateKeyTemplate && (ulPrivateKeyAttributeCount != 0)))
   {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }
   VALID_MECH(pMechanism);

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (pin_expired(&sess->session_info, nv_token_data->token_info.flags) == TRUE) {
      ock_log_err(OCK_E_PIN_EXP);
      rc = CKR_PIN_EXPIRED;
      goto done;
   }
   
   rc = key_mgr_generate_key_pair( sess,                pMechanism,
                                   pPublicKeyTemplate,  ulPublicKeyAttributeCount,
                                   pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
                                   phPublicKey,         phPrivateKey );
   if (rc != CKR_OK){ 
      ock_log_err(OCK_E_KEY_GENERATION);
   }

done:
   LLOCK;
   if (debugfile) {
      CK_ATTRIBUTE *attr = NULL;
      CK_ULONG      i;

      ock_log_debug( "%-25s:  rc = %08x, sess = %d, mech = %x\n", "C_GenerateKeyPair", rc, (sess == NULL)?-1:(CK_LONG)sess->handle, pMechanism->mechanism );

      if (rc == CKR_OK) {
         ock_log_debug( "   Public  handle:  %d\n", *phPublicKey );
         ock_log_debug( "   Private handle:  %d\n", *phPrivateKey );
      }

      ock_log_debug( "   Public Template:\n");

      attr = pPublicKeyTemplate;
      for (i = 0; i < ulPublicKeyAttributeCount; i++, attr++) {
         CK_BYTE *ptr = (CK_BYTE *)attr->pValue;

         ock_log_debug( "   %3d:  Attribute type:  0x%08x\n", i, attr->type );
         ock_log_debug( "         Value Length:    %08d\n",   attr->ulValueLen );

         if (attr->ulValueLen != (CK_ULONG)(-1) && (ptr != NULL))
            ock_log_debug( "         First 4 bytes:   %02x %02x %02x %02x", ptr[0], ptr[1], ptr[2], ptr[3] );

         ock_log_debug( "\n\n");
      }

      ock_log_debug( "   Private Template:\n");

      attr = pPrivateKeyTemplate;
      for (i = 0; i < ulPrivateKeyAttributeCount; i++, attr++) {
         CK_BYTE *ptr = (CK_BYTE *)attr->pValue;

         ock_log_debug( "   %3d:  Attribute type:  0x%08x\n", i, attr->type );
         ock_log_debug( "         Value Length:    %08d\n",   attr->ulValueLen );

         if (attr->ulValueLen != (CK_ULONG)(-1) && (ptr != NULL))
            ock_log_debug( "         First 4 bytes:   %02x %02x %02x %02x", ptr[0], ptr[1], ptr[2], ptr[3] );

         ock_log_debug( "\n\n");
      }

   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_WrapKey( ST_SESSION_HANDLE  sSession,
                 CK_MECHANISM_PTR   pMechanism,
                 CK_OBJECT_HANDLE   hWrappingKey,
                 CK_OBJECT_HANDLE   hKey,
                 CK_BYTE_PTR        pWrappedKey,
                 CK_ULONG_PTR       pulWrappedKeyLen )
{
   SESSION  * sess = NULL;
   CK_BBOOL   length_only = FALSE;
   CK_RV      rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pMechanism || !pulWrappedKeyLen) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }
   VALID_MECH(pMechanism);

   if (!pWrappedKey)
      length_only = TRUE;

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (pin_expired(&sess->session_info, nv_token_data->token_info.flags) == TRUE) {
      ock_log_err(OCK_E_PIN_EXP);
      rc = CKR_PIN_EXPIRED;
      goto done;
   }
   
   rc = key_mgr_wrap_key( sess,         length_only,
                          pMechanism,
                          hWrappingKey, hKey,
                          pWrappedKey,  pulWrappedKeyLen );
   if (rc != CKR_OK){ 
      ock_log_err(OCK_E_WRAP_KEY);
   }

done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d, encrypting key = %d, wrapped key = %d\n", "C_WrapKey", rc, (sess == NULL)?-1:(CK_LONG)sess->handle, hWrappingKey, hKey );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_UnwrapKey( ST_SESSION_HANDLE     sSession,
                   CK_MECHANISM_PTR      pMechanism,
                   CK_OBJECT_HANDLE      hUnwrappingKey,
                   CK_BYTE_PTR           pWrappedKey,
                   CK_ULONG              ulWrappedKeyLen,
                   CK_ATTRIBUTE_PTR      pTemplate,
                   CK_ULONG              ulCount,
                   CK_OBJECT_HANDLE_PTR  phKey )
{
   SESSION        * sess = NULL;
   CK_ATTRIBUTE   * attr = NULL;
   CK_BYTE        * ptr  = NULL;
   CK_ULONG         i;
   CK_RV            rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pMechanism || !pWrappedKey ||
      (!pTemplate && ulCount != 0) || !phKey)
   {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }
   VALID_MECH(pMechanism);

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (pin_expired(&sess->session_info, nv_token_data->token_info.flags) == TRUE) {
      ock_log_err(OCK_E_PIN_EXP);
      rc = CKR_PIN_EXPIRED;
      goto done;
   }
   
   rc = key_mgr_unwrap_key( sess,           pMechanism,
                            pTemplate,      ulCount,
                            pWrappedKey,    ulWrappedKeyLen,
                            hUnwrappingKey, phKey );
   if (rc != CKR_OK){ 
      ock_log_err(OCK_E_UNWRAP_KEY2);
   }

done:
//   if (rc == CKR_OBJECT_HANDLE_INVALID)  brkpt();
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d, decrypting key = %d, unwrapped key = %d\n", "C_UnwrapKey", rc, (sess == NULL)?-1:(CK_LONG)sess->handle, hUnwrappingKey, *phKey );

      attr = pTemplate;
      for (i = 0; i < ulCount; i++, attr++) {
         ptr = (CK_BYTE *)attr->pValue;

         ock_log_debug( "   %3d:  Attribute type:  0x%08x\n", i, attr->type );
         ock_log_debug( "         Value Length:    %08d\n",   attr->ulValueLen );

         if (attr->ulValueLen != (CK_ULONG)(-1) && (ptr != NULL))
            ock_log_debug( "         First 4 bytes:   %02x %02x %02x %02x", ptr[0], ptr[1], ptr[2], ptr[3] );

         ock_log_debug( "\n\n");
      }

   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_DeriveKey( ST_SESSION_HANDLE     sSession,
                   CK_MECHANISM_PTR      pMechanism,
                   CK_OBJECT_HANDLE      hBaseKey,
                   CK_ATTRIBUTE_PTR      pTemplate,
                   CK_ULONG              ulCount,
                   CK_OBJECT_HANDLE_PTR  phKey )
{
   SESSION        * sess = NULL;
   CK_ATTRIBUTE   * attr = NULL;
   CK_BYTE        * ptr  = NULL;
   CK_ULONG         i;
   CK_RV            rc = CKR_OK;
   SESS_SET


   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pMechanism || (!pTemplate && ulCount != 0)) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }
   VALID_MECH(pMechanism);

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   if (pin_expired(&sess->session_info, nv_token_data->token_info.flags) == TRUE) {
      ock_log_err(OCK_E_PIN_EXP);
      rc = CKR_PIN_EXPIRED;
      goto done;
   }
   
   rc = key_mgr_derive_key( sess,      pMechanism,
                            hBaseKey,  phKey,
                            pTemplate, ulCount );
   if (rc != CKR_OK){ 
      ock_log_err(OCK_E_DERIVE);
   }

done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, sess = %d, base key = %d, mech = %x\n", "C_DeriveKey", rc, (sess == NULL)?-1:(CK_LONG)sess->handle, hBaseKey, pMechanism->mechanism );

      if (rc == CKR_OK) {
         switch (pMechanism->mechanism) {
            case CKM_SSL3_KEY_AND_MAC_DERIVE:
            {
               CK_SSL3_KEY_MAT_PARAMS *pReq;
               CK_SSL3_KEY_MAT_OUT    *pPtr;
               pReq = (CK_SSL3_KEY_MAT_PARAMS *)pMechanism->pParameter;
               pPtr = pReq->pReturnedKeyMaterial;

               ock_log_debug( "   Client MAC key:  %d\n", pPtr->hClientMacSecret );
               ock_log_debug( "   Server MAC key:  %d\n", pPtr->hServerMacSecret );
               ock_log_debug( "   Client Key:      %d\n", pPtr->hClientKey );
               ock_log_debug( "   Server Key:      %d\n", pPtr->hServerKey );
            }
            break;

            case CKM_DH_PKCS_DERIVE:
            {
               ock_log_debug( "   DH Shared Secret:  \n" );
            }
            break ;

            default:
               ock_log_debug( "   Derived key:     %d\n", *phKey );
         }
      }


      attr = pTemplate;
      for (i = 0; i < ulCount; i++, attr++) {
         ptr = (CK_BYTE *)attr->pValue;

         ock_log_debug( "   %3d:  Attribute type:  0x%08x\n", i, attr->type );
         ock_log_debug( "         Value Length:    %08d\n",   attr->ulValueLen );

         if (attr->ulValueLen != (CK_ULONG)(-1) && (ptr != NULL))
            ock_log_debug( "         First 4 bytes:   %02x %02x %02x %02x", ptr[0], ptr[1], ptr[2], ptr[3] );

         ock_log_debug( "\n\n");
      }

   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_SeedRandom( ST_SESSION_HANDLE  sSession,
                    CK_BYTE_PTR        pSeed,
                    CK_ULONG           ulSeedLen )
{
   SESS_SET
   if (st_Initialized() == FALSE){
      ock_log_err(OCK_E_API_NOT_INIT);
      return CKR_CRYPTOKI_NOT_INITIALIZED;
   }
   return CKR_OK;
}


//
//
CK_RV SC_GenerateRandom( ST_SESSION_HANDLE  sSession,
                        CK_BYTE_PTR        pRandomData,
                        CK_ULONG           ulRandomLen )
{
   SESSION *sess = NULL;
   CK_RV    rc = CKR_OK;
   SESS_SET

   LOCKIT;
   if (st_Initialized() == FALSE) {
      ock_log_err(OCK_E_API_NOT_INIT);
      rc = CKR_CRYPTOKI_NOT_INITIALIZED;
      goto done;
   }

   if (!pRandomData && ulRandomLen != 0) {
      ock_log_err(OCK_E_BAD_ARG);
      rc = CKR_ARGUMENTS_BAD;
      goto done;
   }

   sess = SESSION_MGR_FIND( hSession );
   if (!sess) {
      ock_log_err(OCK_E_SESS_HANDLE_INV);
      rc = CKR_SESSION_HANDLE_INVALID;
      goto done;
   }

   rc = rng_generate( pRandomData, ulRandomLen );
   if (rc != CKR_OK){ 
      st_err_log(130, __FILE__, __LINE__, __FUNCTION__);
   }

done:
   LLOCK;
   if (debugfile) {
      ock_log_debug( "%-25s:  rc = %08x, %d bytes\n", "C_GenerateRandom", rc, ulRandomLen );
   }

   UNLOCKIT; return rc;
}


//
//
CK_RV SC_GetFunctionStatus( ST_SESSION_HANDLE  sSession )
{
   SESS_SET
   if (st_Initialized() == FALSE){
      ock_log_err(OCK_E_API_NOT_INIT);
      return CKR_CRYPTOKI_NOT_INITIALIZED;
   }
   ock_log_err(OCK_E_FUNC_NOT_PARALLEL);
   return CKR_FUNCTION_NOT_PARALLEL;
}


//
//
CK_RV SC_CancelFunction( ST_SESSION_HANDLE  sSession )
{
   SESS_SET
   if (st_Initialized() == FALSE){
      ock_log_err(OCK_E_API_NOT_INIT);
      return CKR_CRYPTOKI_NOT_INITIALIZED;
   }
   ock_log_err(OCK_E_FUNC_NOT_PARALLEL);
   return CKR_FUNCTION_NOT_PARALLEL;
}


#if (LINUX)
#define __cdecl 
#endif
//
//
CK_RV __cdecl QueryTweakValues( void )
{
   ock_log_err(OCK_E_FUNCTION_NOT_SUPP);
   return CKR_FUNCTION_NOT_SUPPORTED;
}


//
//
CK_RV __cdecl UpdateTweakValues( void )
{
   ock_log_err(OCK_E_FUNCTION_NOT_SUPP);
   return CKR_FUNCTION_NOT_SUPPORTED;
}

// Added for AIX work
void
SC_SetFunctionList(void){

   function_list.ST_Initialize          = (void *)ST_Initialize;
   function_list.ST_GetTokenInfo        = SC_GetTokenInfo;
   function_list.ST_GetMechanismList    = SC_GetMechanismList;
   function_list.ST_GetMechanismInfo    = SC_GetMechanismInfo;
   function_list.ST_InitToken           = SC_InitToken;
   function_list.ST_InitPIN             = SC_InitPIN;
   function_list.ST_SetPIN              = SC_SetPIN;
   function_list.ST_OpenSession         = SC_OpenSession;
   function_list.ST_CloseSession        = SC_CloseSession;
   function_list.ST_GetSessionInfo      = SC_GetSessionInfo;
   function_list.ST_GetOperationState   = SC_GetOperationState;
   function_list.ST_SetOperationState   = SC_SetOperationState;
   function_list.ST_Login               = SC_Login;
   function_list.ST_Logout              = SC_Logout;
   function_list.ST_CreateObject        = SC_CreateObject;
   function_list.ST_CopyObject          = SC_CopyObject;
   function_list.ST_DestroyObject       = SC_DestroyObject;
   function_list.ST_GetObjectSize       = SC_GetObjectSize;
   function_list.ST_GetAttributeValue   = SC_GetAttributeValue;
   function_list.ST_SetAttributeValue   = SC_SetAttributeValue;
   function_list.ST_FindObjectsInit     = SC_FindObjectsInit;
   function_list.ST_FindObjects         = SC_FindObjects;
   function_list.ST_FindObjectsFinal    = SC_FindObjectsFinal;
   function_list.ST_EncryptInit         = SC_EncryptInit;
   function_list.ST_Encrypt             = SC_Encrypt;
   function_list.ST_EncryptUpdate       = SC_EncryptUpdate;
   function_list.ST_EncryptFinal        = SC_EncryptFinal;
   function_list.ST_DecryptInit         = SC_DecryptInit;
   function_list.ST_Decrypt             = SC_Decrypt;
   function_list.ST_DecryptUpdate       = SC_DecryptUpdate;
   function_list.ST_DecryptFinal        = SC_DecryptFinal;
   function_list.ST_DigestInit          = SC_DigestInit;
   function_list.ST_Digest              = SC_Digest;
   function_list.ST_DigestUpdate        = SC_DigestUpdate;
   function_list.ST_DigestKey           = SC_DigestKey;
   function_list.ST_DigestFinal         = SC_DigestFinal;
   function_list.ST_SignInit            = SC_SignInit;
   function_list.ST_Sign                = SC_Sign;
   function_list.ST_SignUpdate          = SC_SignUpdate;
   function_list.ST_SignFinal           = SC_SignFinal;
   function_list.ST_SignRecoverInit     = SC_SignRecoverInit;
   function_list.ST_SignRecover         = SC_SignRecover;
   function_list.ST_VerifyInit          = SC_VerifyInit;
   function_list.ST_Verify              = SC_Verify;
   function_list.ST_VerifyUpdate        = SC_VerifyUpdate;
   function_list.ST_VerifyFinal         = SC_VerifyFinal;
   function_list.ST_VerifyRecoverInit   = SC_VerifyRecoverInit;
   function_list.ST_VerifyRecover       = SC_VerifyRecover;
   function_list.ST_DigestEncryptUpdate = NULL; // SC_DigestEncryptUpdate;
   function_list.ST_DecryptDigestUpdate = NULL; // SC_DecryptDigestUpdate;
   function_list.ST_SignEncryptUpdate   = NULL; //SC_SignEncryptUpdate;
   function_list.ST_DecryptVerifyUpdate = NULL; // SC_DecryptVerifyUpdate;
   function_list.ST_GenerateKey         = SC_GenerateKey;
   function_list.ST_GenerateKeyPair     = SC_GenerateKeyPair;
   function_list.ST_WrapKey             = SC_WrapKey;
   function_list.ST_UnwrapKey           = SC_UnwrapKey;
   function_list.ST_DeriveKey           = SC_DeriveKey;
   function_list.ST_SeedRandom          = SC_SeedRandom ;
   function_list.ST_GenerateRandom      = SC_GenerateRandom;
   function_list.ST_GetFunctionStatus   = NULL; // SC_GetFunctionStatus;
   function_list.ST_CancelFunction      = NULL; // SC_CancelFunction;

}
