/*
 * Licensed materials, Property of IBM Corp.
 *
 * (C) COPYRIGHT International Business Machines Corp. 2013
 *
 */

/* Reenryption of EP11 secure keys. The secure key is reencrypted at the card 
   by a new wrapping (still pending) key. Needed also for SPKIs of public keys. */  

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <dlfcn.h>
#include <pkcs11types.h>
#include <ep11.h>
#include <ep11adm.h>
#include <p11util.h>
#include <ctype.h>

#define EP11SHAREDLIB "libep11.so"
#define PKCS11_MAX_PIN_LEN	128
#define PKCS11_SO_PIN_ENV_VAR   "PKCS11_SO_PIN"
#define PKCS11_USER_PIN_ENV_VAR "PKCS11_USER_PIN"

CK_FUNCTION_LIST  *funcs;
CK_SLOT_ID  SLOT_ID = -1;
CK_LONG adapter = -1; 
CK_LONG domain  = -1; 
CK_OBJECT_HANDLE key_store[4096];

int (*_m_get_ep11_info)(CK_VOID_PTR pinfo, CK_ULONG_PTR, unsigned int, 
			unsigned int, uint64_t);
long (*_ep11a_cmdblock)(unsigned char *, size_t , unsigned int ,  
			const struct ep11_admresp *, const unsigned char *,
			const unsigned char *, size_t );
unsigned long int (*_m_admin) (unsigned char *, size_t *, unsigned char *, 
			       size_t *, const unsigned char *, size_t , 
			       const unsigned char *, size_t, uint64_t) ;
long (*_ep11a_internal_rv)(const unsigned char *, size_t ,
			   struct ep11_admresp *, CK_RV *);

typedef struct  
{
  short format; 
  short length; 
  short apqns[512]; 
} __attribute__((packed)) ep11_target_t;


#define blobsize 2048*4 

typedef struct 
{
  size_t        blob_size; 
  size_t        blob_id; 
  unsigned char blob[blobsize]; 
} ep11_opaque;

static int
reencrypt(CK_SESSION_HANDLE session, CK_ULONG obj, CK_BYTE *old)
{
  CK_BYTE req[blobsize]; 
  CK_BYTE resp[blobsize]; 
  CK_LONG req_len; 
  size_t  resp_len;  
  struct ep11_admresp rb;
  struct ep11_admresp lrb;
  ep11_target_t target;
  CK_RV rc;
  CK_BYTE name[256];

  ep11_opaque *op_old = (ep11_opaque *) old; 
  ep11_opaque  op_new; 

  
  CK_ATTRIBUTE opaque_template[] = {
    {CKA_IBM_OPAQUE, &op_new, sizeof(op_new)}
  };

  CK_ATTRIBUTE name_template[] = {
    {CKA_LABEL, NULL_PTR, 0}
  };
  
  memset(name,0,256); 

  /* print CKA_LABEL if it exists, only informational  
     exist and size query */ 
  rc = funcs->C_GetAttributeValue(session, key_store[obj], name_template, 1);
  if (rc == CKR_OK && name_template[0].ulValueLen < 256)
    {
      name_template[0].pValue = name; 
      /* knowing its size, after mem allocation, get the name value */ 
      rc = funcs->C_GetAttributeValue(session, key_store[obj], name_template, 1);
    }
  
  memset(&rb,0, sizeof(rb));
  memset(&lrb,0, sizeof(lrb));
  memset(&target,0,sizeof(target)); 
  target.length   = 1; 
  
  target.apqns[0] = adapter; 
  target.apqns[1] = domain; 
  rb.domain  = domain;
  lrb.domain = domain;   

  fprintf(stderr,"going to reencrpyt key %lx with blob len %lx %s\n",obj,op_old->blob_size,name); 
  resp_len = blobsize; 

  req_len  = _ep11a_cmdblock(req, blobsize, EP11_ADM_REENCRYPT, &rb,
                            NULL, op_old->blob, op_old->blob_size);
  
  if (req_len < 0)
    {
      fprintf(stderr,"reencrypt cmd block construction failed\n");
      return -2; 
    }

  rc = _m_admin(resp, &resp_len, NULL, 0, req, req_len, NULL, 0, (unsigned long long) &target);

  if(rc != CKR_OK || resp_len == 0 || resp == NULL)
    {
      fprintf(stderr,"reencryption failed %lx %ld\n",rc,req_len);
      return -3; 
    }
  
  if (_ep11a_internal_rv(resp, resp_len, &lrb, &rc) < 0) 
    {
      fprintf(stderr, "reencryption response malformed %lx\n",rc);  
      return -4; 
     }
  
  if(op_old->blob_size != lrb.pllen)
    {
      fprintf(stderr, "reencryption blob size changed %lx %lx %lx %lx\n",
              op_old->blob_size,lrb.pllen,resp_len,req_len);
      return -5; 
    }

  memset(&op_new,0,sizeof(op_new)); 
  op_new.blob_id   = op_old->blob_id; 
  op_new.blob_size = op_old->blob_size; 
  memcpy(op_new.blob,lrb.payload,op_new.blob_size); 

  rc = funcs->C_SetAttributeValue(session, key_store[obj], opaque_template, 1);
  if (rc != CKR_OK)
    {
      fprintf(stderr, "reencryption C_SetAttributeValue failed obj %lx %s rc %lx\n",obj,name,rc); 
      return -6; 
    }

  fprintf(stderr, "reencryption success obj %lx %s\n",obj,name); 
  return 0; 
} 


static int 
check_card_status()
{
  CK_RV rc;
  ep11_target_t target;
  CK_IBM_DOMAIN_INFO dinf; 
  CK_ULONG dinf_len = sizeof(dinf); 
  
  if (adapter == -1 || domain == -1)
    {
      fprintf(stderr,"adapter/domain specification missing.\n");
      return -1; 
    }
  
  target.format = 0; 
  target.length = 1; 
  target.apqns[0] = adapter; 
  target.apqns[1] = domain; 

  rc = _m_get_ep11_info ((CK_VOID_PTR) &dinf, &dinf_len,
                        CK_IBM_EP11Q_DOMAIN,
                        0,
                        (unsigned long long) &target);

  if (rc != CKR_OK)
    {
      fprintf(stderr,"m_get_ep11_info rc 0x%lx, valid apapter/domain 0x%02lx/%ld?.\n",
              rc,adapter,domain);
      return -1; 
    }

  if (CK_IBM_DOM_COMMITTED_NWK & dinf.flags) {
    fprintf(stderr,"Card ID 0x%02lx, domain ID %ld has committed pending(next) WK\n",
            adapter, domain);
  } else {
    fprintf(stderr,"Card ID 0x%02lx, domain ID %ld has no committed pending WK\n",
            adapter, domain);
    return -1; 
   }

  return 0; 

}


static int get_user_pin(CK_BYTE *dest)
{
  char *val;
  
  val = getenv(PKCS11_USER_PIN_ENV_VAR);
  if (val == NULL) {
    fprintf(stderr, "The environment variable %s must be set.\n"
            , PKCS11_USER_PIN_ENV_VAR);
    return -1;
  }
  
  if ((strlen(val) + 1) > PKCS11_MAX_PIN_LEN) {
    fprintf(stderr, "The environment variable %s must hold a "
            "value less than %d chars in length.\n",
            PKCS11_USER_PIN_ENV_VAR, (int)PKCS11_MAX_PIN_LEN);
    return -1;
  }
  
  memcpy(dest, val, strlen(val) + 1);
  return 0;
}

static int 
do_GetFunctionList( void )
{
  CK_RV    rc;
  CK_RV  (*func_list)() = NULL; 
  void    *d;
  char    *evar;
  char    *evar_default = "libopencryptoki.so";
  
  evar = getenv("PKCSLIB");
  if ( evar == NULL) {
    evar = evar_default;
  }

  d = dlopen(evar,RTLD_NOW);
  if ( d == NULL ) {
    return 0;
  }
  
  func_list = (CK_RV (*)())dlsym(d,"C_GetFunctionList");
  if (func_list == NULL ) {
    return 0;
  }
  rc = func_list(&funcs);
  
  if (rc != CKR_OK) {
    return 0;
  }
  
  return 1;
  
}

static void 
usage (char *fct)
{
  printf("usage:  %s [-slot <num>] [-adapter <num>] [-domain <num>] [-h]\n\n", fct );
  return;
}

static int 
do_ParseArgs(int argc, char **argv)
{
  int i;
  
  if (argc <= 1) {
      printf ("No Arguments given. For help use the '--help' or '-h' option.\n");
      return -1; 
  }

  for (i = 1; i < argc; i++) {
    if (strcmp (argv[i], "-h") == 0 || strcmp (argv[i], "--help") == 0) {
      usage (argv [0]);
      return 0;
    }
    else if (strcmp (argv[i], "-slot") == 0) {
      if (!isdigit(*argv[i+1])) {
         printf("Slot parameter is not numeric!\n");
         return -1;
      }
      SLOT_ID = (int)strtol(argv[i+1], NULL, 0);
      i++;
    }
    else if (strcmp (argv[i], "-adapter") == 0) {
      if (!isdigit(*argv[i+1])) {
         printf("Adapter parameter is not numeric!\n");
         return -1;
      }
      adapter = (int)strtol(argv[i+1], NULL, 0);
      i++; 
    }
    else if (strcmp (argv[i], "-domain") == 0) {
      if (!isdigit(*argv[i+1])) {
         printf("Domain parameter is not numeric!\n");
         return -1;
      }
      domain = (int)strtol(argv[i+1], NULL, 0);
      i++; 
    }
    else {
      printf ("Invalid argument passed as option: %s\n", argv [i]);
      usage (argv [0]);
      return -1;
    }
  }
  if (SLOT_ID == -1) {
      printf("Slot-ID not set!\n");
      return -1;
  } 
  if (adapter == -1) {
      printf("Adapter-ID not set!\n");
      return -1;
  }
  if (domain == -1) {
      printf("Domain-ID not set!\n");
      return -1;
  }

  return 1;
}


int main  (int argc, char **argv){
  int rc;
  int obj; 
  void *lib_ep11;
  CK_C_INITIALIZE_ARGS cinit_args;
  CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
  CK_FLAGS flags;
  CK_SESSION_HANDLE session;
  CK_ULONG     user_pin_len;
  CK_ULONG   keys_found = 0; 
  
  rc = do_ParseArgs(argc, argv);
  if(rc != 1){
    return rc;
  }
 
  /* dynamically load in the ep11 shared library */
  lib_ep11 = dlopen(EP11SHAREDLIB, RTLD_GLOBAL | RTLD_NOW);
  if (!lib_ep11) {
  	fprintf(stderr,"ERROR loading shared lib '%s' [%s]", EP11SHAREDLIB, dlerror());
  	return CKR_FUNCTION_FAILED;
  }

  _m_get_ep11_info = dlsym(lib_ep11, "m_get_ep11_info");
  _ep11a_cmdblock = dlsym(lib_ep11, "ep11a_cmdblock");
  _m_admin = dlsym(lib_ep11, "m_admin");
  _ep11a_internal_rv = dlsym(lib_ep11, "ep11a_internal_rv");

  if (!_m_get_ep11_info || !_ep11a_cmdblock || 
	!_m_admin || !_ep11a_internal_rv) {
	fprintf(stderr,"ERROR getting function pointer from shared lib '%s'", EP11SHAREDLIB);
	return CKR_FUNCTION_FAILED;
  }
 
  printf("Using slot #%lu...\n\n", SLOT_ID);
  
  rc = do_GetFunctionList();
  if(! rc) {
    fprintf(stderr,"ERROR do_GetFunctionList() Failed, rx = 0x%0x\n", rc);
    return rc;
  }
  
  memset( &cinit_args, 0x0, sizeof(cinit_args) );
  cinit_args.flags = CKF_OS_LOCKING_OK;
  
  funcs->C_Initialize( &cinit_args );
  {
    CK_SESSION_HANDLE hsess = 0;
    rc = funcs->C_GetFunctionStatus(hsess);
    if (rc != CKR_FUNCTION_NOT_PARALLEL){
      return rc;
    }
    
    rc = funcs->C_CancelFunction(hsess);
    if (rc != CKR_FUNCTION_NOT_PARALLEL){
      return rc;
    }
  }
  
  flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;          
  rc = funcs->C_OpenSession(SLOT_ID, flags,             
                            NULL, NULL, &session );     
  if (rc != CKR_OK) {
    fprintf(stderr,"C_OpenSession() rc = 0x%02x [%s]\n",rc, p11_get_ckr(rc));
    session = CK_INVALID_HANDLE;    
    return rc; 
  }                                       

  if (get_user_pin(user_pin)) 
    {                                          
      fprintf(stderr,"get_user_pin() failed\n"); 
      rc = funcs->C_CloseAllSessions(SLOT_ID); 
      if (rc != CKR_OK) 
        fprintf(stderr,"C_CloseAllSessions() rc = 0x%02x [%s]\n",rc, p11_get_ckr(rc)); 
      return rc; 
    }
  
  user_pin_len = (CK_ULONG) strlen( (char *) user_pin);                
  rc = funcs->C_Login(session, CKU_USER,                               
                      user_pin, user_pin_len);                         
  if (rc != CKR_OK) {                                                  
    fprintf(stderr,"C_Login() rc = 0x%02x [%s]\n",rc, p11_get_ckr(rc));                                 
    return rc; 
  }                                                                    
  
  if (check_card_status() != 0)
    return 1; 
      
  /* find all objects */ 
  rc = funcs->C_FindObjectsInit(session,NULL,0); 
  
  do {
    rc = funcs->C_FindObjects(session,
                              key_store,
                              4096,
                              &keys_found);
        
    if (rc != CKR_OK)
      {
        fprintf(stderr,"C_FindObjects() rc = 0x%02x [%s]\n",rc, p11_get_ckr(rc));
        return rc; 
      }
    
    for (obj = 0; obj < keys_found; obj++)
      {
        CK_ATTRIBUTE opaque_template[] = {
          {CKA_IBM_OPAQUE, NULL_PTR, 0}
        };
        
        CK_KEY_TYPE keytype; 
        CK_ATTRIBUTE key_type_template[] = {
          {CKA_KEY_TYPE, &keytype, sizeof(CK_KEY_TYPE)} 
        };
        
        CK_BYTE *old_blob;
        
        /* only for keys */ 
        rc = funcs->C_GetAttributeValue(session, key_store[obj], key_type_template, 1);
        if (rc != CKR_OK)
          continue; 
        
        /* exist and size query CKA_IBM_QPAQUE*/ 
        rc = funcs->C_GetAttributeValue(session, key_store[obj], opaque_template, 1);
        if (rc == CKR_OK)
          {
            old_blob = malloc(opaque_template[0].ulValueLen); 
            opaque_template[0].pValue = old_blob; 
            /* get the blob after knowing its size */ 
            rc = funcs->C_GetAttributeValue(session, key_store[obj], opaque_template, 1);
            
            if (rc != CKR_OK)
              {
                fprintf(stderr,"second C_GetAttributeValue failed rc = 0x%02x [%s]\n",
			rc, p11_get_ckr(rc));
                return rc; 
              }
            else
              {
                if (reencrypt(session,obj,(CK_BYTE *) opaque_template[0].pValue) != 0)
                  {
                    /* reencrypt failed */ 
                    return -1; 
                  }
              }
            free(old_blob); 
          }
      }
  }
  /* next 4096 objects */ 
  while(keys_found != 0); 
  
  rc = funcs->C_FindObjectsFinal(session);
  fprintf(stderr,"all keys successfully reencrypted\n");

  rc = funcs->C_Logout(session);
  rc = funcs->C_CloseAllSessions(SLOT_ID);   

  return rc;
}

