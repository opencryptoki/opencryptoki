/*
 * COPYRIGHT (c) International Business Machines Corp. 2013-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/* Reenryption of EP11 secure keys. The secure key is reencrypted at the card
 * by a new wrapping (still pending) key. Needed also for SPKIs of public
 * keys.
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <dlfcn.h>
#include <ctype.h>
#include <errno.h>

#define OCK_NO_EP11_DEFINES
#include "../../include/pkcs11types.h"
#include "../../lib/common/p11util.h"
#include "../../lib/ep11_stdll/ep11_func.h"
#include "pin_prompt.h"

#define EP11SHAREDLIB_NAME "OCK_EP11_LIBRARY"
#define EP11SHAREDLIB_V4 "libep11.so.4"
#define EP11SHAREDLIB_V3 "libep11.so.3"
#define EP11SHAREDLIB_V2 "libep11.so.2"
#define EP11SHAREDLIB_V1 "libep11.so.1"
#define EP11SHAREDLIB "libep11.so"
#define PKCS11_MAX_PIN_LEN 128

CK_FUNCTION_LIST *funcs;
CK_SLOT_ID SLOT_ID = -1;
CK_LONG adapter = -1;
CK_LONG domain = -1;
CK_OBJECT_HANDLE key_store[4096];

m_get_xcp_info_t _m_get_xcp_info;
m_admin_t _m_admin;
xcpa_cmdblock_t _xcpa_cmdblock;
xcpa_internal_rv_t _xcpa_internal_rv;
m_add_module_t _m_add_module;
m_rm_module_t _m_rm_module;

CK_VERSION lib_version;

typedef struct {
    short format;
    short length;
    short apqns[512];
} __attribute__ ((packed)) ep11_target_t;


#define BLOBSIZE         2048*4



static int reencrypt(CK_SESSION_HANDLE session, CK_ULONG obj, CK_BYTE *old,
                     CK_ULONG old_len)
{
    CK_BYTE req[BLOBSIZE];
    CK_BYTE resp[BLOBSIZE];
    CK_LONG req_len;
    size_t resp_len;
    struct XCPadmresp rb;
    struct XCPadmresp lrb;
    ep11_target_t target_list;
    struct XCP_Module module;
    target_t target = XCP_TGT_INIT;
    CK_RV rc;
    CK_BYTE name[256];
    unsigned char blob[BLOBSIZE];
    CK_ULONG blob_len;

    CK_ATTRIBUTE opaque_template[] = {
        { CKA_IBM_OPAQUE, blob, BLOBSIZE }
    };

    CK_ATTRIBUTE name_template[] = {
        {CKA_LABEL, NULL_PTR, 0}
    };

    memset(name, 0, 256);

    /* print CKA_LABEL if it exists, only informational
       exist and size query */
    rc = funcs->C_GetAttributeValue(session, key_store[obj], name_template, 1);
    if (rc == CKR_OK && name_template[0].ulValueLen < 256) {
        name_template[0].pValue = name;
        /* knowing its size, after mem allocation, get the name value */
        rc = funcs->C_GetAttributeValue(session, key_store[obj], name_template,
                                        1);
    }

    memset(&rb, 0, sizeof(rb));
    memset(&lrb, 0, sizeof(lrb));

    if (_m_add_module != NULL) {
        memset(&module, 0, sizeof(module));
        module.version = lib_version.major >= 3 ? XCP_MOD_VERSION_2
                                                : XCP_MOD_VERSION_1;
        module.flags = XCP_MFL_MODULE;
        module.module_nr = adapter;
        XCPTGTMASK_SET_DOM(module.domainmask, domain);
        rc = _m_add_module(&module, &target);
        if (rc != 0)
            return CKR_FUNCTION_FAILED;
    } else {
        /* Fall back to old target handling */
        memset(&target_list, 0, sizeof(ep11_target_t));
        target_list.length = 1;
        target_list.apqns[0] = adapter;
        target_list.apqns[1] = domain;
        target = (target_t)&target_list;
    }

    rb.domain = domain;
    lrb.domain = domain;

    fprintf(stderr, "going to reencrpyt key %lx with blob len %lx: '%s'\n", obj,
            old_len, name);
    resp_len = BLOBSIZE;

    req_len = _xcpa_cmdblock(req, BLOBSIZE, XCP_ADM_REENCRYPT, &rb,
                              NULL, old, old_len);

    if (req_len < 0) {
        fprintf(stderr, "reencrypt cmd block construction failed\n");
        rc = -2;
        goto out;
    }

    rc = _m_admin(resp, &resp_len, NULL, 0, req, req_len, NULL, 0,
                  target);

    if (rc != CKR_OK || resp_len == 0) {
        fprintf(stderr, "reencryption failed: %lx %ld\n", rc, req_len);
        rc = -3;
        goto out;
    }

    if (_xcpa_internal_rv(resp, resp_len, &lrb, &rc) < 0) {
        fprintf(stderr, "reencryption response malformed: %lx\n", rc);
        rc = -4;
        goto out;
    }

    if (rc != 0) {
        fprintf(stderr, "reencryption failed: %lx\n", rc);
        rc = -7;
        goto out;
    }

    if (old_len != lrb.pllen) {
        fprintf(stderr, "reencryption blob size changed: %lx %lx %lx %lx\n",
                old_len, lrb.pllen, resp_len, req_len);
        rc = -5;
        goto out;
    }

    memset(blob, 0, sizeof(blob));
    blob_len = old_len;
    memcpy(blob, lrb.payload, blob_len);
    opaque_template[0].ulValueLen = blob_len;

    rc = funcs->C_SetAttributeValue(session, key_store[obj], opaque_template,
                                    1);
    if (rc != CKR_OK) {
        fprintf(stderr,
                "reencryption C_SetAttributeValue failed: obj %lx '%s' rc: %lx\n",
                obj, name, rc);
        rc = -6;
        goto out;
    }

    fprintf(stderr, "reencryption success obj: %lx '%s:\n", obj, name);

out:
    if (_m_rm_module != NULL)
        _m_rm_module(&module, target);
    return rc;
}

static CK_RV get_ep11_library_version(CK_VERSION *lib_version)
{
    unsigned int host_version;
    CK_ULONG version_len = sizeof(host_version);
    CK_RV rc;

    rc = _m_get_xcp_info(&host_version, &version_len,
                         CK_IBM_XCPHQ_VERSION, 0, 0);
    if (rc != CKR_OK) {
        fprintf(stderr, "_m_get_xcp_info (HOST) failed: rc=0x%lx\n", rc);
        return rc;
    }
    lib_version->major = (host_version & 0x00FF0000) >> 16;
    lib_version->minor = host_version & 0x000000FF0000;
    /*
     * EP11 host library < v2.0 returns an invalid version (i.e. 0x100). This
     * can safely be treated as version 1.0
     */
    if (lib_version->major == 0) {
        lib_version->major = 1;
        lib_version->minor = 0;
    }

    return CKR_OK;
}


static int check_card_status(void)
{
    CK_RV rc;
    ep11_target_t target_list;
    struct XCP_Module module;
    target_t target = XCP_TGT_INIT;
    CK_IBM_DOMAIN_INFO dinf;
    CK_ULONG dinf_len = sizeof(dinf);

    if (adapter == -1 || domain == -1) {
        fprintf(stderr, "adapter/domain specification missing.\n");
        return -1;
    }

    if (_m_add_module != NULL) {
        memset(&module, 0, sizeof(module));
        module.version = lib_version.major >= 3 ? XCP_MOD_VERSION_2
                                                : XCP_MOD_VERSION_1;
        module.flags = XCP_MFL_MODULE;
        module.module_nr = adapter;
        XCPTGTMASK_SET_DOM(module.domainmask, domain);
        rc = _m_add_module(&module, &target);
        if (rc != 0)
            return CKR_FUNCTION_FAILED;
    } else {
        /* Fall back to old target handling */
        memset(&target_list, 0, sizeof(ep11_target_t));
        target_list.length = 1;
        target_list.apqns[0] = adapter;
        target_list.apqns[1] = domain;
        target = (target_t)&target_list;
    }

    rc = _m_get_xcp_info((CK_VOID_PTR) &dinf, &dinf_len,
                         CK_IBM_XCPQ_DOMAIN, 0, target);

    if (rc != CKR_OK) {
        fprintf(stderr, "m_get_xcp_info rc 0x%lx, valid apapter/domain "
                "0x%02lx/%ld?.\n", rc, adapter, domain);
        rc = -1;
        goto out;
    }

    if (CK_IBM_DOM_COMMITTED_NWK & dinf.flags) {
        fprintf(stderr, "Card ID 0x%02lx, domain ID %ld has committed "
                "pending(next) WK\n", adapter, domain);
    } else {
        fprintf(stderr,
                "Card ID 0x%02lx, domain ID %ld has no committed pending WK\n",
                adapter, domain);
        rc = -1;
        goto out;
    }

out:
    if (_m_rm_module != NULL)
         _m_rm_module(&module, target);

    return rc;
}

static int get_user_pin(CK_BYTE *dest)
{
    int ret = -1;
    const char *userpin = NULL;
    char *buf_user = NULL;
    size_t userpinlen;

    userpin = pin_prompt(&buf_user, "Enter the USER PIN: ");
    if (!userpin) {
        fprintf(stderr, "Could not get USER PIN.\n");
        goto out;
    }
    userpinlen = strlen(userpin);

    if (userpinlen > PKCS11_MAX_PIN_LEN) {
        fprintf(stderr, "The USER PIN must be less than %d chars in length.\n",
                (int) PKCS11_MAX_PIN_LEN);
        goto out;
    }

    memcpy(dest, userpin, userpinlen + 1);
    ret = 0;
out:
    pin_free(&buf_user);
    return ret;
}

static int do_GetFunctionList(void)
{
    CK_RV rc;
    CK_RV (*func_list)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) = NULL;
    void *d;
    char *evar;
    char *evar_default = "libopencryptoki.so";

    evar = secure_getenv("PKCSLIB");
    if (evar == NULL) {
        evar = evar_default;
    }

    d = dlopen(evar, RTLD_NOW);
    if (d == NULL) {
        return 0;
    }

    *(void **)(&func_list) = dlsym(d, "C_GetFunctionList");
    if (func_list == NULL) {
        return 0;
    }
    rc = func_list(&funcs);

    if (rc != CKR_OK) {
        return 0;
    }

    return 1;

}

static void usage(char *fct)
{
    printf("usage:  %s [-slot <num>] [-adapter <num>] [-domain <num>] [-h]\n\n",
           fct);
    return;
}

static int do_ParseArgs(int argc, char **argv)
{
    int i;

    if (argc <= 1) {
        printf("No Arguments given. "
               "For help use the '--help' or '-h' option.\n");
        return -1;
    }

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-slot") == 0) {
            if (!isdigit(*argv[i + 1])) {
                printf("Slot parameter is not numeric!\n");
                return -1;
            }
            SLOT_ID = (int) strtol(argv[i + 1], NULL, 0);
            i++;
        } else if (strcmp(argv[i], "-adapter") == 0) {
            if (!isdigit(*argv[i + 1])) {
                printf("Adapter parameter is not numeric!\n");
                return -1;
            }
            adapter = (int) strtol(argv[i + 1], NULL, 0);
            i++;
        } else if (strcmp(argv[i], "-domain") == 0) {
            if (!isdigit(*argv[i + 1])) {
                printf("Domain parameter is not numeric!\n");
                return -1;
            }
            domain = (int) strtol(argv[i + 1], NULL, 0);
            i++;
        } else {
            printf("Invalid argument passed as option: %s\n", argv[i]);
            usage(argv[0]);
            return -1;
        }
    }
    if (SLOT_ID == (CK_SLOT_ID)(-1)) {
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

#ifdef EP11_HSMSIM
#define DLOPEN_FLAGS        RTLD_GLOBAL | RTLD_NOW | RTLD_DEEPBIND
#else
#define DLOPEN_FLAGS        RTLD_GLOBAL | RTLD_NOW
#endif

static void *ep11_load_host_lib(void)
{
    void *lib_ep11;
    char *ep11_lib_name;
    char *errstr;

    ep11_lib_name = secure_getenv(EP11SHAREDLIB_NAME);
    if (ep11_lib_name != NULL) {
        lib_ep11 = dlopen(ep11_lib_name, DLOPEN_FLAGS);

        if (lib_ep11 == NULL) {
            errstr = dlerror();
            fprintf(stderr, "Error loading shared library '%s' [%s]\n",
                    ep11_lib_name, errstr);
            return NULL;
        }
        return lib_ep11;
    }

    ep11_lib_name = EP11SHAREDLIB_V4;
    lib_ep11 = dlopen(ep11_lib_name, DLOPEN_FLAGS);

    if (lib_ep11 == NULL) {
        /* Try version 3 instead */
        ep11_lib_name = EP11SHAREDLIB_V3;
        lib_ep11 = dlopen(ep11_lib_name, DLOPEN_FLAGS);
    }

    if (lib_ep11 == NULL) {
        /* Try version 2 instead */
        ep11_lib_name = EP11SHAREDLIB_V2;
        lib_ep11 = dlopen(ep11_lib_name, DLOPEN_FLAGS);
    }

    if (lib_ep11 == NULL) {
        /* Try version 1 instead */
        ep11_lib_name = EP11SHAREDLIB_V1;
        lib_ep11 = dlopen(ep11_lib_name, DLOPEN_FLAGS);
    }

    if (lib_ep11 == NULL) {
        /* Try unversioned library instead */
        ep11_lib_name = EP11SHAREDLIB;
        lib_ep11 = dlopen(ep11_lib_name, DLOPEN_FLAGS);
    }

    if (lib_ep11 == NULL) {
        errstr = dlerror();
        fprintf(stderr, "Error loading shared library '%s[.4|.3|.2|.1]' [%s]\n",
                EP11SHAREDLIB, errstr);
        return NULL;
    }

    return lib_ep11;
}

int main(int argc, char **argv)
{
    int rc;
    void *lib_ep11;
    CK_C_INITIALIZE_ARGS cinit_args;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN + 1];
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_ULONG obj;
    CK_ULONG user_pin_len;
    CK_ULONG keys_found = 0;

    rc = do_ParseArgs(argc, argv);
    if (rc != 1) {
        return rc;
    }

    /* dynamically load in the ep11 shared library */
    lib_ep11 = ep11_load_host_lib();
    if (!lib_ep11)
        return CKR_FUNCTION_FAILED;

    *(void **)(&_xcpa_cmdblock) = dlsym(lib_ep11, "xcpa_cmdblock");
    if (_xcpa_cmdblock == NULL)
        *(void **)(&_xcpa_cmdblock) = dlsym(lib_ep11, "ep11a_cmdblock");
    *(void **)(&_m_admin) = dlsym(lib_ep11, "m_admin");
    *(void **)(&_xcpa_internal_rv) = dlsym(lib_ep11, "xcpa_internal_rv");
    if (_xcpa_internal_rv == NULL)
        *(void **)(&_xcpa_internal_rv) = dlsym(lib_ep11, "ep11a_internal_rv");
    *(void **)(&_m_get_xcp_info) = dlsym(lib_ep11, "m_get_xcp_info");
    if (_m_get_xcp_info == NULL)
        *(void **)(&_m_get_xcp_info) = dlsym(lib_ep11, "m_get_ep11_info");

    if (!_m_get_xcp_info || !_xcpa_cmdblock ||
        !_m_admin || !_xcpa_internal_rv) {
        fprintf(stderr, "ERROR getting function pointer from shared lib '%s'",
                EP11SHAREDLIB);
        return CKR_FUNCTION_FAILED;
    }

    /*
     * The following are only available since EP11 host library version 2.
     * Ignore if they fail to load, the code will fall back to the old target
     * handling in this case.
     */
    *(void **)(&_m_add_module) = dlsym(lib_ep11, "m_add_module");
    *(void **)(&_m_rm_module) = dlsym(lib_ep11, "m_rm_module");
    if (_m_add_module == NULL || _m_rm_module == NULL) {
        _m_add_module = NULL;
        _m_rm_module = NULL;
    }

    printf("Using slot #%lu...\n\n", SLOT_ID);

    rc = do_GetFunctionList();
    if (!rc) {
        fprintf(stderr, "ERROR do_GetFunctionList() Failed, rx = 0x%0x\n", rc);
        return rc;
    }

    memset(&cinit_args, 0x0, sizeof(cinit_args));
    cinit_args.flags = CKF_OS_LOCKING_OK;

    funcs->C_Initialize(&cinit_args);
    {
        CK_SESSION_HANDLE hsess = 0;
        rc = funcs->C_GetFunctionStatus(hsess);
        if (rc != CKR_FUNCTION_NOT_PARALLEL) {
            return rc;
        }

        rc = funcs->C_CancelFunction(hsess);
        if (rc != CKR_FUNCTION_NOT_PARALLEL) {
            return rc;
        }
    }

    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    rc = funcs->C_OpenSession(SLOT_ID, flags, NULL, NULL, &session);
    if (rc != CKR_OK) {
        fprintf(stderr, "C_OpenSession() rc = 0x%02x [%s]\n", rc,
                p11_get_ckr(rc));
        session = CK_INVALID_HANDLE;
        return rc;
    }

    if (get_user_pin(user_pin)) {
        fprintf(stderr, "get_user_pin() failed\n");
        rc = funcs->C_CloseAllSessions(SLOT_ID);
        if (rc != CKR_OK)
            fprintf(stderr, "C_CloseAllSessions() rc = 0x%02x [%s]\n", rc,
                    p11_get_ckr(rc));
        return rc;
    }

    user_pin_len = (CK_ULONG) strlen((char *) user_pin);
    rc = funcs->C_Login(session, CKU_USER, user_pin, user_pin_len);
    if (rc != CKR_OK) {
        fprintf(stderr, "C_Login() rc = 0x%02x [%s]\n", rc, p11_get_ckr(rc));
        return rc;
    }

    rc = get_ep11_library_version(&lib_version);
    if (rc != CKR_OK)
        return rc;

    if (check_card_status() != 0)
        return 1;

    /* find all objects */
    rc = funcs->C_FindObjectsInit(session, NULL, 0);

    do {
        rc = funcs->C_FindObjects(session, key_store, 4096, &keys_found);

        if (rc != CKR_OK) {
            fprintf(stderr, "C_FindObjects() rc = 0x%02x [%s]\n", rc,
                    p11_get_ckr(rc));
            return rc;
        }

        for (obj = 0; obj < keys_found; obj++) {
            CK_ATTRIBUTE opaque_template[] = {
                {CKA_IBM_OPAQUE, NULL_PTR, 0}
            };

            CK_KEY_TYPE keytype;
            CK_ATTRIBUTE key_type_template[] = {
                {CKA_KEY_TYPE, &keytype, sizeof(CK_KEY_TYPE)}
            };

            CK_BYTE *old_blob;

            /* only for keys */
            rc = funcs->C_GetAttributeValue(session, key_store[obj],
                                            key_type_template, 1);
            if (rc != CKR_OK)
                continue;

            /* exist and size query CKA_IBM_QPAQUE */
            rc = funcs->C_GetAttributeValue(session, key_store[obj],
                                            opaque_template, 1);
            if (rc == CKR_OK) {
                old_blob = malloc(opaque_template[0].ulValueLen);
                opaque_template[0].pValue = old_blob;
                /* get the blob after knowing its size */
                rc = funcs->C_GetAttributeValue(session, key_store[obj],
                                                opaque_template, 1);

                if (rc != CKR_OK) {
                    fprintf(stderr, "second C_GetAttributeValue failed "
                            "rc = 0x%02x [%s]\n", rc, p11_get_ckr(rc));
                    return rc;
                } else {
                    if (reencrypt(session, obj,
                                  (CK_BYTE *) opaque_template[0].pValue,
                                  opaque_template[0].ulValueLen) != 0) {
                        /* reencrypt failed */
                        return -1;
                    }
                }
                free(old_blob);
            }
        }
    }
    /* next 4096 objects */
    while (keys_found != 0);

    rc = funcs->C_FindObjectsFinal(session);
    fprintf(stderr, "all keys successfully reencrypted\n");

    rc = funcs->C_Logout(session);
    rc = funcs->C_CloseAllSessions(SLOT_ID);

    return rc;
}
