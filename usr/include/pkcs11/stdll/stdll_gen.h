 /*
  * COPYRIGHT (c) International Business Machines Corp. 2001-2017
  *
  * This program is provided under the terms of the Common Public License,
  * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
  * software constitutes recipient's acceptance of CPL-1.0 terms which can be
  * found in the file LICENSE file or at
  * https://opensource.org/licenses/cpl1.0.php
  */

#ifndef _PKCS11_GENERAL_H
#define _PKCS11_GENERAL_H

#include <stdio.h>
#include "pkcs11o.h"
#include "stdll.h"

#define  CKS_MAX_SESSIONS         10
#define  CKS_NUMBER_OF_MECHANISMS 2
#define  CKS_NUMBER_OF_OBJECTS    100  /* Size of Object Array */
#define  CKS_NUMBER_OF_SLOTS      1

#define DLL_LBL    "Prototype Software Token (BSAFE)"
#define DLL_MFG    "IBM Austin:  RS/6000 Division   "
#define DLL_MODEL  "BSAFE Prototype                 "
#define DLL_SERIAL "mdmcl00-02  03-SEPTEMBER-1999   "

#define  DBG_LABEL "pkcs11.c: "

typedef struct SC_Slot {
   CK_SLOT_ID           MySlotID;
   CK_TOKEN_INFO        MyToken;
   CK_BBOOL             LoggedIn;     /* Is this redundant of MyState? */
   CK_CHAR_PTR          MyDevice;
   CK_STATE             MyState;      /* Login Status  */
   CK_USER_TYPE         MyUserType;   /* R/O, R/E User */
} SC_Slot_t;

SC_Slot_t slots[ CKS_NUMBER_OF_SLOTS ];

CK_ULONG                SlotCount;

STDLL_FcnList_t         MyFunctionList;
CK_MECHANISM_TYPE       MyMechanisms[ CKS_NUMBER_OF_MECHANISMS ];

typedef struct SC_Session {
   CK_SESSION_HANDLE    SessionList;
   CK_SESSION_INFO_PTR  SessionInfo;
} SC_Session_t;

SC_Session_t sessions[ CKS_NUMBER_OF_SLOTS ]
                     [ CKS_MAX_SESSIONS    ];

SC_OBJECT_HANDLE_PTR        ObjectList [ CKS_NUMBER_OF_SLOTS   ]
                                       [ CKS_MAX_SESSIONS      ];

SC_OBJECT_HANDLE_PTR        TokenObjectList;

/* Find Objects */
typedef struct SC_FindObjects {
   CK_BBOOL                FindObjectReady;
   CK_ATTRIBUTE_PTR        FindObjectAttr;
   CK_ULONG                FindObjectNum;
} SC_FindObjects_t;

SC_FindObjects_t FindParameters[ CKS_NUMBER_OF_SLOTS ]
                               [ CKS_MAX_SESSIONS    ];
/* Loop Control Variable */  /*  XXX Global? What about concurrent access? */
int lcv;
#endif
