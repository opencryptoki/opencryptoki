/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <dlfcn.h>
#include <pkcs11types.h>
#include <locale.h>
#include <limits.h>
#include <nl_types.h>
#include <memory.h>
#include <string.h>
#include <strings.h>
#include <pwd.h>
#include <grp.h>
#include <openssl/crypto.h>

#include "platform.h"
#include "slotmgr.h"
#include "pkcsconf_msg.h"
#include "p11util.h"
#include "defs.h"
#include "mechtable.h"
#include "uri.h"
#include "pin_prompt.h"

#if defined(_AIX)
    const char *__progname = "pkcsconf";
#endif

#define LEEDS_DEFAULT_PIN "87654321"
#define PIN_SIZE 80
#define BACK_SPACE 8
#define DELETE     127
#define LINE_FEED  10

#define CFG_UNUSED_1       0x0001
#define CFG_UNUSED_2       0x0002
#define CFG_SLOT           0x0004
#define CFG_PKCS_INFO      0x0008
#define CFG_TOKEN_INFO     0x0010
#define CFG_SLOT_INFO      0x0020
#define CFG_MECHANISM_INFO 0x0040
#define CFG_INITIALIZE     0x0080
#define CFG_INIT_USER      0x0100
#define CFG_SET_USER       0x0200
#define CFG_SET_SO         0x0400
#define CFG_NEW_PIN        0x0800
#define CFG_SHARED_MEM     0x1000
#define CFG_LIST_SLOT      0x2000

CK_RV init(void);
void usage(char *);
int get_slot(char *);
CK_RV display_pkcs11_info(void);
CK_RV get_slot_list(CK_BOOL tokenPresent);
CK_RV display_slot_info(int);
CK_RV display_token_info(int);
CK_RV display_mechanism_info(int);
CK_RV init_token(int, const char *);
CK_RV init_user_pin(int, const char *, const char *);
CK_RV list_slot(int);
CK_RV set_user_pin(int, CK_USER_TYPE, const char *, const char *);

void *dllPtr;
CK_FUNCTION_LIST_PTR FunctionPtr = NULL;
CK_SLOT_ID_PTR SlotList = NULL;
CK_ULONG SlotCount = 0;
Slot_Mgr_Shr_t *shmp = NULL;
int in_slot;

int main(int argc, char *argv[])
{
    CK_RV rv = CKR_OK;          // Return Code
    CK_FLAGS flags = 0;         // Bit mask for what options were passed in
    int c, errflag = 0;
    const char *pin_user = NULL, *pin_so = NULL, *pin_new = NULL;
    char *buf_user = NULL, *buf_so = NULL, *buf_new = NULL;

    /* Parse the command line parameters */
    while ((c = getopt(argc, argv, "itsmIc:S:U:upPn:lh")) != (-1)) {
        switch (c) {
        case 'c':              /* a specific card (slot) is specified */
            if (flags & CFG_SLOT) {
                warnx("Must specify a single slot.");
                errflag++;
            } else {
                flags |= CFG_SLOT;
                in_slot = get_slot(optarg);
                if (in_slot < 0) {
                    warnx("Must specify a decimal number as slot.");
                    errflag++;
                }
            }
            break;
        case 'S':              /* the SO pin */
            if (pin_so) {
                warnx("Must specify a single SO PIN.");
                errflag++;
            } else {
                pin_so = optarg;
            }
            break;
        case 'U':              /* the user pin */
            if (pin_user) {
                warnx("Must specify a single user PIN.");
                errflag++;
            } else {
                pin_user = optarg;
            }
            break;
        case 'n':              /* the new pin */
            if (pin_new) {
                warnx("Must specify a single user PIN.");
                errflag++;
            } else {
                pin_new = optarg;
            }
            break;
        case 'i':              /* display PKCS11 info */
            flags |= CFG_PKCS_INFO;
            break;
        case 't':              /* display token info */
            flags |= CFG_TOKEN_INFO;
            break;
        case 's':              /* display slot info */
            flags |= CFG_SLOT_INFO;
            break;
        case 'm':              /* display mechanism info */
            flags |= CFG_MECHANISM_INFO;
            break;
        case 'I':              /* initialize the token */
            flags |= CFG_INITIALIZE;
            break;
        case 'u':              /* initialize the user PIN */
            flags |= CFG_INIT_USER;
            break;
        case 'p':              /* set the user PIN */
            flags |= CFG_SET_USER;
            break;
        case 'P':              /* set the SO PIN */
            flags |= CFG_SET_SO;
            break;
        case 'l':              /* display slot description */
            flags |= CFG_LIST_SLOT;
            break;
        case 'h':              /* display command line options */
            usage(argv[0]);
            break;
        default:               /* if something else was passed in it's an error */
            errflag++;
            break;
        }
    }
    if (optind < argc) {
        warnx("unrecognized option --- '%s'", argv[optind]);
        errflag++;
    }
    if (errflag != 0)           /* If there was an error print the usage statement */
        usage(argv[0]);

    if (!flags)                 /* If there was no options print the usage statement */
        usage(argv[0]);

    /* Eliminate the ability to specify -I -p -u -P without a slot number */
    if ((flags & (CFG_INITIALIZE | CFG_INIT_USER | CFG_SET_USER | CFG_SET_SO))
        && !(flags & CFG_SLOT)) {
        usage(argv[0]);
    }
    /* Load the PKCS11 library and start the slotmanager if it is not running */
    if (init() != CKR_OK) {
        rv = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Get the slot list and indicate if a slot number was passed in or not */
    if ((rv = get_slot_list((flags & (CFG_SLOT_INFO | CFG_LIST_SLOT)) == 0)))
        goto done;

    /* If the user tries to set the user and SO pin at the same time print an
     * error massage and exit indicating the function failed */
    if ((flags & CFG_SET_USER) && (flags & CFG_SET_SO)) {
        warnx("Setting the SO and user PINs are mutually exclusive.");
        rv = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* If the user wants to display PKCS11 info call the function to do so */
    if (flags & CFG_PKCS_INFO)
        if ((rv = display_pkcs11_info()))
            goto done;

    /* If the user wants to display token info call the function to do so */
    if (flags & CFG_TOKEN_INFO)
        if ((rv = display_token_info((flags & CFG_SLOT) ? in_slot : -1)))
            goto done;

    /* If the user wants to display slot info call the function to do so */
    if (flags & CFG_SLOT_INFO)
        if ((rv = display_slot_info((flags & CFG_SLOT) ? in_slot : -1)))
            goto done;

    /* If the user wants to display slot info call the function to do so */
    if (flags & CFG_LIST_SLOT)
        if ((rv = list_slot((flags & CFG_SLOT) ? in_slot : -1)))
            goto done;

    /* If the user wants to display mechanism info call the function to do so */
    if (flags & CFG_MECHANISM_INFO)
        if ((rv = display_mechanism_info((flags & CFG_SLOT) ? in_slot : -1)))
            goto done;

    /* If the user wants to initialize the card check to see if they passed in
     * the SO pin, if not ask for the PIN */
    if (flags & CFG_INITIALIZE) {
        if (!pin_so)
            pin_so = pin_prompt(&buf_so, "Enter the SO PIN: ");

        rv = init_token(in_slot, pin_so);
    }

    /* If the user wants to initialize the User PIN, check to see if they have
     * passed in the SO PIN, if not ask for it.  Then check to see if they
     * passed the New User PIN on the command line if not ask for the PIN and
     * verify it
     */
    if (flags & CFG_INIT_USER) {
        if (!pin_so)
            pin_so = pin_prompt(&buf_so, "Enter the SO PIN: ");

        if (!pin_new)
            pin_new = pin_prompt_new(&buf_new,
                                     "Enter the new user PIN: ",
                                     "Re-enter the new user PIN: ");

        if (!pin_new) {
            warnx("Invalid new user pin");
            rv = CKR_PIN_INVALID;
            goto done;
        }

        rv = init_user_pin(in_slot, pin_new, pin_so);

        /* partial cleanup/re-init for chained sub-functions */
        pin_new = NULL;
        pin_free(&buf_new);
    }

    /* If the user wants to set the SO PIN, check to see if they have passed the
     * current SO PIN and the New PIN in.  If not prompt and validate them. */
    if (flags & CFG_SET_SO) {
        if (!pin_so)
            pin_so = pin_prompt(&buf_so, "Enter the SO PIN: ");

        if (!pin_new)
            pin_new = pin_prompt_new(&buf_new,
                                     "Enter the new SO PIN: ",
                                     "Re-enter the new SO PIN: ");

        if (!pin_new) {
            warnx("Invalid new so pin");
            rv = CKR_PIN_INVALID;
            goto done;
        }

        rv = set_user_pin(in_slot, CKU_SO, pin_so, pin_new);

        /* partial cleanup/re-init for chained sub-functions */
        pin_new = NULL;
        pin_free(&buf_new);
    }

    /* If the user wants to set the User PIN, check to see if they have passed
     * the current User PIN and the New PIN in. If not prompt and validate them.
     */
    if (flags & CFG_SET_USER) {
        if (!pin_user)
            pin_user = pin_prompt(&buf_user, "Enter user PIN: ");

        if (!pin_new)
            pin_new = pin_prompt_new(&buf_new,
                                     "Enter the new user PIN: ",
                                     "Re-enter the new user PIN: ");

        if (!pin_new) {
            warnx("Invalid new user pin");
            rv = CKR_PIN_INVALID;
            goto done;
        }

        rv = set_user_pin(in_slot, CKU_USER, pin_user, pin_new);
    }

    /* We are done, detach from shared memory, and free the memory we may have
     * allocated. */

done:
    pin_free(&buf_user);
    pin_free(&buf_so);
    pin_free(&buf_new);

    free(SlotList);
    if (FunctionPtr)
        FunctionPtr->C_Finalize(NULL);
#ifndef WITH_SANITIZER
    if (dllPtr)
        dlclose(dllPtr);
#endif

    return rv;
}

int get_slot(char *optarg)
{
    char *endptr;
    long val;

    errno = 0;
    val = strtol(optarg, &endptr, 10);

    /* Check for various possible errors */
    if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
        || (errno != 0 && val == 0)) {
        perror("strtol");
        return -1;
    }

    /* No digits were found in optarg, so return error */
    if (endptr == optarg)
        return -1;

    /* Invalid slot id */
    if (val < INT_MIN || val >= NUMBER_SLOTS_MANAGED)
        return -1;

    return (int)val;
}

CK_RV check_user_and_group(void)
{
    int i;
    uid_t euid;
    struct passwd *epw;
    struct group *grp;

    /*
     * Check for root user or Group PKCS#11 Membership.
     * Only these are allowed.
     */
    euid = geteuid();

    /* effective Root is ok */
    if (euid == 0)
        return CKR_OK;

    /*
     * Check for member of group. SAB get login seems to not work
     * with some instances of application invocations (particularly
     * when forked). So we need to get the group information.
     * Really need to take the uid and map it to a name.
     */
    grp = getgrnam(PKCS_GROUP);
    if (grp == NULL) {
        return CKR_FUNCTION_FAILED;
    }

    if (getgid() == grp->gr_gid || getegid() == grp->gr_gid)
        return CKR_OK;

    /* Check if effective user is member of pkcs11 group */
    epw = getpwuid(euid);
    for (i = 0; grp->gr_mem[i]; i++) {
        if ((epw && (strncmp(epw->pw_name, grp->gr_mem[i],
                             strlen(epw->pw_name)) == 0)))
            return CKR_OK;
    }

    return CKR_FUNCTION_FAILED;
}

void print_info_uri(CK_INFO_PTR info)
{
    struct p11_uri *uri;

    uri = p11_uri_new();
    if (!uri)
        return;

    uri->info = info;

    printf("\tURI: %s\n", p11_uri_format(uri));

    p11_uri_free(uri);
    uri = NULL;
}

CK_RV display_pkcs11_info(void)
{

    CK_RV rc;
    CK_INFO CryptokiInfo;

    /* Get the PKCS11 infomation structure and if fails print message */
    rc = FunctionPtr->C_GetInfo(&CryptokiInfo);
    if (rc != CKR_OK) {
        warnx("Error getting PKCS#11 info: 0x%lX (%s)", rc, p11_get_ckr(rc));
        return rc;
    }

    /* display the header and information */
    printf("PKCS#11 Info\n");
    printf("\tVersion %d.%d \n", CryptokiInfo.cryptokiVersion.major,
           CryptokiInfo.cryptokiVersion.minor);
    printf("\tManufacturer: %.32s \n", CryptokiInfo.manufacturerID);
    printf("\tFlags: 0x%lX  \n", CryptokiInfo.flags);
    printf("\tLibrary Description: %.32s \n", CryptokiInfo.libraryDescription);
    printf("\tLibrary Version: %d.%d \n", CryptokiInfo.libraryVersion.major,
           CryptokiInfo.libraryVersion.minor);
    print_info_uri(&CryptokiInfo);

    return rc;
}

CK_RV get_slot_list(CK_BOOL tokenPresent)
{
    CK_RV rc;                   // Return Code

    /* Find out how many tokens are present in slots */
    rc = FunctionPtr->C_GetSlotList(tokenPresent, NULL_PTR, &SlotCount);
    if (rc != CKR_OK) {
        warnx("Error getting number of slots: 0x%lX (%s)", rc,
              p11_get_ckr(rc));
        return rc;
    }

    if (SlotCount == 0) {
        warnx("C_GetSlotList returned 0 slots. Check that your tokens"
              " are installed correctly.");
        return -ENODEV;
    }

    /* Allocate enough space for the slots information */
    SlotList = (CK_SLOT_ID_PTR) malloc(SlotCount * sizeof(CK_SLOT_ID));

    rc = FunctionPtr->C_GetSlotList(tokenPresent, SlotList, &SlotCount);
    if (rc != CKR_OK) {
        warnx("Error getting slot list: 0x%lX (%s)", rc, p11_get_ckr(rc));
        return rc;
    }

    return CKR_OK;
}

void display_mechanism_name(CK_MECHANISM_TYPE mech)
{
    const struct mechrow *row = mechrow_from_numeric(mech);

    if (row)
        printf("(%s)", row->string);
}

void display_mechanism_flags(CK_FLAGS flags)
{
    CK_ULONG i, firsties = 1;
    char *tok = "(";

    for (i = 0; pkcs11_mech_flags[i].name; i++) {
        if (pkcs11_mech_flags[i].flag & flags) {
            printf("%s%s", tok, pkcs11_mech_flags[i].name);

            if (firsties) {
                tok = "|";
                firsties = 0;
            }
        }
    }

    if (!firsties)
        printf(")");
}

CK_RV print_mech_info(int slot_id)
{
    CK_RV rc;                   // Return Code
    CK_MECHANISM_TYPE_PTR MechanismList = NULL; // Head to Mechanism list
    CK_MECHANISM_INFO MechanismInfo;    // Structure to hold Mechanism Info
    CK_ULONG MechanismCount = 0;        // Number of supported mechanisms
    CK_ULONG i;

    /* For each slot find out how many mechanisms are supported */
    rc = FunctionPtr->C_GetMechanismList(slot_id, NULL_PTR, &MechanismCount);
    if (rc != CKR_OK) {
        if (rc == CKR_TOKEN_NOT_PRESENT)
            return CKR_OK;
        warnx("Error getting number of mechanisms: 0x%lX (%s)",
              rc, p11_get_ckr(rc));
        return rc;
    }

    /* Allocate enough memory to store all the supported mechanisms */
    MechanismList = (CK_MECHANISM_TYPE_PTR) malloc(MechanismCount *
                                                   sizeof(CK_MECHANISM_TYPE));

    /* This time get the mechanism list */
    rc = FunctionPtr->C_GetMechanismList(slot_id, MechanismList,
                                         &MechanismCount);
    if (rc != CKR_OK) {
        warnx("Error getting mechanisms list: 0x%lX (%s)", rc,
              p11_get_ckr(rc));
        return rc;
    }

    /* For each Mechanism in the List */
    for (i = 0; i < MechanismCount; i++) {

        /* Get the Mechanism Info and display it */
        rc = FunctionPtr->C_GetMechanismInfo(slot_id,
                                             MechanismList[i], &MechanismInfo);
        if (rc != CKR_OK) {
            warnx("Error getting mechanisms info: 0x%lX (%s)", rc,
                  p11_get_ckr(rc));
            return rc;
        }
        printf("Mechanism #%lu\n", i);
        printf("\tMechanism: 0x%lX ", MechanismList[i]);

        display_mechanism_name(MechanismList[i]);
        printf("\n");

        printf("\tKey Size: %lu-%lu\n", MechanismInfo.ulMinKeySize,
               MechanismInfo.ulMaxKeySize);
        printf("\tFlags: 0x%lX ", MechanismInfo.flags);

        display_mechanism_flags(MechanismInfo.flags);
        printf("\n");
    }

    /* Free the memory we allocated for the mechanism list */
    free(MechanismList);
    return CKR_OK;
}

CK_RV display_mechanism_info(int slot_id)
{
    CK_ULONG lcv;

    if (slot_id == -1) {
        for (lcv = 0; lcv < SlotCount; lcv++) {
            printf("Mechanism Info for Slot #%lu:\n", SlotList[lcv]);
            print_mech_info(SlotList[lcv]);
        }
    } else {
        return print_mech_info(slot_id);
    }

    return CKR_OK;
}

void print_slot_info(int slot_id, CK_SLOT_INFO *SlotInfo)
{
    /* Display the slot information */
    printf("Slot #%d Info\n", slot_id);
    printf("\tDescription: %.64s\n", SlotInfo->slotDescription);
    printf("\tManufacturer: %.32s\n", SlotInfo->manufacturerID);
    printf("\tFlags: 0x%lX %c", SlotInfo->flags,
           SlotInfo->flags != 0 ? '(' : ' ');

    if (SlotInfo->flags & CKF_TOKEN_PRESENT)
        printf("TOKEN_PRESENT|");
    if (SlotInfo->flags & CKF_REMOVABLE_DEVICE)
        printf("REMOVABLE_DEVICE|");
    if (SlotInfo->flags & CKF_HW_SLOT)
        printf("HW_SLOT|");
    if (SlotInfo->flags != 0)
        printf(")");
    printf("\n");

    printf("\tHardware Version: %d.%d\n", SlotInfo->hardwareVersion.major,
           SlotInfo->hardwareVersion.minor);
    printf("\tFirmware Version: %d.%d\n", SlotInfo->firmwareVersion.major,
           SlotInfo->firmwareVersion.minor);
}

void print_slot_info_uri(int slot_id, CK_SLOT_INFO_PTR SlotInfo)
{
    struct p11_uri *uri;

    uri = p11_uri_new();
    if (!uri)
        return;

    uri->slot_id = slot_id;
    uri->slot_info = SlotInfo;

    printf("\tURI: %s\n", p11_uri_format(uri));

    p11_uri_free(uri);
    uri = NULL;
}

CK_RV display_slot_info(int slot_id)
{
    CK_RV rc;                   // Return Code
    CK_SLOT_INFO SlotInfo;      // Structure to hold slot information
    unsigned int lcv;           // Loop control Variable

    if (slot_id != -1) {
        rc = FunctionPtr->C_GetSlotInfo(slot_id, &SlotInfo);
        if (rc != CKR_OK) {
            warnx("Error getting slot info: 0x%lX (%s)", rc,
                  p11_get_ckr(rc));
            return rc;
        }

        print_slot_info(slot_id, &SlotInfo);
        print_slot_info_uri(slot_id, &SlotInfo);
        return CKR_OK;
    }

    for (lcv = 0; lcv < SlotCount; lcv++) {
        /* Get the info for the slot we are examining and store in SlotInfo */
        rc = FunctionPtr->C_GetSlotInfo(SlotList[lcv], &SlotInfo);
        if (rc != CKR_OK) {
            if (rc == CKR_TOKEN_NOT_PRESENT)
                return CKR_OK;
            warnx("Error getting slot info: 0x%lX (%s)", rc,
                  p11_get_ckr(rc));
            return rc;
        }

        print_slot_info(SlotList[lcv], &SlotInfo);
        print_slot_info_uri(SlotList[lcv], &SlotInfo);

    }
    return CKR_OK;
}

CK_RV list_slot(int slot_id)
{
    CK_RV rc;                   // Return code
    CK_SLOT_INFO SlotInfo;      // Structure to hold slot information
    unsigned int lcv;           // Loop control variable

    if (slot_id != -1) {
        rc = FunctionPtr->C_GetSlotInfo(slot_id, &SlotInfo);
        if (rc != CKR_OK) {
            warnx("Error getting slot info: 0x%lX (%s)", rc,
                  p11_get_ckr(rc));
            return rc;
        }

        /* Display the slot description */
        printf("%d:", slot_id);
        printf("\tDescription: %.64s\n", SlotInfo.slotDescription);

        return CKR_OK;
    }


    for (lcv = 0; lcv < SlotCount; lcv++) {
        /* Get the info for the slot we are examining and store in SlotInfo */
        rc = FunctionPtr->C_GetSlotInfo(SlotList[lcv], &SlotInfo);
        if (rc != CKR_OK) {
            warnx("Error getting slot info: 0x%lX (%s)", rc,
                  p11_get_ckr(rc));
            return rc;
        }

        /* Display the slot description */
        printf("%lu:", SlotList[lcv]);
        printf("\tDescription: %.64s\n", SlotInfo.slotDescription);
    }
    return CKR_OK;
}

static void print_value(CK_ULONG value, char *buf, CK_ULONG buf_len,
                        CK_BBOOL check_infinite, char *fmt)
{
    if (value == CK_UNAVAILABLE_INFORMATION)
        strncpy(buf, "[information unavailable]", buf_len - 1);
    else if (check_infinite && value == CK_EFFECTIVELY_INFINITE)
        strncpy(buf, "[effectively infinite]", buf_len - 1);
    else
        snprintf(buf, buf_len, fmt, value);
    buf[buf_len - 1] = '\0';
}

void print_token_info(int slot_id, CK_TOKEN_INFO *TokenInfo)
{
    char temp1[256];
    char temp2[256];

    /* Display the token information */
    printf("Token #%d Info:\n", slot_id);
    printf("\tLabel: %.32s\n", TokenInfo->label);
    printf("\tManufacturer: %.32s\n", TokenInfo->manufacturerID);
    printf("\tModel: %.16s\n", TokenInfo->model);
    printf("\tSerial Number: %.16s\n", TokenInfo->serialNumber);
    printf("\tFlags: 0x%lX (", TokenInfo->flags);

    /* print more informative flag message */
    if (TokenInfo->flags & CKF_RNG)
        printf("RNG|");
    if (TokenInfo->flags & CKF_WRITE_PROTECTED)
        printf("WRITE_PROTECTED|");
    if (TokenInfo->flags & CKF_LOGIN_REQUIRED)
        printf("LOGIN_REQUIRED|");
    if (TokenInfo->flags & CKF_USER_PIN_INITIALIZED)
        printf("USER_PIN_INITIALIZED|");
    if (TokenInfo->flags & CKF_RESTORE_KEY_NOT_NEEDED)
        printf("RESTORE_KEY_NOT_NEEDED|");
    if (TokenInfo->flags & CKF_CLOCK_ON_TOKEN)
        printf("CLOCK_ON_TOKEN|");
    if (TokenInfo->flags & CKF_PROTECTED_AUTHENTICATION_PATH)
        printf("PROTECTED_AUTHENTICATION_PATH|");
    if (TokenInfo->flags & CKF_DUAL_CRYPTO_OPERATIONS)
        printf("DUAL_CRYPTO_OPERATIONS|");
    if (TokenInfo->flags & CKF_TOKEN_INITIALIZED)
        printf("TOKEN_INITIALIZED|");
    if (TokenInfo->flags & CKF_SECONDARY_AUTHENTICATION)
        printf("SECONDARY_AUTHENTICATION|");
    if (TokenInfo->flags & CKF_USER_PIN_COUNT_LOW)
        printf("USER_PIN_COUNT_LOW|");
    if (TokenInfo->flags & CKF_USER_PIN_FINAL_TRY)
        printf("USER_PIN_FINAL_TRY|");
    if (TokenInfo->flags & CKF_USER_PIN_LOCKED)
        printf("USER_PIN_LOCKED|");
    if (TokenInfo->flags & CKF_USER_PIN_TO_BE_CHANGED)
        printf("USER_PIN_TO_BE_CHANGED|");
    if (TokenInfo->flags & CKF_SO_PIN_COUNT_LOW)
        printf("SO_PIN_COUNT_LOW|");
    if (TokenInfo->flags & CKF_SO_PIN_FINAL_TRY)
        printf("SO_PIN_FINAL_TRY|");
    if (TokenInfo->flags & CKF_SO_PIN_LOCKED)
        printf("SO_PIN_LOCKED|");
    if (TokenInfo->flags & CKF_SO_PIN_TO_BE_CHANGED)
        printf("SO_PIN_TO_BE_CHANGED|");
    printf(")\n");

    print_value(TokenInfo->ulSessionCount, temp1, sizeof(temp1), FALSE, "%lu");
    print_value(TokenInfo->ulMaxSessionCount, temp2, sizeof(temp2), TRUE,
                "%lu");
    printf("\tSessions: %s/%s\n", temp1, temp2);
    print_value(TokenInfo->ulRwSessionCount, temp1, sizeof(temp1), FALSE,
                "%lu");
    print_value(TokenInfo->ulMaxRwSessionCount, temp2, sizeof(temp2), TRUE,
                "%lu");
    printf("\tR/W Sessions: %s/%s\n", temp1, temp2);
    printf("\tPIN Length: %lu-%lu\n", TokenInfo->ulMinPinLen,
           TokenInfo->ulMaxPinLen);
    print_value(TokenInfo->ulFreePublicMemory, temp1, sizeof(temp1), FALSE,
                "0x%lX");
    print_value(TokenInfo->ulTotalPublicMemory, temp2, sizeof(temp2), FALSE,
                "0x%lX");
    printf("\tPublic Memory: %s/%s\n", temp1, temp2);
    print_value(TokenInfo->ulFreePrivateMemory, temp1, sizeof(temp1), FALSE,
                "0x%lX");
    print_value(TokenInfo->ulTotalPrivateMemory, temp2, sizeof(temp2), FALSE,
                "0x%lX");
    printf("\tPrivate Memory: %s/%s\n", temp1, temp2);
    printf("\tHardware Version: %d.%d\n", TokenInfo->hardwareVersion.major,
           TokenInfo->hardwareVersion.minor);
    printf("\tFirmware Version: %d.%d\n", TokenInfo->firmwareVersion.major,
           TokenInfo->firmwareVersion.minor);
    printf("\tTime: %.16s\n", TokenInfo->utcTime);
}

void print_token_info_uri(const CK_TOKEN_INFO_PTR TokenInfo)
{
    struct p11_uri *uri;

    uri = p11_uri_new();
    if (!uri)
        return;

    uri->token_info = TokenInfo;
    printf("\tURI: %s\n", p11_uri_format(uri));

    p11_uri_free(uri);
    uri = NULL;
}

CK_RV display_token_info(int slot_id)
{
    CK_RV rc;                   // Return Code
    CK_TOKEN_INFO TokenInfo;    // Variable to hold Token Information
    unsigned int lcv;           // Loop control variable

    if (slot_id != -1) {
        rc = FunctionPtr->C_GetTokenInfo(slot_id, &TokenInfo);
        if (rc != CKR_OK) {
            warnx("Error getting token info: 0x%lX (%s)", rc,
                  p11_get_ckr(rc));
            return rc;
        }

        print_token_info(slot_id, &TokenInfo);
        print_token_info_uri(&TokenInfo);
        return CKR_OK;
    }

    for (lcv = 0; lcv < SlotCount; lcv++) {
        /* Get the Token info for each slot in the system */
        rc = FunctionPtr->C_GetTokenInfo(SlotList[lcv], &TokenInfo);
        if (rc != CKR_OK) {
            if (rc == CKR_TOKEN_NOT_PRESENT)
                return CKR_OK;
            warnx("Error getting token info: 0x%lX (%s)", rc,
                  p11_get_ckr(rc));
            return rc;
        }

        print_token_info(SlotList[lcv], &TokenInfo);
        print_token_info_uri(&TokenInfo);
    }
    return CKR_OK;
}

CK_RV init_token(int slot_id, const char *pin)
{
    /* Note this function reinitializes a token to the state it was
     * in just after the initial install
     * It does the following actions (if SO pin is correct):
     *   (1) Purges all Token Objects
     *   (2) Resets SO PIN back to the default
     *   (3) Purges the USER PIN
     *   (4) Sets the Token Label
     */

    CK_RV rc;                   // Return Code
    CK_CHAR label[32],          // What we want to set the Label of the card to
             enteredlabel[33];  // Max size of 32 + carriage return;

    /* Get the token label from the user, NOTE it states to give a unique label
     * but it is never verified as unique.  This is becuase Netscape requires a
     * unique token label; however the PKCS11 spec does not.
     */
    printf("Enter a unique token label: ");
    fflush(stdout);
    memset(enteredlabel, 0, sizeof(enteredlabel));

    if (fgets((char *) enteredlabel, sizeof(enteredlabel), stdin) == NULL)
        printf("\n");
    else
        enteredlabel[strcspn((const char *) enteredlabel, "\n")] = '\0';

    /* First clear the label array. Per PKCS#11 spec, We must PAD this field to
     * 32 bytes, and it should NOT be null-terminated */
    memset(label, ' ', sizeof(label));
    memcpy((char *) label, (char *) enteredlabel,
           strlen((char *) enteredlabel));

    rc = FunctionPtr->C_InitToken(slot_id, (CK_CHAR_PTR)pin, strlen(pin), label);
    if (rc != CKR_OK) {
        if (rc == CKR_PIN_INCORRECT)
            warnx("Incorrect PIN entered.");
        else
            warnx("Error initializing token: 0x%lX (%s)", rc,
                  p11_get_ckr(rc));
        return rc;
    }

    return CKR_OK;
}

CK_RV init_user_pin(int slot_id, const char *pin, const char *sopin)
{
    CK_RV rc;                   // Return Value
    CK_FLAGS flags = 0;         // Mask that we will use when opening the session
    CK_SESSION_HANDLE session_handle;   // The session handle we get

    /* set the mask we will use for Open Session */
    flags |= CKF_SERIAL_SESSION;
    flags |= CKF_RW_SESSION;

    /* We need to open a read/write session to the adapter to initialize the
     * user PIN. Attempt to do so */
    rc = FunctionPtr->C_OpenSession(slot_id, flags, NULL, NULL,
                                    &session_handle);
    if (rc != CKR_OK) {
        warnx("Error opening session: 0x%lX (%s)", rc, p11_get_ckr(rc));
        return rc;
    }

    /* After the session is open, we must login as the SO to initialize
     * the PIN */
    rc = FunctionPtr->C_Login(session_handle, CKU_SO,
                              (CK_CHAR_PTR)sopin, strlen(sopin));
    if (rc != CKR_OK) {
        if (rc == CKR_PIN_INCORRECT)
            warnx("Incorrect PIN entered.");
        else
            warnx("Error logging in: 0x%lX (%s)", rc, p11_get_ckr(rc));
        return rc;
    }

    /* Call the function to Init the PIN */
    rc = FunctionPtr->C_InitPIN(session_handle, (CK_CHAR_PTR)pin, strlen(pin));
    if (rc != CKR_OK)
        warnx("Error setting PIN: 0x%lX (%s)", rc, p11_get_ckr(rc));

    /* Logout so that others can use the PIN */
    rc = FunctionPtr->C_Logout(session_handle);
    if (rc != CKR_OK)
        warnx("Error logging out: 0x%lX (%s)", rc, p11_get_ckr(rc));

    /* Close the session */
    rc = FunctionPtr->C_CloseSession(session_handle);
    if (rc != CKR_OK) {
        warnx("Error closing session: 0x%lX (%s)", rc, p11_get_ckr(rc));
        return rc;
    }
    return CKR_OK;
}

CK_RV set_user_pin(int slot_id, CK_USER_TYPE user, const char *oldpin,
                   const char *newpin)
{
    CK_RV rc;                   // Return Value
    CK_FLAGS flags = 0;         // Mash ot open the session with
    CK_SESSION_HANDLE session_handle;   // The handle of the session we will open

    /* NOTE: This function is used for both the setting of the SO and USER pins,
     *       the CK_USER_TYPE specifes which we are changing. */

    /* set the flags we will open the session with */
    flags |= CKF_SERIAL_SESSION;
    flags |= CKF_RW_SESSION;

    /* Open the Session */
    rc = FunctionPtr->C_OpenSession(slot_id, flags, NULL, NULL,
                                    &session_handle);
    if (rc != CKR_OK) {
        warnx("Error opening session: 0x%lX (%s)", rc, p11_get_ckr(rc));
        return rc;
    }

    /* Login to the session we just created as the pkcs11 passed in USER type */
    rc = FunctionPtr->C_Login(session_handle, user,
                              (CK_CHAR_PTR)oldpin, strlen(oldpin));
    if (rc != CKR_OK) {
        if (rc == CKR_PIN_INCORRECT)
            warnx("Incorrect PIN entered.");
        else
            warnx("Error logging in: 0x%lX (%s)", rc, p11_get_ckr(rc));
        return rc;
    }

    /* set the new PIN */
    rc = FunctionPtr->C_SetPIN(session_handle,
                               (CK_CHAR_PTR)oldpin, strlen(oldpin),
                               (CK_CHAR_PTR)newpin, strlen(newpin));
    if (rc != CKR_OK)
        warnx("Error setting PIN: 0x%lX (%s)\n", rc, p11_get_ckr(rc));

    /* and of course clean up after ourselves */
    rc = FunctionPtr->C_CloseSession(session_handle);
    if (rc != CKR_OK) {
        warnx("Error closing session: 0x%lX (%s)\n", rc, p11_get_ckr(rc));
        return rc;
    }

    return CKR_OK;
}

CK_RV init(void)
{
    CK_RV rc = CKR_OK;          // Return Code
    void (*symPtr) (CK_FUNCTION_LIST_PTR_PTR ppFunctionList); // Pointer for the Dll

    /* Open the PKCS11 API shared library, and inform the user is there is an
     * error */
    /* The host machine should have the right library in the
     * LD_LIBRARY_PATH */
    dllPtr = dlopen(OCK_API_LIBNAME, DYNLIB_LDFLAGS);
    if (!dllPtr) {
        warnx("Error loading PKCS#11 library");
        warnx("dlopen error: %s", dlerror());
        return -1;
    }

    /* Get the list of the PKCS11 functions this token support */
    *(void **)(&symPtr) = dlsym(dllPtr, "C_GetFunctionList");
    if (!symPtr) {
        warnx("Error getting function list, symbol not found, error: %s",
               dlerror());
        return -1;
    }

    symPtr(&FunctionPtr);
    if (!FunctionPtr) {
        warnx("Error getting function list, C_GetFunctionList returned NULL");
        return -1;
    }

    /* If we get here we know the slot manager is running and we can use PKCS11
     * calls, so we will execute the PKCS11 Initilize command. */
    rc = FunctionPtr->C_Initialize(NULL);
    if (rc != CKR_OK) {
        warnx("Error initializing the PKCS11 library: 0x%lX (%s)", rc,
              p11_get_ckr(rc));

        if (check_user_and_group() != CKR_OK) {
            printf("Note: all non-root users that require access to PKCS#11 "
                   "tokens using opencryptoki must be assigned to the pkcs11 "
                   "group to be able to communicate with the pkcsslotd "
                   "daemon.\n");
        }
    }

    return rc;
}

void usage(char *progname)
{
    /* If we get here the user needs help, so give it to them */
    printf("usage:\t%s [-itsmIupPh] [-c slotnumber -U userPIN -S SOPin "
           "-n newpin]\n", progname);
    printf("\t-i display PKCS11 info\n");
    printf("\t-t display token info\n");
    printf("\t-s display slot info\n");
    printf("\t-m display mechanism list\n");
    printf("\t-l display slot description\n");
    printf("\t-I initialize token \n");
    printf("\t-u initialize user PIN\n");
    printf("\t-p set the user PIN\n");
    printf("\t-P set the SO PIN\n");
    printf("\t-h show this help\n");

    exit(-1);
}
