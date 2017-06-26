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
#include <termios.h>
#include <pkcs11types.h>
#include <locale.h>
#include <limits.h>
#include <nl_types.h>
#include <memory.h>
#include <string.h>
#include <strings.h>
#include "slotmgr.h"
#include "pkcsconf_msg.h"
#include "p11util.h"

#define LEEDS_DEFAULT_PIN "87654321"
#define PIN_SIZE 80
#define BACK_SPACE 8
#define DELETE     127
#define LINE_FEED  10

#define CFG_SO_PIN         0x0001
#define CFG_USER_PIN       0x0002
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
int echo(int);
int get_pin(CK_CHAR **);
int get_slot(char *);
CK_RV cleanup(void);
CK_RV display_pkcs11_info(void);
CK_RV get_slot_list(void);
CK_RV display_slot_info(int);
CK_RV display_token_info(int);
CK_RV display_mechanism_info(int);
CK_RV init_token(int, CK_CHAR_PTR);
CK_RV init_user_pin(int, CK_CHAR_PTR, CK_CHAR_PTR);
CK_RV list_slot(int);
CK_RV set_user_pin(int, CK_USER_TYPE, CK_CHAR_PTR, CK_CHAR_PTR);

void * dllPtr;
CK_FUNCTION_LIST_PTR  FunctionPtr = NULL;
CK_SLOT_ID_PTR        SlotList = NULL;
CK_ULONG              SlotCount = 0;
Slot_Mgr_Shr_t *      shmp = NULL;
int in_slot;

int
main(int argc, char *argv[]){
   CK_RV rc = CKR_OK;          // Return Code
   CK_FLAGS flags = 0;         // Bit mask for what options were passed in
   CK_CHAR_PTR sopin = NULL,   // The Security Office PIN
               pin = NULL,     // The User PIN
               newpin = NULL,  // To store PIN changes
               newpin2 = NULL; // To store validation of PIN change

   int c,                      // To store passed in options
       newpinlen, newpin2len,
       errflag = 0;            // Error Flag

   /* Parse the command line parameters */
   while ((c = getopt (argc, argv, "itsmIc:S:U:upPn:lh")) != (-1)){
      switch (c){
         case 'c':  /* a specific card (slot) is specified */
            if (flags & CFG_SLOT) {
                printf("Must specify a single slot.\n");
                fflush(stdout);
                errflag++;
            }
            else {
                flags |= CFG_SLOT;
                in_slot = get_slot(optarg);
                if (in_slot < 0) {
                    printf("Must specify a decimal number as slot.\n");
                    errflag++;
                }
            }
            break;
         case 'S':  /* the SO pin */
            if (flags & CFG_SO_PIN) {
                printf("Must specify a single SO PIN.\n");
                fflush(stdout);
                errflag++;
            }
            else {
                flags |= CFG_SO_PIN;
                sopin = (CK_CHAR_PTR) malloc(strlen(optarg)+1);
                memcpy(sopin, optarg, strlen(optarg)+1);
            }
            break;
         case 'U':  /* the user pin */
            if (flags & CFG_USER_PIN) {
                printf("Must specify a single user PIN.\n");
                fflush(stdout);
                errflag++;
            }
            else {
                flags |= CFG_USER_PIN;
                pin = (CK_CHAR_PTR) malloc(strlen(optarg)+1);
                memcpy(pin, optarg, strlen(optarg)+1);
            }
            break;
         case 'n':  /* the new pin */
            if (flags & CFG_NEW_PIN) {
                printf("Must specify a single new PIN.\n");
                fflush(stdout);
                errflag++;
            }
            else {
                flags |= CFG_NEW_PIN;
                newpin = (CK_CHAR_PTR) malloc(strlen(optarg)+1);
                memcpy(newpin, optarg, strlen(optarg)+1);
            }
            break;
         case 'i':  /* display PKCS11 info */
            flags |= CFG_PKCS_INFO;
            break;
         case 't':  /* display token info */
            flags |= CFG_TOKEN_INFO;
            break;
         case 's':  /* display slot info */
            flags |= CFG_SLOT_INFO;
            break;
         case 'm':  /* display mechanism info */
            flags |= CFG_MECHANISM_INFO;
            break;
         case 'I':  /* initialize the token */
            flags |= CFG_INITIALIZE;
            break;
         case 'u':  /* initialize the user PIN */
            flags |= CFG_INIT_USER;
            break;
         case 'p':  /* set the user PIN */
            flags |= CFG_SET_USER;
            break;
         case 'P':  /* set the SO PIN */
            flags |= CFG_SET_SO;
            break;
         case 'l':  /* display slot description */
            flags |= CFG_LIST_SLOT;
            break;
         case 'h':  /* display command line options */
	    usage(argv[0]);
            break;
         default:   /* if something else was passed in it is an error */
            errflag++;
            break;
      }
   }
   if (errflag != 0)  /* If there was an error print the usage statement */
       usage(argv[0]);

   if (!flags)  /* If there was no options print the usage statement */
       usage(argv[0]);

   /* Eliminate the ability to specify -I -p -u -P without a slot number */
   if ( (flags & (CFG_INITIALIZE | CFG_INIT_USER | CFG_SET_USER | CFG_SET_SO))
            && !(flags & CFG_SLOT)){
      usage(argv[0]);
   }
   /* Load the PKCS11 library and start the slotmanager if it is not running */
   if ( init() != CKR_OK )
	exit(-1);

   /* Get the slot list and indicate if a slot number was passed in or not */
   if ((rc = get_slot_list()))
      goto done;

   /* If the user tries to set the user and SO pin at the same time print an
    * error massage and exit indicating the function failed */
   if ((flags & CFG_SET_USER) && (flags & CFG_SET_SO)) {
      printf("Setting the SO and user PINs are mutually exclusive.\n");
      fflush(stdout);
      return CKR_FUNCTION_FAILED;
   }

   /* If the user wants to display PKCS11 info call the function to do so */
   if (flags & CFG_PKCS_INFO)
      if ((rc = display_pkcs11_info()))
	 goto done;

   /* If the user wants to display token info call the function to do so */
   if (flags & CFG_TOKEN_INFO)
      if ((rc = display_token_info((flags & CFG_SLOT) ? in_slot : -1)))
	 goto done;

   /* If the user wants to display slot info call the function to do so */
   if (flags & CFG_SLOT_INFO)
      if ((rc = display_slot_info((flags & CFG_SLOT) ? in_slot : -1)))
	 goto done;

   /* If the user wants to display slot info call the function to do so */
   if (flags & CFG_LIST_SLOT)
      if ((rc = list_slot((flags & CFG_SLOT) ? in_slot : -1)))
	 goto done;

   /* If the user wants to display mechanism info call the function to do so */
   if (flags & CFG_MECHANISM_INFO)
      if ((rc = display_mechanism_info((flags & CFG_SLOT) ? in_slot : -1)))
	 goto done;

    /* If the user wants to initialize the card check to see if they passed in
     * the SO pin, if not ask for the PIN */
   if (flags & CFG_INITIALIZE){
       if (flags & CFG_SLOT){
            if (~flags & CFG_SO_PIN){
                int rc;
                do {
                    printf("Enter the SO PIN: ");
                    fflush(stdout);
                    rc = get_pin(&(sopin));
                } while (rc == -EINVAL);
            }
            rc = init_token(in_slot, sopin);
        }
       else {
           printf("Must specify one slot");
           fflush(stdout);
           rc = -EINVAL;
       }
   }

    /* If the user wants to initialize the User PIN, check to see if they have
     * passed in the SO PIN, if not ask for it.  Then check to see if they passed
     * the New User PIN on the command line if not ask for the PIN and verify it */
    if (flags & CFG_INIT_USER){
        if (flags & CFG_SLOT){
            if (~flags & CFG_SO_PIN) {
                int rc;
                do {
                    printf("Enter the SO PIN: ");
                    fflush(stdout);
                    rc = get_pin(&sopin);
                } while (rc == -EINVAL);
            }
            if (~flags & CFG_NEW_PIN) {
                int rc;
                do {
                    printf("Enter the new user PIN: ");
                    fflush(stdout);
                    rc = get_pin(&newpin);
                } while (rc == -EINVAL);
                newpinlen = strlen((char *)newpin);
                do {
                    printf("Re-enter the new user PIN: ");
                    fflush(stdout);
                    rc = get_pin(&newpin2);
                } while (rc == -EINVAL);
                newpin2len = strlen((char *)newpin2);
                if (newpinlen != newpin2len || memcmp(newpin, newpin2, strlen((char *)newpin)) != 0) {
                    printf("New PINs do not match.\n");
                    fflush(stdout);
                    exit(CKR_PIN_INVALID);
                }
            }
            rc = init_user_pin(in_slot, newpin, sopin);
        }
        else {
            printf("Must specify one slot");
            fflush(stdout);
            rc = -EINVAL;
        }
    }

   /* If the user wants to set the SO PIN, check to see if they have passed the
    * current SO PIN and the New PIN in.  If not prompt and validate them. */
    if (flags & CFG_SET_SO){
        if (flags & CFG_SLOT){
            if (~flags & CFG_SO_PIN) {
                int rc;

                do {
                    printf("Enter the SO PIN: ");
                    fflush(stdout);
                    rc = get_pin(&sopin);
                } while (rc == -EINVAL);
            }
            if (~flags & CFG_NEW_PIN) {
                int rc;

                do {
                    printf("Enter the new SO PIN: ");
                    fflush(stdout);
                    rc = get_pin(&newpin);
                } while (rc == -EINVAL);
                newpinlen = strlen((char *)newpin);
                do {
                    printf("Re-enter the new SO PIN: ");
                    fflush(stdout);
                    rc = get_pin(&newpin2);
                } while (rc == -EINVAL);
                newpin2len = strlen((char *)newpin2);
                if (newpinlen != newpin2len || memcmp(newpin, newpin2, strlen((char *)newpin)) != 0) {
                    printf("New PINs do not match.\n");
                    fflush(stdout);
                    exit(CKR_PIN_INVALID);
                }
            }
            rc = set_user_pin(in_slot, CKU_SO, sopin, newpin);
        }
        else {
            printf("Must specify one slot");
            fflush(stdout);
            rc = -EINVAL;
        }
    }

    /* If the user wants to set the User PIN, check to see if they have passed the
     * current User PIN and the New PIN in.  If not prompt and validate them. */
    if (flags & CFG_SET_USER){
        if (flags & CFG_SLOT){
            if (~flags & CFG_USER_PIN) {
                int rc;

                do {
                    printf("Enter user PIN: ");
                    fflush(stdout);
                    rc = get_pin(&pin);
                } while (rc == -EINVAL);
            }
            if (~flags & CFG_NEW_PIN) {
                do {
                    printf("Enter the new user PIN: ");
                    fflush(stdout);
                    rc = get_pin(&newpin);
                } while (rc == -EINVAL);
                newpinlen = strlen((char *)newpin);
                do {
                    printf("Re-enter the new user PIN: ");
                    fflush(stdout);
                    rc = get_pin(&newpin2);
                } while (rc == -EINVAL);
                newpin2len = strlen((char *)newpin2);
                if (newpinlen != newpin2len || memcmp(newpin, newpin2, strlen((char *)newpin)) != 0) {
                    printf("New PINs do not match.\n");
                    fflush(stdout);
                    exit(CKR_PIN_INVALID);
                }
            }
            rc = set_user_pin(in_slot, CKU_USER, pin, newpin);
        }
        else {
            printf("Must specify one slot");
            fflush(stdout);
            rc = -EINVAL;
        }
    }

   /* We are done, detach from shared memory, and free the memory we may have
    * allocated.  In the case of PIN's we memset them to ensure that they are not
    * left around in system memory*/

done:
   if (sopin) {
     memset(sopin, 0, strlen((char *)sopin));
     free (sopin);
   }

   if (pin) {
      memset(pin, 0, strlen((char *)pin));
      free (pin);
   }

   if (newpin) {
      memset(newpin, 0, strlen((char *)newpin));
      free (newpin);
   }

   if (newpin2) {
      memset(newpin2, 0, strlen((char *)newpin2));
      free (newpin2);
   }

   return ((rc == 0) || (rc % 256) ? rc : -1);
}

int get_pin(CK_CHAR **pin)
{
	int  count;
	char buff[PIN_SIZE] = { 0 }, c = 0;
	int rc = 0;

	*pin = NULL;
	/* Turn off echoing to the terminal when getting the password */
	echo(FALSE);
	/* Get each character and print out a '*' for each input */
	for (count = 0; (c != LINE_FEED) && (count < PIN_SIZE);) {
		buff[count] = getc(stdin);
		c = buff[count];
		if (c == BACK_SPACE || c == DELETE) {
			if (count)
				count--;
			continue;
		}
		fflush(stdout);
		count++;
	}
	echo(TRUE);
	/* After we get the password go to the next line */
	printf("\n");
	fflush(stdout);
	/* Allocate 80 bytes for the user PIN. This is large enough
	 * for the tokens supported in AIX 5.0 and 5.1 */
	*pin = (unsigned char *)malloc(PIN_SIZE);
	if (!(*pin)) {
		rc = -ENOMEM;
		goto out;
	}
	/* Strip the carage return from the user input (it is not part
	 * of the PIN) and put the PIN in the return buffer */
	buff[count - 1] =  '\0';
	/* keep the trailing null for the strlen */
	strncpy((char *)*pin, buff, (strlen((char *)buff) + 1));
out:
	return rc;
}

int get_slot(char *optarg)
{
    char *endptr;
    int val;

    errno = 0;
    val = (int) strtol(optarg, &endptr, 10);

    /* Check for various possible errors */
    if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
            || (errno != 0 && val == 0)) {
        perror("strtol");
        return -1;
    }

    /* No digits were found in optarg, so return error */
    if (endptr == optarg)
        return -1;

    return val;
}

int
echo(int bool){
   struct termios term;

   /* flush standard out to make sure everything that needs to be displayed has
    * been displayed */
   fflush(stdout);

   /* get the current terminal attributes */
   if (tcgetattr(STDIN_FILENO, &term) != 0)
      return -1;

   /* Since we are calling this function we must want to read in a char at a
    * time.  Therefore set the cc structure before setting the terminal attrs */
   term.c_cc[VMIN] = 1;
   term.c_cc[VTIME] = 0;

   /* If we are turning off the display of input characters AND with the inverse
    * of the ECHO mask, if we are turning on the display OR with the ECHO mask.
    * We also set if we are reading in canonical or noncanonical mode.  */
   if (bool)
      term.c_lflag |= (ECHO | ICANON);
   else
      term.c_lflag &= ~(ECHO | ICANON);

   /* Set the attributes, and flush the streams so that any input already
    * displayed on the terminal is invalid */
   if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &term) != 0)
      return -1;

   return 0;
}

CK_RV
display_pkcs11_info(void){

   CK_RV rc;
   CK_INFO CryptokiInfo;

   /* Get the PKCS11 infomation structure and if fails print message */
   rc = FunctionPtr->C_GetInfo(&CryptokiInfo);
   if (rc != CKR_OK) {
      printf("Error getting PKCS#11 info: 0x%lX (%s)\n", rc, p11_get_ckr(rc));
      return rc;
   }

   /* display the header and information */
   printf("PKCS#11 Info\n");
   printf("\tVersion %d.%d \n", CryptokiInfo.cryptokiVersion.major,
         CryptokiInfo.cryptokiVersion.minor);
   printf("\tManufacturer: %.32s \n", CryptokiInfo.manufacturerID);
   printf("\tFlags: 0x%lX  \n", CryptokiInfo.flags);
   printf("\tLibrary Description: %.32s \n", CryptokiInfo.libraryDescription);
   printf("\tLibrary Version %d.%d \n", CryptokiInfo.libraryVersion.major,
         CryptokiInfo.libraryVersion.minor);

   return rc;
}

CK_RV
get_slot_list(){
   CK_RV                 rc;                   // Return Code

   /* Find out how many tokens are present in slots */
   rc = FunctionPtr->C_GetSlotList(TRUE, NULL_PTR, &SlotCount);
   if (rc != CKR_OK) {
      printf("Error getting number of slots: 0x%lX (%s)\n", rc, p11_get_ckr(rc));
      return rc;
   }

   if (SlotCount == 0) {
      printf("C_GetSlotList returned 0 slots. Check that your tokens"
		" are installed correctly.\n");
      return -ENODEV;
   }

   /* Allocate enough space for the slots information */
   SlotList = (CK_SLOT_ID_PTR) malloc(SlotCount * sizeof(CK_SLOT_ID));

   rc = FunctionPtr->C_GetSlotList(TRUE, SlotList, &SlotCount);
   if (rc != CKR_OK) {
      printf("Error getting slot list: 0x%lX (%s)\n", rc, p11_get_ckr(rc));
      return rc;
   }

   return CKR_OK;
}

void
display_mechanism_name(CK_MECHANISM_TYPE mech)
{
	CK_ULONG i;

	for (i = 0; pkcs11_mech_list[i].name; i++) {
		if (pkcs11_mech_list[i].mech == mech) {
			printf("(%s)", pkcs11_mech_list[i].name);
			return;
		}
	}
}

void
display_mechanism_flags(CK_FLAGS flags)
{
	CK_ULONG i, firsties = 1;

	for (i = 0; pkcs11_mech_flags[i].name; i++) {
		if (pkcs11_mech_flags[i].flag & flags) {
			if (firsties) {
				printf("(");
				firsties = 0;
			}

			printf("%s|", pkcs11_mech_flags[i].name);
		}
	}

	if (!firsties) {
		printf(")");
	}
}

CK_RV
print_mech_info(int slot_id)
{
    CK_RV                   rc;                     // Return Code
    CK_MECHANISM_TYPE_PTR   MechanismList   = NULL; // Head to Mechanism list
    CK_MECHANISM_INFO       MechanismInfo;          // Structure to hold Mechanism Info
    CK_ULONG                MechanismCount  = 0;    // Number of supported mechanisms
    unsigned int            i;

    /* For each slot find out how many mechanisms are supported */
    rc = FunctionPtr->C_GetMechanismList(slot_id, NULL_PTR, &MechanismCount);
    if (rc != CKR_OK) {
        printf("Error getting number of mechanisms: 0x%lX (%s)\n",
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
        printf("Error getting mechanisms list: 0x%lX (%s)\n", rc, p11_get_ckr(rc));
        return rc;
    }

    /* For each Mechanism in the List */
    for (i = 0; i < MechanismCount; i++){

        /* Get the Mechanism Info and display it */
        rc = FunctionPtr->C_GetMechanismInfo(slot_id,
                MechanismList[i], &MechanismInfo);
        if (rc != CKR_OK) {
            printf("Error getting mechanisms info: 0x%lX (%s)\n", rc, p11_get_ckr(rc));
            return rc;
        }
        printf("Mechanism #%d\n", i);
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
    free (MechanismList);
    return CKR_OK;
}

CK_RV
display_mechanism_info(int slot_id){
    CK_ULONG                lcv;

    if (slot_id == -1) {
	for (lcv = 0; lcv < SlotCount; lcv++) {
	    printf("Mechanism Info for Slot #%lu:\n", SlotList[lcv]);
	    print_mech_info(SlotList[lcv]);
	}
    } else
	return print_mech_info(slot_id);

    return CKR_OK;
}

void
print_slot_info(int slot_id, CK_SLOT_INFO *SlotInfo)
{
      /* Display the slot information */
      printf("Slot #%d Info\n", slot_id);
      printf("\tDescription: %.64s\n", SlotInfo->slotDescription);
      printf("\tManufacturer: %.32s\n", SlotInfo->manufacturerID);
      printf("\tFlags: 0x%lX (", SlotInfo->flags);

      if (SlotInfo->flags & CKF_TOKEN_PRESENT)
	      printf("TOKEN_PRESENT|");
      if (SlotInfo->flags & CKF_REMOVABLE_DEVICE)
	      printf("REMOVABLE_DEVICE|");
      if (SlotInfo->flags & CKF_HW_SLOT)
	      printf("HW_SLOT|");
      printf(")\n");

      printf("\tHardware Version: %d.%d\n", SlotInfo->hardwareVersion.major,
            SlotInfo->hardwareVersion.minor);
      printf("\tFirmware Version: %d.%d\n", SlotInfo->firmwareVersion.major,
            SlotInfo->firmwareVersion.minor);
}

CK_RV
display_slot_info(int slot_id)
{
   CK_RV          rc;        // Return Code
   CK_SLOT_INFO   SlotInfo;  // Structure to hold slot information
   unsigned int   lcv;       // Loop control Variable

   if (slot_id != -1) {
      rc = FunctionPtr->C_GetSlotInfo(slot_id, &SlotInfo);
      if (rc != CKR_OK) {
         printf("Error getting slot info: 0x%lX (%s) \n", rc,
		p11_get_ckr(rc));
         return rc;
      }

      print_slot_info(slot_id, &SlotInfo);
      return CKR_OK;
   }

   for (lcv = 0; lcv < SlotCount; lcv++){
      /* Get the info for the slot we are examining and store in SlotInfo*/
      rc = FunctionPtr->C_GetSlotInfo(SlotList[lcv], &SlotInfo);
      if (rc != CKR_OK) {
         printf("Error getting slot info: 0x%lX (%s) \n", rc, p11_get_ckr(rc));
         return rc;
      }

      print_slot_info(SlotList[lcv], &SlotInfo);

   }
   return CKR_OK;
}

CK_RV
list_slot(int slot_id){
    CK_RV          rc;        // Return code
    CK_SLOT_INFO   SlotInfo;  // Structure to hold slot information
    unsigned int   lcv;       // Loop control variable

    if (slot_id != -1) {
        rc = FunctionPtr->C_GetSlotInfo(slot_id, &SlotInfo);
        if (rc != CKR_OK) {
            printf("Error getting slot info: 0x%lX (%s)\n", rc, p11_get_ckr(rc));
            return rc;
        }

        /* Display the slot description */
        printf("%d:", slot_id);
        printf("\tDescription: %.64s\n", SlotInfo.slotDescription);

        return CKR_OK;
    }


    for (lcv = 0; lcv < SlotCount; lcv++){
        /* Get the info for the slot we are examining and store in SlotInfo*/
        rc = FunctionPtr->C_GetSlotInfo(SlotList[lcv], &SlotInfo);
        if (rc != CKR_OK) {
            printf("Error getting slot info: 0x%lX (%s)\n", rc, p11_get_ckr(rc));
            return rc;
        }

        /* Display the slot description */
        printf("%ld:", SlotList[lcv]);
        printf("\tDescription: %.64s\n", SlotInfo.slotDescription);
    }
    return CKR_OK;
}

void
print_token_info(int slot_id, CK_TOKEN_INFO *TokenInfo)
{
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

      printf("\tSessions: %lu/%lu\n", TokenInfo->ulSessionCount,
            TokenInfo->ulMaxSessionCount);
      printf("\tR/W Sessions: %lu/%lu\n", TokenInfo->ulRwSessionCount,
	    TokenInfo->ulMaxRwSessionCount);
      printf("\tPIN Length: %lu-%lu\n", TokenInfo->ulMinPinLen,
	    TokenInfo->ulMaxPinLen);
      printf("\tPublic Memory: 0x%lX/0x%lX\n", TokenInfo->ulFreePublicMemory,
	    TokenInfo->ulTotalPublicMemory);
      printf("\tPrivate Memory: 0x%lX/0x%lX\n", TokenInfo->ulFreePrivateMemory,
	    TokenInfo->ulTotalPrivateMemory);
      printf("\tHardware Version: %d.%d\n", TokenInfo->hardwareVersion.major,
            TokenInfo->hardwareVersion.minor);
      printf("\tFirmware Version: %d.%d\n", TokenInfo->firmwareVersion.major,
            TokenInfo->firmwareVersion.minor);
      printf("\tTime: %.16s\n", TokenInfo->utcTime);
}

CK_RV
display_token_info(int slot_id)
{
   CK_RV          rc;         // Return Code
   CK_TOKEN_INFO  TokenInfo;  // Variable to hold Token Information
   unsigned int   lcv;        // Loop control variable

   if (slot_id != -1) {
      rc = FunctionPtr->C_GetTokenInfo(slot_id, &TokenInfo);
      if (rc != CKR_OK) {
         printf("Error getting token info: 0x%lX (%s)\n", rc, p11_get_ckr(rc));
         return rc;
      }

      print_token_info(slot_id, &TokenInfo);
      return CKR_OK;
   }

   for (lcv = 0; lcv < SlotCount; lcv++){
      /* Get the Token info for each slot in the system */
      rc = FunctionPtr->C_GetTokenInfo(SlotList[lcv], &TokenInfo);
      if (rc != CKR_OK) {
         printf("Error getting token info: 0x%lX (%s)\n", rc, p11_get_ckr(rc));
         return rc;
      }

      print_token_info(SlotList[lcv], &TokenInfo);
   }
   return CKR_OK;
}

CK_RV
init_token(int slot_id, CK_CHAR_PTR pin){
    /* Note this function reinitializes a token to the state it was
     * in just after the initial install
     * It does the following actions (if SO pin is correct):
     *   (1) Purges all Token Objects
     *   (2) Resets SO PIN back to the default
     *   (3) Purges the USER PIN
     *   (4) Sets the Token Label
     */

    CK_RV rc;                     // Return Code
    CK_ULONG    pinlen;           // Length of the PIN
    CK_CHAR     label[32],        // What we want to set the Label of the card to
                enteredlabel[33]; // Max size of 32 + carriage return;

    /* Find out the size of the entered PIN */
    pinlen = strlen((char *)pin);

    /* Get the token label from the user, NOTE it states to give a unique label
     * but it is never verified as unique.  This is becuase Netscape requires a
     * unique token label; however the PKCS11 spec does not.
     */
    printf("Enter a unique token label: ");
    fflush(stdout);
    memset(enteredlabel, 0, sizeof(enteredlabel));

    if (fgets((char *)enteredlabel, sizeof(enteredlabel), stdin) == NULL)
	printf("\n");
    else
	enteredlabel[strcspn((const char*)enteredlabel,"\n")] = '\0';

    /* First clear the label array. Per PKCS#11 spec, We must PAD this field to
     * 32 bytes, and it should NOT be null-terminated */
    memset(label, ' ', sizeof(label));
    strncpy((char *)label, (char *)enteredlabel, strlen((char *)enteredlabel));

    rc = FunctionPtr->C_InitToken(slot_id, pin, pinlen, label);
    if (rc != CKR_OK) {
        if (rc == CKR_PIN_INCORRECT) {
            printf("Incorrect PIN Entered.\n");
            fflush(stdout);
        }
        else {
            printf("Error initializing token: 0x%lX (%s)\n", rc, p11_get_ckr(rc));
            fflush(stdout);
        }
        return rc;
    }

    return CKR_OK;
}

CK_RV
init_user_pin(int slot_id, CK_CHAR_PTR pin, CK_CHAR_PTR sopin){
    CK_RV rc;                               // Return Value
    CK_FLAGS            flags = 0;          // Mask that we will use when opening the session
    CK_SESSION_HANDLE   session_handle;     // The session handle we get
    CK_ULONG            pinlen, sopinlen;   // Length of the user and SO PINs

    /* get the length of the PINs */
    pinlen = strlen((char *)pin);
    sopinlen = strlen((char *)sopin);

    /* set the mask we will use for Open Session */
    flags |= CKF_SERIAL_SESSION;
    flags |= CKF_RW_SESSION;

    /* We need to open a read/write session to the adapter to initialize the user
     * PIN.  Attempt to do so */
    rc = FunctionPtr->C_OpenSession(slot_id, flags, NULL, NULL,
            &session_handle);
    if (rc != CKR_OK){
        printf("Error opening session: 0x%lX (%s)\n", rc, p11_get_ckr(rc));
        fflush(stdout);
        return rc;
    }

    /* After the session is open, we must login as the SO to initialize the PIN */
    rc = FunctionPtr->C_Login(session_handle, CKU_SO, sopin, sopinlen);
    if (rc != CKR_OK){
        if (rc == CKR_PIN_INCORRECT) {
            printf("Incorrect PIN Entered.\n");
            fflush(stdout);
        }
        else {
            printf("Error logging in: 0x%lX (%s)\n", rc, p11_get_ckr(rc));
            fflush(stdout);
        }
        return rc;
    }

    /* Call the function to Init the PIN */
    rc = FunctionPtr->C_InitPIN(session_handle, pin, pinlen);
    if (rc != CKR_OK){
        printf("Error setting PIN: 0x%lX (%s)\n", rc, p11_get_ckr(rc));
        fflush(stdout);
    }

    /* Logout so that others can use the PIN */
    rc = FunctionPtr->C_Logout(session_handle);
    if (rc != CKR_OK){
        printf("Error logging out: 0x%lX (%s)\n", rc, p11_get_ckr(rc));
        fflush(stdout);
    }

    /* Close the session */
    rc = FunctionPtr->C_CloseSession(session_handle);
    if (rc != CKR_OK){
        printf("Error closing session: 0x%lX (%s)\n", rc, p11_get_ckr(rc));
        fflush(stdout);
        return rc;
    }
    return CKR_OK;
}

CK_RV
set_user_pin(int slot_id, CK_USER_TYPE user, CK_CHAR_PTR oldpin, CK_CHAR_PTR newpin){
    CK_RV               rc;                     // Return Value
    CK_FLAGS            flags = 0;              // Mash ot open the session with
    CK_SESSION_HANDLE   session_handle;         // The handle of the session we will open
    CK_ULONG            oldpinlen, newpinlen;   // The size of the new and ole PINS

    /* NOTE:  This function is used for both the settinf of the SO and USER pins,
     *        the CK_USER_TYPE specifes which we are changing. */

    /* Get the size of the PINs */
    oldpinlen = strlen((char *)oldpin);
    newpinlen = strlen((char *)newpin);

    /* set the flags we will open the session with */
    flags |= CKF_SERIAL_SESSION;
    flags |= CKF_RW_SESSION;

    /* Open the Session */
    rc = FunctionPtr->C_OpenSession(slot_id, flags, NULL, NULL,
            &session_handle);
    if (rc != CKR_OK){
        printf("Error opening session: 0x%lX (%s)\n", rc, p11_get_ckr(rc));
        fflush(stdout);
        return rc;
    }

    /* Login to the session we just created as the pkcs11 passed in USER type */
    rc = FunctionPtr->C_Login(session_handle, user, oldpin, oldpinlen);
    if (rc != CKR_OK){
        if (rc == CKR_PIN_INCORRECT) {
            printf("Incorrect PIN Entered.\n");
            fflush(stdout);
        }
        else {
            printf("Error logging in: 0x%lX (%s)\n", rc, p11_get_ckr(rc));
            fflush(stdout);
        }
        return rc;
    }

    /* set the new PIN */
    rc = FunctionPtr->C_SetPIN(session_handle, oldpin, oldpinlen,
            newpin, newpinlen);
    if (rc != CKR_OK){
        printf("Error setting PIN: 0x%lX (%s)\n", rc, p11_get_ckr(rc));
        fflush(stdout);
    }

    /* and of course clean up after ourselves */
    rc = FunctionPtr->C_CloseSession(session_handle);
    if (rc != CKR_OK){
        printf("Error closing session: 0x%lX (%s)\n", rc, p11_get_ckr(rc));
        fflush(stdout);
        return rc;
    }

    return CKR_OK;
}

CK_RV
init(void){
   CK_RV rc = CKR_OK;    // Return Code
   void (*symPtr)();     // Pointer for the Dll

   /* Open the PKCS11 API shared library, and inform the user is there is an
    * error */
   /* The host machine should have the right library in the
    * LD_LIBRARY_PATH */
   dllPtr = dlopen("libopencryptoki.so", RTLD_NOW);
   if (!dllPtr) {
      printf("Error loading PKCS#11 library\n");
      printf("dlopen error: %s\n", dlerror());
      fflush(stdout);
      return -1;
   }

   /* Get the list of the PKCS11 functions this token support */
   symPtr = (void (*)())dlsym(dllPtr, "C_GetFunctionList");
   if (!symPtr) {
      rc = errno;
      printf("Error getting function list: 0x%lX (%s)\n", rc, p11_get_ckr(rc));
      fflush(stdout);
      return rc;
   }

   symPtr(&FunctionPtr);

   /* If we get here we know the slot manager is running and we can use PKCS11
    * calls, so we will execute the PKCS11 Initilize command. */
   rc = FunctionPtr->C_Initialize(NULL);
   if (rc != CKR_OK) {
      printf("Error initializing the PKCS11 library: 0x%lX (%s)\n", rc, p11_get_ckr(rc));
      fflush(stdout);
      cleanup();
   }

   return rc;
}

CK_RV
cleanup(void){
   CK_RV rc;  // Return Code

   /* To clean up we will free the slot list we create, call the Finalize
    * routine for PKCS11 and close the dynamically linked library */
   free (SlotList);
   rc = FunctionPtr->C_Finalize(NULL);
   if (dllPtr)
      dlclose(dllPtr);

   exit (rc);
}

void
usage(char *progname){

   /* If we get here the user needs help, so give it to them */
   printf("usage:\t%s [-itsmIupPh] [-c slotnumber -U userPIN -S SOPin -n newpin]\n", progname);
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
