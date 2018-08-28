/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/types.h>

#include "log.h"
#include "slotmgr.h"
#include "err.h"


static ConstInfo SysErrorInfo[] = {

    CONSTINFO(EPERM),
    CONSTINFO(ENOENT),
    CONSTINFO(ESRCH),
    CONSTINFO(EINTR),
    CONSTINFO(EIO),
    CONSTINFO(ENXIO),
    CONSTINFO(E2BIG),
    CONSTINFO(ENOEXEC),
    CONSTINFO(EBADF),
    CONSTINFO(ECHILD),
    CONSTINFO(EAGAIN),
    CONSTINFO(ENOMEM),
    CONSTINFO(EACCES),
    CONSTINFO(EFAULT),
    CONSTINFO(ENOTBLK),
    CONSTINFO(EBUSY),
    CONSTINFO(EEXIST),
    CONSTINFO(EXDEV),
    CONSTINFO(ENODEV),
    CONSTINFO(ENOTDIR),
    CONSTINFO(EISDIR),
    CONSTINFO(EINVAL),
    CONSTINFO(ENFILE),
    CONSTINFO(EMFILE),
    CONSTINFO(ENOTTY),
    CONSTINFO(ETXTBSY),
    CONSTINFO(EFBIG),
    CONSTINFO(ENOSPC),
    CONSTINFO(ESPIPE),
    CONSTINFO(EROFS),
    CONSTINFO(EMLINK),
    CONSTINFO(EPIPE),
    CONSTINFO(EDOM),
    CONSTINFO(ERANGE),
    CONSTINFO(ENOMSG),
    CONSTINFO(EIDRM),
#ifdef ECHRNG
    CONSTINFO(ECHRNG),
#endif
#ifdef EL2NSYNC
    CONSTINFO(EL2NSYNC),
#endif
#ifdef EL3HLT
    CONSTINFO(EL3HLT),
#endif
#ifdef EL3RST
    CONSTINFO(EL3RST),
#endif
#ifdef ELNRNG
    CONSTINFO(ELNRNG),
#endif
#ifdef EUNATCH
    CONSTINFO(EUNATCH),
#endif
#ifdef ENOCSI
    CONSTINFO(ENOCSI),
#endif
#ifdef EL2HLT
    CONSTINFO(EL2HLT),
#endif
    CONSTINFO(EDEADLK),
    CONSTINFO(ESTALE),
    CONSTINFO(EWOULDBLOCK),
    CONSTINFO(EINPROGRESS),
    CONSTINFO(EALREADY),
    CONSTINFO(ENOTSOCK),
    CONSTINFO(EDESTADDRREQ),
    CONSTINFO(EMSGSIZE),
    CONSTINFO(EPROTOTYPE),
    CONSTINFO(ENOPROTOOPT),
    CONSTINFO(EPROTONOSUPPORT),
    CONSTINFO(ESOCKTNOSUPPORT),
    CONSTINFO(EOPNOTSUPP),
    CONSTINFO(EPFNOSUPPORT),
    CONSTINFO(EAFNOSUPPORT),
    CONSTINFO(EADDRINUSE),
    CONSTINFO(EADDRNOTAVAIL),
    CONSTINFO(ENETDOWN),
    CONSTINFO(ENETUNREACH),
    CONSTINFO(ENETRESET),
    CONSTINFO(ECONNABORTED),
    CONSTINFO(ECONNRESET),
    CONSTINFO(ENOBUFS),
    CONSTINFO(EISCONN),
    CONSTINFO(ENOTCONN),
    CONSTINFO(ESHUTDOWN),
    CONSTINFO(ETIMEDOUT),
    CONSTINFO(ECONNREFUSED),
    CONSTINFO(EHOSTDOWN),
    CONSTINFO(EHOSTUNREACH),
#ifdef ERESTART
    CONSTINFO(ERESTART),
#endif
    CONSTINFO(EUSERS),
    CONSTINFO(ELOOP),
    CONSTINFO(ENAMETOOLONG),
    CONSTINFO(ENOTEMPTY),
    CONSTINFO(EDQUOT),
    CONSTINFO(EREMOTE),
    CONSTINFO(ENOSYS),
    CONSTINFO(ETOOMANYREFS),
    CONSTINFO(EILSEQ),
    CONSTINFO(ECANCELED),
#ifdef ENOSR
    CONSTINFO(ENOSR),
#endif
#ifdef ETIME
    CONSTINFO(ETIME),
#endif
#ifdef EBADMSG
    CONSTINFO(EBADMSG),
#endif
#ifdef EPROTO
    CONSTINFO(EPROTO),
#endif
#ifdef ENODATA
    CONSTINFO(ENODATA),
#endif
#ifdef ENOSTR
    CONSTINFO(ENOSTR),
#endif
    CONSTINFO(ENOTSUP),
#ifdef EMULTIHOP
    CONSTINFO(EMULTIHOP),
#endif
#ifdef ENOLINK
    CONSTINFO(ENOLINK),
#endif
#ifdef EOVERFLOW
    CONSTINFO(EOVERFLOW),
#endif

};

static int SysErrorSize = (sizeof(SysErrorInfo) / sizeof(SysErrorInfo[0]));



static ConstInfo SignalInfo[] = {

    CONSTINFO(SIGHUP),
    CONSTINFO(SIGINT),
    CONSTINFO(SIGQUIT),
    CONSTINFO(SIGILL),
    CONSTINFO(SIGTRAP),
    CONSTINFO(SIGABRT),
    CONSTINFO(SIGFPE),
    CONSTINFO(SIGKILL),
    CONSTINFO(SIGBUS),
    CONSTINFO(SIGSEGV),
    CONSTINFO(SIGSYS),
    CONSTINFO(SIGPIPE),
    CONSTINFO(SIGALRM),
    CONSTINFO(SIGTERM),
    CONSTINFO(SIGURG),
    CONSTINFO(SIGSTOP),
    CONSTINFO(SIGTSTP),
    CONSTINFO(SIGCONT),
    CONSTINFO(SIGCHLD),
    CONSTINFO(SIGTTIN),
    CONSTINFO(SIGTTOU),
    CONSTINFO(SIGIO),
    CONSTINFO(SIGXCPU),
    CONSTINFO(SIGXFSZ),
    CONSTINFO(SIGWINCH),
#ifdef SIGPWR
    CONSTINFO(SIGPWR),
#endif
    CONSTINFO(SIGUSR1),
    CONSTINFO(SIGUSR2),
    CONSTINFO(SIGPROF),
    CONSTINFO(SIGVTALRM),
    CONSTINFO(SIGIOT),
#ifdef SIGCLD
    CONSTINFO(SIGCLD),
#endif
#ifdef SIGPOLL
    CONSTINFO(SIGPOLL),
#endif
#if 0
    CONSTINFO(SIG_DFL),
    CONSTINFO(SIG_IGN),
    CONSTINFO(SIG_HOLD),
    CONSTINFO(SIG_CATCH),
    CONSTINFO(SIG_ERR),
#endif                          /* 0 */

};

static int SignalInfoSize = (sizeof(SignalInfo) / sizeof(SignalInfo[0]));

static ConstInfo PkcsReturnInfo[] = {

    CONSTINFO(CKR_OK),
    CONSTINFO(CKR_CANCEL),
    CONSTINFO(CKR_HOST_MEMORY),
    CONSTINFO(CKR_SLOT_ID_INVALID),
    CONSTINFO(CKR_GENERAL_ERROR),
    CONSTINFO(CKR_FUNCTION_FAILED),
    CONSTINFO(CKR_ARGUMENTS_BAD),
    CONSTINFO(CKR_NO_EVENT),
    CONSTINFO(CKR_NEED_TO_CREATE_THREADS),
    CONSTINFO(CKR_CANT_LOCK),
    CONSTINFO(CKR_ATTRIBUTE_READ_ONLY),
    CONSTINFO(CKR_ATTRIBUTE_SENSITIVE),
    CONSTINFO(CKR_ATTRIBUTE_TYPE_INVALID),
    CONSTINFO(CKR_ATTRIBUTE_VALUE_INVALID),
    CONSTINFO(CKR_DATA_INVALID),
    CONSTINFO(CKR_DATA_LEN_RANGE),
    CONSTINFO(CKR_DEVICE_ERROR),
    CONSTINFO(CKR_DEVICE_MEMORY),
    CONSTINFO(CKR_DEVICE_REMOVED),
    CONSTINFO(CKR_ENCRYPTED_DATA_INVALID),
    CONSTINFO(CKR_ENCRYPTED_DATA_LEN_RANGE),
    CONSTINFO(CKR_FUNCTION_CANCELED),
    CONSTINFO(CKR_FUNCTION_NOT_PARALLEL),
    CONSTINFO(CKR_FUNCTION_NOT_SUPPORTED),
    CONSTINFO(CKR_KEY_HANDLE_INVALID),
    CONSTINFO(CKR_KEY_SIZE_RANGE),
    CONSTINFO(CKR_KEY_TYPE_INCONSISTENT),
    CONSTINFO(CKR_KEY_NOT_NEEDED),
    CONSTINFO(CKR_KEY_CHANGED),
    CONSTINFO(CKR_KEY_NEEDED),
    CONSTINFO(CKR_KEY_INDIGESTIBLE),
    CONSTINFO(CKR_KEY_FUNCTION_NOT_PERMITTED),
    CONSTINFO(CKR_KEY_NOT_WRAPPABLE),
    CONSTINFO(CKR_KEY_UNEXTRACTABLE),
    CONSTINFO(CKR_MECHANISM_INVALID),
    CONSTINFO(CKR_MECHANISM_PARAM_INVALID),
    CONSTINFO(CKR_OBJECT_HANDLE_INVALID),
    CONSTINFO(CKR_OPERATION_ACTIVE),
    CONSTINFO(CKR_OPERATION_NOT_INITIALIZED),
    CONSTINFO(CKR_PIN_INCORRECT),
    CONSTINFO(CKR_PIN_INVALID),
    CONSTINFO(CKR_PIN_LEN_RANGE),
    CONSTINFO(CKR_PIN_EXPIRED),
    CONSTINFO(CKR_PIN_LOCKED),
    CONSTINFO(CKR_SESSION_CLOSED),
    CONSTINFO(CKR_SESSION_COUNT),
    CONSTINFO(CKR_SESSION_HANDLE_INVALID),
    CONSTINFO(CKR_SESSION_PARALLEL_NOT_SUPPORTED),
    CONSTINFO(CKR_SESSION_READ_ONLY),
    CONSTINFO(CKR_SESSION_EXISTS),
    CONSTINFO(CKR_SESSION_READ_ONLY_EXISTS),
    CONSTINFO(CKR_SESSION_READ_WRITE_SO_EXISTS),
    CONSTINFO(CKR_SIGNATURE_INVALID),
    CONSTINFO(CKR_SIGNATURE_LEN_RANGE),
    CONSTINFO(CKR_TEMPLATE_INCOMPLETE),
    CONSTINFO(CKR_TEMPLATE_INCONSISTENT),
    CONSTINFO(CKR_TOKEN_NOT_PRESENT),
    CONSTINFO(CKR_TOKEN_NOT_RECOGNIZED),
    CONSTINFO(CKR_TOKEN_WRITE_PROTECTED),
    CONSTINFO(CKR_UNWRAPPING_KEY_HANDLE_INVALID),
    CONSTINFO(CKR_UNWRAPPING_KEY_SIZE_RANGE),
    CONSTINFO(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT),
    CONSTINFO(CKR_USER_ALREADY_LOGGED_IN),
    CONSTINFO(CKR_USER_NOT_LOGGED_IN),
    CONSTINFO(CKR_USER_PIN_NOT_INITIALIZED),
    CONSTINFO(CKR_USER_TYPE_INVALID),
    CONSTINFO(CKR_USER_ANOTHER_ALREADY_LOGGED_IN),
    CONSTINFO(CKR_USER_TOO_MANY_TYPES),
    CONSTINFO(CKR_WRAPPED_KEY_INVALID),
    CONSTINFO(CKR_WRAPPED_KEY_LEN_RANGE),
    CONSTINFO(CKR_WRAPPING_KEY_HANDLE_INVALID),
    CONSTINFO(CKR_WRAPPING_KEY_SIZE_RANGE),
    CONSTINFO(CKR_WRAPPING_KEY_TYPE_INCONSISTENT),
    CONSTINFO(CKR_RANDOM_SEED_NOT_SUPPORTED),
    CONSTINFO(CKR_RANDOM_NO_RNG),
    CONSTINFO(CKR_BUFFER_TOO_SMALL),
    CONSTINFO(CKR_SAVED_STATE_INVALID),
    CONSTINFO(CKR_INFORMATION_SENSITIVE),
    CONSTINFO(CKR_STATE_UNSAVEABLE),
    CONSTINFO(CKR_CRYPTOKI_NOT_INITIALIZED),
    CONSTINFO(CKR_CRYPTOKI_ALREADY_INITIALIZED),
    CONSTINFO(CKR_MUTEX_BAD),
    CONSTINFO(CKR_MUTEX_NOT_LOCKED),
    CONSTINFO(CKR_VENDOR_DEFINED),

};


static int PkcsReturnSize =
    (sizeof(PkcsReturnInfo) / sizeof(PkcsReturnInfo[0]));




static ConstInfo PkcsFlagsInfo[] = {

    CONSTINFO((CKF_RNG | CKF_HW | CKF_LIBRARY_CANT_CREATE_OS_THREADS |
               CKF_TOKEN_PRESENT)),
    CONSTINFO((CKF_REMOVABLE_DEVICE | CKF_OS_LOCKING_OK | CKF_RW_SESSION |
               CKF_WRITE_PROTECTED)),
    CONSTINFO((CKF_SERIAL_SESSION | CKF_HW_SLOT | CKF_LOGIN_REQUIRED)),
    CONSTINFO(CKF_USER_PIN_INITIALIZED),
    CONSTINFO(CKF_RESTORE_KEY_NOT_NEEDED),
    CONSTINFO(CKF_CLOCK_ON_TOKEN),
    CONSTINFO((CKF_PROTECTED_AUTHENTICATION_PATH | CKF_ENCRYPT)),
    CONSTINFO((CKF_DUAL_CRYPTO_OPERATIONS | CKF_DECRYPT)),
    CONSTINFO(CKF_DIGEST),
    CONSTINFO(CKF_SIGN),
    CONSTINFO(CKF_SIGN_RECOVER),
    CONSTINFO(CKF_VERIFY),
    CONSTINFO(CKF_VERIFY_RECOVER),
    CONSTINFO(CKF_GENERATE),
    CONSTINFO((CKF_GENERATE_KEY_PAIR | CKF_USER_PIN_COUNT_LOW)),
    CONSTINFO((CKF_USER_PIN_FINAL_TRY | CKF_WRAP)),
    CONSTINFO((CKF_UNWRAP | CKF_USER_PIN_LOCKED)),
    CONSTINFO((CKF_DERIVE /*| CKF_USER_PIN_MANUFACT_VALUE */ )),
    CONSTINFO(CKF_SO_PIN_DERIVED),
    CONSTINFO(CKF_SO_CARD),
    CONSTINFO(CKF_SO_PIN_COUNT_LOW),
    CONSTINFO(CKF_SO_PIN_FINAL_TRY),
    CONSTINFO(CKF_SO_PIN_LOCKED),
    /*CONSTINFO(CKF_SO_PIN_MANUFACT_VALUE), */
    CONSTINFO(CKF_EXTENSION),

};

static int PkcsFlagsSize = (sizeof(PkcsFlagsInfo) / sizeof(PkcsFlagsInfo[0]));



static ConstInfo PkcsMechanismInfo[] = {

    CONSTINFO(CKM_RSA_PKCS_KEY_PAIR_GEN),
    CONSTINFO(CKM_RSA_PKCS),
    CONSTINFO(CKM_RSA_9796),
    CONSTINFO(CKM_RSA_X_509),
    CONSTINFO(CKM_MD2_RSA_PKCS),
    CONSTINFO(CKM_MD5_RSA_PKCS),
    CONSTINFO(CKM_SHA1_RSA_PKCS),
    CONSTINFO(CKM_DSA_KEY_PAIR_GEN),
    CONSTINFO(CKM_DSA),
    CONSTINFO(CKM_DSA_SHA1),
    CONSTINFO(CKM_DH_PKCS_KEY_PAIR_GEN),
    CONSTINFO(CKM_DH_PKCS_DERIVE),
    CONSTINFO(CKM_RC2_KEY_GEN),
    CONSTINFO(CKM_RC2_ECB),
    CONSTINFO(CKM_RC2_CBC),
    CONSTINFO(CKM_RC2_MAC),
    CONSTINFO(CKM_RC2_MAC_GENERAL),
    CONSTINFO(CKM_RC2_CBC_PAD),
    CONSTINFO(CKM_RC4_KEY_GEN),
    CONSTINFO(CKM_RC4),
    CONSTINFO(CKM_DES_KEY_GEN),
    CONSTINFO(CKM_DES_ECB),
    CONSTINFO(CKM_DES_CBC),
    CONSTINFO(CKM_DES_MAC),
    CONSTINFO(CKM_DES_MAC_GENERAL),
    CONSTINFO(CKM_DES_CBC_PAD),
    CONSTINFO(CKM_DES2_KEY_GEN),
    CONSTINFO(CKM_DES3_KEY_GEN),
    CONSTINFO(CKM_DES3_ECB),
    CONSTINFO(CKM_DES3_CBC),
    CONSTINFO(CKM_DES3_MAC),
    CONSTINFO(CKM_DES3_MAC_GENERAL),
    CONSTINFO(CKM_DES3_CBC_PAD),
    CONSTINFO(CKM_CDMF_KEY_GEN),
    CONSTINFO(CKM_CDMF_ECB),
    CONSTINFO(CKM_CDMF_CBC),
    CONSTINFO(CKM_CDMF_MAC),
    CONSTINFO(CKM_CDMF_MAC_GENERAL),
    CONSTINFO(CKM_CDMF_CBC_PAD),
    CONSTINFO(CKM_MD2),
    CONSTINFO(CKM_MD2_HMAC),
    CONSTINFO(CKM_MD2_HMAC_GENERAL),
    CONSTINFO(CKM_MD5),
    CONSTINFO(CKM_MD5_HMAC),
    CONSTINFO(CKM_MD5_HMAC_GENERAL),
    CONSTINFO(CKM_SHA_1),
    CONSTINFO(CKM_SHA_1_HMAC),
    CONSTINFO(CKM_SHA_1_HMAC_GENERAL),
    CONSTINFO(CKM_SHA224),
    CONSTINFO(CKM_SHA224_HMAC),
    CONSTINFO(CKM_SHA224_HMAC_GENERAL),
    CONSTINFO(CKM_SHA256),
    CONSTINFO(CKM_SHA256_HMAC),
    CONSTINFO(CKM_SHA256_HMAC_GENERAL),
    CONSTINFO(CKM_SHA384),
    CONSTINFO(CKM_SHA384_HMAC),
    CONSTINFO(CKM_SHA384_HMAC_GENERAL),
    CONSTINFO(CKM_SHA512),
    CONSTINFO(CKM_SHA512_HMAC),
    CONSTINFO(CKM_SHA512_HMAC_GENERAL),
    CONSTINFO(CKM_SHA512_224),
    CONSTINFO(CKM_SHA512_224_HMAC),
    CONSTINFO(CKM_SHA512_224_HMAC_GENERAL),
    CONSTINFO(CKM_SHA512_256),
    CONSTINFO(CKM_SHA512_256_HMAC),
    CONSTINFO(CKM_SHA512_256_HMAC_GENERAL),
    CONSTINFO(CKM_CAST_KEY_GEN),
    CONSTINFO(CKM_CAST_ECB),
    CONSTINFO(CKM_CAST_CBC),
    CONSTINFO(CKM_CAST_MAC),
    CONSTINFO(CKM_CAST_MAC_GENERAL),
    CONSTINFO(CKM_CAST_CBC_PAD),
    CONSTINFO(CKM_CAST3_KEY_GEN),
    CONSTINFO(CKM_CAST3_ECB),
    CONSTINFO(CKM_CAST3_CBC),
    CONSTINFO(CKM_CAST3_MAC),
    CONSTINFO(CKM_CAST3_MAC_GENERAL),
    CONSTINFO(CKM_CAST3_CBC_PAD),
    CONSTINFO(CKM_CAST5_KEY_GEN),
    CONSTINFO(CKM_CAST128_KEY_GEN),
    CONSTINFO(CKM_CAST5_ECB),
    CONSTINFO(CKM_CAST128_ECB),
    CONSTINFO(CKM_CAST5_CBC),
    CONSTINFO(CKM_CAST128_CBC),
    CONSTINFO(CKM_CAST5_MAC),
    CONSTINFO(CKM_CAST128_MAC),
    CONSTINFO(CKM_CAST5_MAC_GENERAL),
    CONSTINFO(CKM_CAST128_MAC_GENERAL),
    CONSTINFO(CKM_CAST5_CBC_PAD),
    CONSTINFO(CKM_CAST128_CBC_PAD),
    CONSTINFO(CKM_RC5_KEY_GEN),
    CONSTINFO(CKM_RC5_ECB),
    CONSTINFO(CKM_RC5_CBC),
    CONSTINFO(CKM_RC5_MAC),
    CONSTINFO(CKM_RC5_MAC_GENERAL),
    CONSTINFO(CKM_RC5_CBC_PAD),
    CONSTINFO(CKM_IDEA_KEY_GEN),
    CONSTINFO(CKM_IDEA_ECB),
    CONSTINFO(CKM_IDEA_CBC),
    CONSTINFO(CKM_IDEA_MAC),
    CONSTINFO(CKM_IDEA_MAC_GENERAL),
    CONSTINFO(CKM_IDEA_CBC_PAD),
    CONSTINFO(CKM_GENERIC_SECRET_KEY_GEN),
    CONSTINFO(CKM_CONCATENATE_BASE_AND_KEY),
    CONSTINFO(CKM_CONCATENATE_BASE_AND_DATA),
    CONSTINFO(CKM_CONCATENATE_DATA_AND_BASE),
    CONSTINFO(CKM_XOR_BASE_AND_DATA),
    CONSTINFO(CKM_EXTRACT_KEY_FROM_KEY),
    CONSTINFO(CKM_SSL3_PRE_MASTER_KEY_GEN),
    CONSTINFO(CKM_SSL3_MASTER_KEY_DERIVE),
    CONSTINFO(CKM_SSL3_KEY_AND_MAC_DERIVE),
    CONSTINFO(CKM_SSL3_MD5_MAC),
    CONSTINFO(CKM_SSL3_SHA1_MAC),
    CONSTINFO(CKM_MD5_KEY_DERIVATION),
    CONSTINFO(CKM_MD2_KEY_DERIVATION),
    CONSTINFO(CKM_SHA1_KEY_DERIVATION),
    CONSTINFO(CKM_PBE_MD2_DES_CBC),
    CONSTINFO(CKM_PBE_MD5_DES_CBC),
    CONSTINFO(CKM_PBE_MD5_CAST_CBC),
    CONSTINFO(CKM_PBE_MD5_CAST3_CBC),
    CONSTINFO(CKM_PBE_MD5_CAST5_CBC),
    CONSTINFO(CKM_PBE_MD5_CAST128_CBC),
    CONSTINFO(CKM_PBE_SHA1_CAST5_CBC),
    CONSTINFO(CKM_PBE_SHA1_CAST128_CBC),
    CONSTINFO(CKM_PBE_SHA1_RC4_128),
    CONSTINFO(CKM_PBE_SHA1_RC4_40),
    CONSTINFO(CKM_PBE_SHA1_DES3_EDE_CBC),
    CONSTINFO(CKM_PBE_SHA1_DES2_EDE_CBC),
    CONSTINFO(CKM_PBE_SHA1_RC2_128_CBC),
    CONSTINFO(CKM_PBE_SHA1_RC2_40_CBC),
    CONSTINFO(CKM_PBA_SHA1_WITH_SHA1_HMAC),
    CONSTINFO(CKM_KEY_WRAP_LYNKS),
    CONSTINFO(CKM_KEY_WRAP_SET_OAEP),
    CONSTINFO(CKM_SKIPJACK_KEY_GEN),
    CONSTINFO(CKM_SKIPJACK_ECB64),
    CONSTINFO(CKM_SKIPJACK_CBC64),
    CONSTINFO(CKM_SKIPJACK_OFB64),
    CONSTINFO(CKM_SKIPJACK_CFB64),
    CONSTINFO(CKM_SKIPJACK_CFB32),
    CONSTINFO(CKM_SKIPJACK_CFB16),
    CONSTINFO(CKM_SKIPJACK_CFB8),
    CONSTINFO(CKM_SKIPJACK_WRAP),
    CONSTINFO(CKM_SKIPJACK_PRIVATE_WRAP),
    CONSTINFO(CKM_SKIPJACK_RELAYX),
    CONSTINFO(CKM_KEA_KEY_PAIR_GEN),
    CONSTINFO(CKM_KEA_KEY_DERIVE),
    CONSTINFO(CKM_FORTEZZA_TIMESTAMP),
    CONSTINFO(CKM_BATON_KEY_GEN),
    CONSTINFO(CKM_BATON_ECB128),
    CONSTINFO(CKM_BATON_ECB96),
    CONSTINFO(CKM_BATON_CBC128),
    CONSTINFO(CKM_BATON_COUNTER),
    CONSTINFO(CKM_BATON_SHUFFLE),
    CONSTINFO(CKM_BATON_WRAP),
    CONSTINFO(CKM_ECDSA_KEY_PAIR_GEN),
    CONSTINFO(CKM_ECDSA),
    CONSTINFO(CKM_ECDSA_SHA1),
    CONSTINFO(CKM_ECDSA_SHA224),
    CONSTINFO(CKM_ECDSA_SHA256),
    CONSTINFO(CKM_ECDSA_SHA384),
    CONSTINFO(CKM_ECDSA_SHA512),
    CONSTINFO(CKM_SHA224_RSA_PKCS),
    CONSTINFO(CKM_SHA256_RSA_PKCS),
    CONSTINFO(CKM_SHA384_RSA_PKCS),
    CONSTINFO(CKM_SHA512_RSA_PKCS),
    CONSTINFO(CKM_SHA224_RSA_PKCS_PSS),
    CONSTINFO(CKM_SHA256_RSA_PKCS_PSS),
    CONSTINFO(CKM_SHA384_RSA_PKCS_PSS),
    CONSTINFO(CKM_SHA512_RSA_PKCS_PSS),
    CONSTINFO(CKM_SHA224_KEY_DERIVATION),
    CONSTINFO(CKM_SHA256_KEY_DERIVATION),
    CONSTINFO(CKM_SHA384_KEY_DERIVATION),
    CONSTINFO(CKM_SHA512_KEY_DERIVATION),
    CONSTINFO(CKM_JUNIPER_KEY_GEN),
    CONSTINFO(CKM_JUNIPER_ECB128),
    CONSTINFO(CKM_JUNIPER_CBC128),
    CONSTINFO(CKM_JUNIPER_COUNTER),
    CONSTINFO(CKM_JUNIPER_SHUFFLE),
    CONSTINFO(CKM_JUNIPER_WRAP),
    CONSTINFO(CKM_FASTHASH),
    CONSTINFO(CKM_VENDOR_DEFINED),

};


static unsigned int PkcsMechanismSize =
    (sizeof(PkcsMechanismInfo) / sizeof(PkcsMechanismInfo[0]));



static ConstInfo PkcsObjectInfo[] = {

    CONSTINFO(CKO_DATA),
    CONSTINFO(CKO_CERTIFICATE),
    CONSTINFO(CKO_PUBLIC_KEY),
    CONSTINFO(CKO_PRIVATE_KEY),
    CONSTINFO(CKO_SECRET_KEY),
    CONSTINFO(CKO_VENDOR_DEFINED),

};

static unsigned int PkcsObjectSize =
    (sizeof(PkcsObjectInfo) / sizeof(PkcsObjectInfo[0]));





static ConstInfo PkcsKeyInfo[] = {

    CONSTINFO(CKK_RSA),
    CONSTINFO(CKK_DSA),
    CONSTINFO(CKK_DH),
    CONSTINFO(CKK_ECDSA),
    CONSTINFO(CKK_KEA),
    CONSTINFO(CKK_GENERIC_SECRET),
    CONSTINFO(CKK_RC2),
    CONSTINFO(CKK_RC4),
    CONSTINFO(CKK_DES),
    CONSTINFO(CKK_DES2),
    CONSTINFO(CKK_DES3),
    CONSTINFO(CKK_CAST),
    CONSTINFO(CKK_CAST3),
    CONSTINFO((CKK_CAST5 | CKK_CAST128)),
    CONSTINFO(CKK_RC5),
    CONSTINFO(CKK_IDEA),
    CONSTINFO(CKK_SKIPJACK),
    CONSTINFO(CKK_BATON),
    CONSTINFO(CKK_JUNIPER),
    CONSTINFO(CKK_CDMF),
    CONSTINFO(CKK_VENDOR_DEFINED),

};

static unsigned int PkcsKeySize =
    (sizeof(PkcsKeyInfo) / sizeof(PkcsKeyInfo[0]));





static ConstInfo PkcsAttributeInfo[] = {
    CONSTINFO(CKA_CLASS),
    CONSTINFO(CKA_TOKEN),
    CONSTINFO(CKA_PRIVATE),
    CONSTINFO(CKA_LABEL),
    CONSTINFO(CKA_APPLICATION),
    CONSTINFO(CKA_VALUE),
    CONSTINFO(CKA_CERTIFICATE_TYPE),
    CONSTINFO(CKA_ISSUER),
    CONSTINFO(CKA_SERIAL_NUMBER),
    CONSTINFO(CKA_KEY_TYPE),
    CONSTINFO(CKA_SUBJECT),
    CONSTINFO(CKA_ID),
    CONSTINFO(CKA_SENSITIVE),
    CONSTINFO(CKA_ENCRYPT),
    CONSTINFO(CKA_DECRYPT),
    CONSTINFO(CKA_WRAP),
    CONSTINFO(CKA_UNWRAP),
    CONSTINFO(CKA_SIGN),
    CONSTINFO(CKA_SIGN_RECOVER),
    CONSTINFO(CKA_VERIFY),
    CONSTINFO(CKA_VERIFY_RECOVER),
    CONSTINFO(CKA_DERIVE),
    CONSTINFO(CKA_START_DATE),
    CONSTINFO(CKA_END_DATE),
    CONSTINFO(CKA_MODULUS),
    CONSTINFO(CKA_MODULUS_BITS),
    CONSTINFO(CKA_PUBLIC_EXPONENT),
    CONSTINFO(CKA_PRIVATE_EXPONENT),
    CONSTINFO(CKA_PRIME_1),
    CONSTINFO(CKA_PRIME_2),
    CONSTINFO(CKA_EXPONENT_1),
    CONSTINFO(CKA_EXPONENT_2),
    CONSTINFO(CKA_COEFFICIENT),
    CONSTINFO(CKA_PRIME),
    CONSTINFO(CKA_SUBPRIME),
    CONSTINFO(CKA_BASE),
    CONSTINFO(CKA_VALUE_BITS),
    CONSTINFO(CKA_VALUE_LEN),
    CONSTINFO(CKA_EXTRACTABLE),
    CONSTINFO(CKA_LOCAL),
    CONSTINFO(CKA_NEVER_EXTRACTABLE),
    CONSTINFO(CKA_ALWAYS_SENSITIVE),
    CONSTINFO(CKA_MODIFIABLE),
    CONSTINFO(CKA_ECDSA_PARAMS),
    CONSTINFO(CKA_EC_POINT),
    CONSTINFO(CKA_VENDOR_DEFINED),
    CONSTINFO(CKA_IBM_OPAQUE),
    CONSTINFO(CKA_IBM_RESTRICTABLE),
    CONSTINFO(CKA_IBM_NEVER_MODIFIABLE),
    CONSTINFO(CKA_IBM_RETAINKEY),
    CONSTINFO(CKA_IBM_ATTRBOUND),
    CONSTINFO(CKA_IBM_KEYTYPE),
    CONSTINFO(CKA_IBM_CV),
    CONSTINFO(CKA_IBM_MACKEY),
    CONSTINFO(CKA_IBM_USE_AS_DATA),
    CONSTINFO(CKA_IBM_STRUCT_PARAMS),
    CONSTINFO(CKA_IBM_STD_COMPLIANCE1),
    CONSTINFO(CKA_NSS_MOZILLA_CA_POLICY),
};


static unsigned int PkcsAttributeSize =
    (sizeof(PkcsAttributeInfo) / sizeof(PkcsAttributeInfo[0]));

#if 0
static ConstInfo PkcsSessionStateInfo[] = {

    CONSTINFO(CKS_RO_PUBLIC_SESSION),
    CONSTINFO(CKS_RO_USER_FUNCTIONS),
    CONSTINFO(CKS_RW_PUBLIC_SESSION),
    CONSTINFO(CKS_RW_USER_FUNCTIONS),
    CONSTINFO(CKS_RW_SO_FUNCTIONS),


};
#endif


static ConstInfo PkcsResponseSeverityInfo[] = {
    {SEV_EXPECTED, "expected"},
    {SEV_ALLOWED, "allowed"},
    {SEV_ERROR, "an error"},
    {SEV_FATAL, "fatal"},
};

static unsigned int PkcsResponseSeveritySize =
    (sizeof(PkcsResponseSeverityInfo) / sizeof(PkcsResponseSeverityInfo[0]));


const unsigned char *ConstName(pConstInfo pInfoArray,
                               unsigned int InfoArraySize,
                               unsigned int ConstValue)
{

    unsigned int i;
    unsigned const char *retval = NULL;


    for (i = 0; i < InfoArraySize; i++) {
        if (pInfoArray[i].Code == ConstValue) {
            retval = &(pInfoArray[i].Name[0]);
            break;
        }
        /* end if */
    }                           /* end for i */

    if (retval == NULL) {
        if (ConstValue == 0) {
            retval = (const unsigned char *) "NULL";
        } else {
            retval = (const unsigned char *) "\"<*>CONSTANT NOT FOUND<*>\"";
        }
    }

    return retval;
}

const unsigned char *SignalConst(unsigned int Val)
{
    return ConstName(SignalInfo, SignalInfoSize, Val);
}

const unsigned char *SysConst(unsigned int Val)
{
    return ConstName(SysErrorInfo, SysErrorSize, Val);
}



const unsigned char *PkcsReturn(unsigned int Val)
{
    return ConstName(PkcsReturnInfo, PkcsReturnSize, Val);
}

const unsigned char *PkcsFlags(unsigned int Val)
{
    return ConstName(PkcsFlagsInfo, PkcsFlagsSize, Val);
}

const unsigned char *PkcsMechanism(unsigned int Val)
{
    return ConstName(PkcsMechanismInfo, PkcsMechanismSize, Val);
}

const unsigned char *PkcsObject(unsigned int Val)
{
    return ConstName(PkcsObjectInfo, PkcsObjectSize, Val);
}

const unsigned char *PkcsKey(unsigned int Val)
{
    return ConstName(PkcsKeyInfo, PkcsKeySize, Val);
}

const unsigned char *PkcsAttribute(unsigned int Val)
{
    return ConstName(PkcsAttributeInfo, PkcsAttributeSize, Val);
}

const unsigned char *ResponseSeverity(unsigned int Val)
{
    return ConstName(PkcsResponseSeverityInfo, PkcsResponseSeveritySize, Val);
}
