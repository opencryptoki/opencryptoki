#ifndef _MECH_TO_STR_
#define _MECH_TO_STR_
#include "pkcs11types.h"

/*
 * List generate with:
 *
 * grep CKM_ ../../usr/include/pkcs11/pkcs11types.h |
 *   awk '/^#/ { printf("\tif (mech == %s)\n\t\treturn \"%s\";\n", $2, $2); }'
 *
 */
static inline const char *
mech_to_str(CK_ULONG mech)
{
	if (mech == CKM_RSA_PKCS_KEY_PAIR_GEN)
		return "CKM_RSA_PKCS_KEY_PAIR_GEN";
	if (mech == CKM_RSA_PKCS)
		return "CKM_RSA_PKCS";
	if (mech == CKM_RSA_9796)
		return "CKM_RSA_9796";
	if (mech == CKM_RSA_X_509)
		return "CKM_RSA_X_509";
	if (mech == CKM_MD2_RSA_PKCS)
		return "CKM_MD2_RSA_PKCS";
	if (mech == CKM_MD5_RSA_PKCS)
		return "CKM_MD5_RSA_PKCS";
	if (mech == CKM_SHA1_RSA_PKCS)
		return "CKM_SHA1_RSA_PKCS";
	if (mech == CKM_RIPEMD128_RSA_PKCS)
		return "CKM_RIPEMD128_RSA_PKCS";
	if (mech == CKM_RIPEMD160_RSA_PKCS)
		return "CKM_RIPEMD160_RSA_PKCS";
	if (mech == CKM_RSA_PKCS_OAEP)
		return "CKM_RSA_PKCS_OAEP";
	if (mech == CKM_RSA_X9_31_KEY_PAIR_GEN)
		return "CKM_RSA_X9_31_KEY_PAIR_GEN";
	if (mech == CKM_RSA_X9_31)
		return "CKM_RSA_X9_31";
	if (mech == CKM_SHA1_RSA_X9_31)
		return "CKM_SHA1_RSA_X9_31";
	if (mech == CKM_RSA_PKCS_PSS)
		return "CKM_RSA_PKCS_PSS";
	if (mech == CKM_SHA1_RSA_PKCS_PSS)
		return "CKM_SHA1_RSA_PKCS_PSS";
	if (mech == CKM_DSA_KEY_PAIR_GEN)
		return "CKM_DSA_KEY_PAIR_GEN";
	if (mech == CKM_DSA)
		return "CKM_DSA";
	if (mech == CKM_DSA_SHA1)
		return "CKM_DSA_SHA1";
	if (mech == CKM_DH_PKCS_KEY_PAIR_GEN)
		return "CKM_DH_PKCS_KEY_PAIR_GEN";
	if (mech == CKM_DH_PKCS_DERIVE)
		return "CKM_DH_PKCS_DERIVE";
	if (mech == CKM_X9_42_DH_KEY_PAIR_GEN)
		return "CKM_X9_42_DH_KEY_PAIR_GEN";
	if (mech == CKM_X9_42_DH_DERIVE)
		return "CKM_X9_42_DH_DERIVE";
	if (mech == CKM_X9_42_DH_HYBRID_DERIVE)
		return "CKM_X9_42_DH_HYBRID_DERIVE";
	if (mech == CKM_X9_42_MQV_DERIVE)
		return "CKM_X9_42_MQV_DERIVE";
	if (mech == CKM_SHA256_RSA_PKCS)
		return "CKM_SHA256_RSA_PKCS";
	if (mech == CKM_SHA384_RSA_PKCS)
		return "CKM_SHA384_RSA_PKCS";
	if (mech == CKM_SHA512_RSA_PKCS)
		return "CKM_SHA512_RSA_PKCS";
	if (mech == CKM_RC2_KEY_GEN)
		return "CKM_RC2_KEY_GEN";
	if (mech == CKM_RC2_ECB)
		return "CKM_RC2_ECB";
	if (mech == CKM_RC2_CBC)
		return "CKM_RC2_CBC";
	if (mech == CKM_RC2_MAC)
		return "CKM_RC2_MAC";
	if (mech == CKM_RC2_MAC_GENERAL)
		return "CKM_RC2_MAC_GENERAL";
	if (mech == CKM_RC2_CBC_PAD)
		return "CKM_RC2_CBC_PAD";
	if (mech == CKM_RC4_KEY_GEN)
		return "CKM_RC4_KEY_GEN";
	if (mech == CKM_RC4)
		return "CKM_RC4";
	if (mech == CKM_DES_KEY_GEN)
		return "CKM_DES_KEY_GEN";
	if (mech == CKM_DES_ECB)
		return "CKM_DES_ECB";
	if (mech == CKM_DES_CBC)
		return "CKM_DES_CBC";
	if (mech == CKM_DES_MAC)
		return "CKM_DES_MAC";
	if (mech == CKM_DES_MAC_GENERAL)
		return "CKM_DES_MAC_GENERAL";
	if (mech == CKM_DES_CBC_PAD)
		return "CKM_DES_CBC_PAD";
	if (mech == CKM_DES2_KEY_GEN)
		return "CKM_DES2_KEY_GEN";
	if (mech == CKM_DES3_KEY_GEN)
		return "CKM_DES3_KEY_GEN";
	if (mech == CKM_DES3_ECB)
		return "CKM_DES3_ECB";
	if (mech == CKM_DES3_CBC)
		return "CKM_DES3_CBC";
	if (mech == CKM_DES3_MAC)
		return "CKM_DES3_MAC";
	if (mech == CKM_DES3_MAC_GENERAL)
		return "CKM_DES3_MAC_GENERAL";
	if (mech == CKM_DES3_CBC_PAD)
		return "CKM_DES3_CBC_PAD";
	if (mech == CKM_CDMF_KEY_GEN)
		return "CKM_CDMF_KEY_GEN";
	if (mech == CKM_CDMF_ECB)
		return "CKM_CDMF_ECB";
	if (mech == CKM_CDMF_CBC)
		return "CKM_CDMF_CBC";
	if (mech == CKM_CDMF_MAC)
		return "CKM_CDMF_MAC";
	if (mech == CKM_CDMF_MAC_GENERAL)
		return "CKM_CDMF_MAC_GENERAL";
	if (mech == CKM_CDMF_CBC_PAD)
		return "CKM_CDMF_CBC_PAD";
	if (mech == CKM_MD2)
		return "CKM_MD2";
	if (mech == CKM_MD2_HMAC)
		return "CKM_MD2_HMAC";
	if (mech == CKM_MD2_HMAC_GENERAL)
		return "CKM_MD2_HMAC_GENERAL";
	if (mech == CKM_MD5)
		return "CKM_MD5";
	if (mech == CKM_MD5_HMAC)
		return "CKM_MD5_HMAC";
	if (mech == CKM_MD5_HMAC_GENERAL)
		return "CKM_MD5_HMAC_GENERAL";
	if (mech == CKM_SHA_1)
		return "CKM_SHA_1";
	if (mech == CKM_SHA_1_HMAC)
		return "CKM_SHA_1_HMAC";
	if (mech == CKM_SHA_1_HMAC_GENERAL)
		return "CKM_SHA_1_HMAC_GENERAL";
	if (mech == CKM_RIPEMD128)
		return "CKM_RIPEMD128";
	if (mech == CKM_RIPEMD128_HMAC)
		return "CKM_RIPEMD128_HMAC";
	if (mech == CKM_RIPEMD128_HMAC_GENERAL)
		return "CKM_RIPEMD128_HMAC_GENERAL";
	if (mech == CKM_RIPEMD160)
		return "CKM_RIPEMD160";
	if (mech == CKM_RIPEMD160_HMAC)
		return "CKM_RIPEMD160_HMAC";
	if (mech == CKM_RIPEMD160_HMAC_GENERAL)
		return "CKM_RIPEMD160_HMAC_GENERAL";
	if (mech == CKM_SHA256)
		return "CKM_SHA256";
	if (mech == CKM_SHA256_HMAC)
		return "CKM_SHA256_HMAC";
	if (mech == CKM_SHA256_HMAC_GENERAL)
		return "CKM_SHA256_HMAC_GENERAL";
	if (mech == CKM_SHA384)
		return "CKM_SHA384";
	if (mech == CKM_SHA384_HMAC)
		return "CKM_SHA384_HMAC";
	if (mech == CKM_SHA384_HMAC_GENERAL)
		return "CKM_SHA384_HMAC_GENERAL";
	if (mech == CKM_SHA512)
		return "CKM_SHA512";
	if (mech == CKM_SHA512_HMAC)
		return "CKM_SHA512_HMAC";
	if (mech == CKM_SHA512_HMAC_GENERAL)
		return "CKM_SHA512_HMAC_GENERAL";
	if (mech == CKM_CAST_KEY_GEN)
		return "CKM_CAST_KEY_GEN";
	if (mech == CKM_CAST_ECB)
		return "CKM_CAST_ECB";
	if (mech == CKM_CAST_CBC)
		return "CKM_CAST_CBC";
	if (mech == CKM_CAST_MAC)
		return "CKM_CAST_MAC";
	if (mech == CKM_CAST_MAC_GENERAL)
		return "CKM_CAST_MAC_GENERAL";
	if (mech == CKM_CAST_CBC_PAD)
		return "CKM_CAST_CBC_PAD";
	if (mech == CKM_CAST3_KEY_GEN)
		return "CKM_CAST3_KEY_GEN";
	if (mech == CKM_CAST3_ECB)
		return "CKM_CAST3_ECB";
	if (mech == CKM_CAST3_CBC)
		return "CKM_CAST3_CBC";
	if (mech == CKM_CAST3_MAC)
		return "CKM_CAST3_MAC";
	if (mech == CKM_CAST3_MAC_GENERAL)
		return "CKM_CAST3_MAC_GENERAL";
	if (mech == CKM_CAST3_CBC_PAD)
		return "CKM_CAST3_CBC_PAD";
	if (mech == CKM_CAST5_KEY_GEN)
		return "CKM_CAST5_KEY_GEN";
	if (mech == CKM_CAST128_KEY_GEN)
		return "CKM_CAST128_KEY_GEN";
	if (mech == CKM_CAST5_ECB)
		return "CKM_CAST5_ECB";
	if (mech == CKM_CAST128_ECB)
		return "CKM_CAST128_ECB";
	if (mech == CKM_CAST5_CBC)
		return "CKM_CAST5_CBC";
	if (mech == CKM_CAST128_CBC)
		return "CKM_CAST128_CBC";
	if (mech == CKM_CAST5_MAC)
		return "CKM_CAST5_MAC";
	if (mech == CKM_CAST128_MAC)
		return "CKM_CAST128_MAC";
	if (mech == CKM_CAST5_MAC_GENERAL)
		return "CKM_CAST5_MAC_GENERAL";
	if (mech == CKM_CAST128_MAC_GENERAL)
		return "CKM_CAST128_MAC_GENERAL";
	if (mech == CKM_CAST5_CBC_PAD)
		return "CKM_CAST5_CBC_PAD";
	if (mech == CKM_CAST128_CBC_PAD)
		return "CKM_CAST128_CBC_PAD";
	if (mech == CKM_RC5_KEY_GEN)
		return "CKM_RC5_KEY_GEN";
	if (mech == CKM_RC5_ECB)
		return "CKM_RC5_ECB";
	if (mech == CKM_RC5_CBC)
		return "CKM_RC5_CBC";
	if (mech == CKM_RC5_MAC)
		return "CKM_RC5_MAC";
	if (mech == CKM_RC5_MAC_GENERAL)
		return "CKM_RC5_MAC_GENERAL";
	if (mech == CKM_RC5_CBC_PAD)
		return "CKM_RC5_CBC_PAD";
	if (mech == CKM_IDEA_KEY_GEN)
		return "CKM_IDEA_KEY_GEN";
	if (mech == CKM_IDEA_ECB)
		return "CKM_IDEA_ECB";
	if (mech == CKM_IDEA_CBC)
		return "CKM_IDEA_CBC";
	if (mech == CKM_IDEA_MAC)
		return "CKM_IDEA_MAC";
	if (mech == CKM_IDEA_MAC_GENERAL)
		return "CKM_IDEA_MAC_GENERAL";
	if (mech == CKM_IDEA_CBC_PAD)
		return "CKM_IDEA_CBC_PAD";
	if (mech == CKM_GENERIC_SECRET_KEY_GEN)
		return "CKM_GENERIC_SECRET_KEY_GEN";
	if (mech == CKM_CONCATENATE_BASE_AND_KEY)
		return "CKM_CONCATENATE_BASE_AND_KEY";
	if (mech == CKM_CONCATENATE_BASE_AND_DATA)
		return "CKM_CONCATENATE_BASE_AND_DATA";
	if (mech == CKM_CONCATENATE_DATA_AND_BASE)
		return "CKM_CONCATENATE_DATA_AND_BASE";
	if (mech == CKM_XOR_BASE_AND_DATA)
		return "CKM_XOR_BASE_AND_DATA";
	if (mech == CKM_EXTRACT_KEY_FROM_KEY)
		return "CKM_EXTRACT_KEY_FROM_KEY";
	if (mech == CKM_SSL3_PRE_MASTER_KEY_GEN)
		return "CKM_SSL3_PRE_MASTER_KEY_GEN";
	if (mech == CKM_SSL3_MASTER_KEY_DERIVE)
		return "CKM_SSL3_MASTER_KEY_DERIVE";
	if (mech == CKM_SSL3_KEY_AND_MAC_DERIVE)
		return "CKM_SSL3_KEY_AND_MAC_DERIVE";
	if (mech == CKM_SSL3_MASTER_KEY_DERIVE_DH)
		return "CKM_SSL3_MASTER_KEY_DERIVE_DH";
	if (mech == CKM_TLS_PRE_MASTER_KEY_GEN)
		return "CKM_TLS_PRE_MASTER_KEY_GEN";
	if (mech == CKM_TLS_MASTER_KEY_DERIVE)
		return "CKM_TLS_MASTER_KEY_DERIVE";
	if (mech == CKM_TLS_KEY_AND_MAC_DERIVE)
		return "CKM_TLS_KEY_AND_MAC_DERIVE";
	if (mech == CKM_TLS_MASTER_KEY_DERIVE_DH)
		return "CKM_TLS_MASTER_KEY_DERIVE_DH";
	if (mech == CKM_SSL3_MD5_MAC)
		return "CKM_SSL3_MD5_MAC";
	if (mech == CKM_SSL3_SHA1_MAC)
		return "CKM_SSL3_SHA1_MAC";
	if (mech == CKM_MD5_KEY_DERIVATION)
		return "CKM_MD5_KEY_DERIVATION";
	if (mech == CKM_MD2_KEY_DERIVATION)
		return "CKM_MD2_KEY_DERIVATION";
	if (mech == CKM_SHA1_KEY_DERIVATION)
		return "CKM_SHA1_KEY_DERIVATION";
	if (mech == CKM_SHA256_KEY_DERIVATION)
		return "CKM_SHA256_KEY_DERIVATION";
	if (mech == CKM_PBE_MD2_DES_CBC)
		return "CKM_PBE_MD2_DES_CBC";
	if (mech == CKM_PBE_MD5_DES_CBC)
		return "CKM_PBE_MD5_DES_CBC";
	if (mech == CKM_PBE_MD5_CAST_CBC)
		return "CKM_PBE_MD5_CAST_CBC";
	if (mech == CKM_PBE_MD5_CAST3_CBC)
		return "CKM_PBE_MD5_CAST3_CBC";
	if (mech == CKM_PBE_MD5_CAST5_CBC)
		return "CKM_PBE_MD5_CAST5_CBC";
	if (mech == CKM_PBE_MD5_CAST128_CBC)
		return "CKM_PBE_MD5_CAST128_CBC";
	if (mech == CKM_PBE_SHA1_CAST5_CBC)
		return "CKM_PBE_SHA1_CAST5_CBC";
	if (mech == CKM_PBE_SHA1_CAST128_CBC)
		return "CKM_PBE_SHA1_CAST128_CBC";
	if (mech == CKM_PBE_SHA1_RC4_128)
		return "CKM_PBE_SHA1_RC4_128";
	if (mech == CKM_PBE_SHA1_RC4_40)
		return "CKM_PBE_SHA1_RC4_40";
	if (mech == CKM_PBE_SHA1_DES3_EDE_CBC)
		return "CKM_PBE_SHA1_DES3_EDE_CBC";
	if (mech == CKM_PBE_SHA1_DES2_EDE_CBC)
		return "CKM_PBE_SHA1_DES2_EDE_CBC";
	if (mech == CKM_PBE_SHA1_RC2_128_CBC)
		return "CKM_PBE_SHA1_RC2_128_CBC";
	if (mech == CKM_PBE_SHA1_RC2_40_CBC)
		return "CKM_PBE_SHA1_RC2_40_CBC";
	if (mech == CKM_PKCS5_PBKD2)
		return "CKM_PKCS5_PBKD2";
	if (mech == CKM_PBA_SHA1_WITH_SHA1_HMAC)
		return "CKM_PBA_SHA1_WITH_SHA1_HMAC";
	if (mech == CKM_KEY_WRAP_LYNKS)
		return "CKM_KEY_WRAP_LYNKS";
	if (mech == CKM_KEY_WRAP_SET_OAEP)
		return "CKM_KEY_WRAP_SET_OAEP";
	if (mech == CKM_SKIPJACK_KEY_GEN)
		return "CKM_SKIPJACK_KEY_GEN";
	if (mech == CKM_SKIPJACK_ECB64)
		return "CKM_SKIPJACK_ECB64";
	if (mech == CKM_SKIPJACK_CBC64)
		return "CKM_SKIPJACK_CBC64";
	if (mech == CKM_SKIPJACK_OFB64)
		return "CKM_SKIPJACK_OFB64";
	if (mech == CKM_SKIPJACK_CFB64)
		return "CKM_SKIPJACK_CFB64";
	if (mech == CKM_SKIPJACK_CFB32)
		return "CKM_SKIPJACK_CFB32";
	if (mech == CKM_SKIPJACK_CFB16)
		return "CKM_SKIPJACK_CFB16";
	if (mech == CKM_SKIPJACK_CFB8)
		return "CKM_SKIPJACK_CFB8";
	if (mech == CKM_SKIPJACK_WRAP)
		return "CKM_SKIPJACK_WRAP";
	if (mech == CKM_SKIPJACK_PRIVATE_WRAP)
		return "CKM_SKIPJACK_PRIVATE_WRAP";
	if (mech == CKM_SKIPJACK_RELAYX)
		return "CKM_SKIPJACK_RELAYX";
	if (mech == CKM_KEA_KEY_PAIR_GEN)
		return "CKM_KEA_KEY_PAIR_GEN";
	if (mech == CKM_KEA_KEY_DERIVE)
		return "CKM_KEA_KEY_DERIVE";
	if (mech == CKM_FORTEZZA_TIMESTAMP)
		return "CKM_FORTEZZA_TIMESTAMP";
	if (mech == CKM_BATON_KEY_GEN)
		return "CKM_BATON_KEY_GEN";
	if (mech == CKM_BATON_ECB128)
		return "CKM_BATON_ECB128";
	if (mech == CKM_BATON_ECB96)
		return "CKM_BATON_ECB96";
	if (mech == CKM_BATON_CBC128)
		return "CKM_BATON_CBC128";
	if (mech == CKM_BATON_COUNTER)
		return "CKM_BATON_COUNTER";
	if (mech == CKM_BATON_SHUFFLE)
		return "CKM_BATON_SHUFFLE";
	if (mech == CKM_BATON_WRAP)
		return "CKM_BATON_WRAP";
	if (mech == CKM_ECDSA_KEY_PAIR_GEN)
		return "CKM_ECDSA_KEY_PAIR_GEN";
	if (mech == CKM_EC_KEY_PAIR_GEN)
		return "CKM_EC_KEY_PAIR_GEN";
	if (mech == CKM_ECDSA)
		return "CKM_ECDSA";
	if (mech == CKM_ECDSA_SHA1)
		return "CKM_ECDSA_SHA1";
	if (mech == CKM_ECDH1_DERIVE)
		return "CKM_ECDH1_DERIVE";
	if (mech == CKM_ECDH1_COFACTOR_DERIVE)
		return "CKM_ECDH1_COFACTOR_DERIVE";
	if (mech == CKM_ECMQV_DERIVE)
		return "CKM_ECMQV_DERIVE";
	if (mech == CKM_JUNIPER_KEY_GEN)
		return "CKM_JUNIPER_KEY_GEN";
	if (mech == CKM_JUNIPER_ECB128)
		return "CKM_JUNIPER_ECB128";
	if (mech == CKM_JUNIPER_CBC128)
		return "CKM_JUNIPER_CBC128";
	if (mech == CKM_JUNIPER_COUNTER)
		return "CKM_JUNIPER_COUNTER";
	if (mech == CKM_JUNIPER_SHUFFLE)
		return "CKM_JUNIPER_SHUFFLE";
	if (mech == CKM_JUNIPER_WRAP)
		return "CKM_JUNIPER_WRAP";
	if (mech == CKM_FASTHASH)
		return "CKM_FASTHASH";
	if (mech == CKM_AES_KEY_GEN)
		return "CKM_AES_KEY_GEN";
	if (mech == CKM_AES_ECB)
		return "CKM_AES_ECB";
	if (mech == CKM_AES_CBC)
		return "CKM_AES_CBC";
	if (mech == CKM_AES_MAC)
		return "CKM_AES_MAC";
	if (mech == CKM_AES_MAC_GENERAL)
		return "CKM_AES_MAC_GENERAL";
	if (mech == CKM_AES_CBC_PAD)
		return "CKM_AES_CBC_PAD";
	if (mech == CKM_AES_CTR)
		return "CKM_AES_CTR";
	if (mech == CKM_DSA_PARAMETER_GEN)
		return "CKM_DSA_PARAMETER_GEN";
	if (mech == CKM_DH_PKCS_PARAMETER_GEN)
		return "CKM_DH_PKCS_PARAMETER_GEN";
	if (mech == CKM_X9_42_DH_PARAMETER_GEN)
		return "CKM_X9_42_DH_PARAMETER_GEN";
	if (mech == CKM_VENDOR_DEFINED)
		return "CKM_VENDOR_DEFINED";

	return "(unknown mech)";
}

#endif
