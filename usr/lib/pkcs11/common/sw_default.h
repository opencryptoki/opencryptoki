/* (C) COPYRIGHT International Business Machines Corp. 2006                */

/***************************************************************************
                          Change Log
                          ==========
       08/31/06   Daniel H Jones (danjones@us.ibm.com)
                  Initial file created 
 
****************************************************************************/

// Prototypes

CK_RV sw_default_GetMechanismList(CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR);
CK_RV sw_default_GetMechanismInfo(CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR);
CK_RV sw_default_aes_key_gen( CK_BYTE *, CK_ULONG);
CK_RV sw_default_aes_ecb(CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *,
			 CK_BYTE *, CK_ULONG, CK_BYTE);
CK_RV sw_default_aes_cbc(CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *,
			 CK_BYTE *, CK_ULONG, CK_BYTE *, CK_BYTE);
CK_RV sw_default_des_key_gen(CK_BYTE *, CK_ULONG);
CK_RV sw_default_des_ecb(CK_BYTE *, CK_ULONG, CK_BYTE *,
			 CK_ULONG *, CK_BYTE *, CK_BYTE);
CK_RV sw_default_des_cbc(CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *,
			 CK_BYTE *, CK_BYTE *, CK_BYTE);
CK_RV sw_default_tdes_ecb(CK_BYTE *, CK_ULONG, CK_BYTE *,
			  CK_ULONG *, CK_BYTE *, CK_BYTE);
CK_RV sw_default_tdes_cbc(CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *,
			  CK_BYTE *, CK_BYTE *, CK_BYTE);
CK_RV sw_default_dh_pkcs_derive(CK_BYTE *, CK_ULONG *, CK_BYTE *, CK_ULONG,
				CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG);
CK_RV sw_default_dh_pkcs_key_pair_gen(TEMPLATE *, TEMPLATE *);
CK_RV sw_default_rsa_generate_keypair(TEMPLATE *, TEMPLATE *);
CK_RV sw_default_rsa_encrypt(CK_BYTE *, CK_ULONG, CK_BYTE *, OBJECT *);
CK_RV sw_default_rsa_decrypt(CK_BYTE *, CK_ULONG, CK_BYTE *, OBJECT *);

int sw_default_slot2local(CK_SLOT_ID);

CK_RV sw_default_rng(CK_BYTE *,  CK_ULONG);
