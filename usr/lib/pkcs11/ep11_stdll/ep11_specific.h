/*
 * Licensed materials, Property of IBM Corp.
 *
 * OpenCryptoki EP11 token - EP11 token functions
 *
 * (C) COPYRIGHT International Business Machines Corp. 2015
 *
 */

#ifndef EP11_SPECIFIC_H
#define EP11_SPECIFIC_H

CK_RV ep11tok_get_mechanism_list(CK_MECHANISM_TYPE_PTR pMechanismList,
				 CK_ULONG_PTR pulCount);

CK_RV ep11tok_get_mechanism_info(CK_MECHANISM_TYPE type,
				 CK_MECHANISM_INFO_PTR pInfo);

CK_RV ep11tok_init(CK_SLOT_ID SlotNumber, char *conf_name);

CK_RV ep11tok_final(void);

CK_RV ep11tok_generate_key(SESSION *session, CK_MECHANISM_PTR mech,
			   CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len,
			   CK_OBJECT_HANDLE_PTR handle);


CK_RV ep11tok_derive_key(SESSION *session, CK_MECHANISM_PTR mech,
			 CK_OBJECT_HANDLE hBaseKey, CK_OBJECT_HANDLE_PTR handle,
			 CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len);

CK_RV ep11tok_generate_key_pair(SESSION * sess, CK_MECHANISM_PTR pMechanism,
				CK_ATTRIBUTE_PTR pPublicKeyTemplate,
				CK_ULONG ulPublicKeyAttributeCount,
				CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
				CK_ULONG ulPrivateKeyAttributeCount,
				CK_OBJECT_HANDLE_PTR phPublicKey,
				CK_OBJECT_HANDLE_PTR phPrivateKey);

CK_RV ep11tok_sign_init(SESSION *session, CK_MECHANISM *mech,
			CK_BBOOL recover_mode, CK_OBJECT_HANDLE key);

CK_RV ep11tok_sign(SESSION *session, CK_BBOOL length_only, CK_BYTE *in_data,
		   CK_ULONG in_data_len, CK_BYTE *signature, CK_ULONG *sig_len);

CK_RV ep11tok_sign_update(SESSION *session, CK_BYTE *in_data,
			  CK_ULONG in_data_len);

CK_RV ep11tok_sign_final(SESSION *session, CK_BBOOL length_only,
			 CK_BYTE *signature, CK_ULONG *sig_len);

CK_RV ep11tok_verify_init(SESSION *session, CK_MECHANISM *mech,
			  CK_BBOOL recover_mode, CK_OBJECT_HANDLE key);

CK_RV ep11tok_verify(SESSION *session, CK_BYTE *in_data, CK_ULONG in_data_len,
		     CK_BYTE *signature, CK_ULONG sig_len);

CK_RV ep11tok_verify_update(SESSION *session, CK_BYTE *in_data,
			    CK_ULONG in_data_len);

CK_RV ep11tok_verify_final(SESSION *session, CK_BYTE *signature,
			   CK_ULONG sig_len);

CK_RV ep11tok_decrypt_final(SESSION *session, CK_BYTE_PTR output_part,
			    CK_ULONG_PTR p_output_part_len);

CK_RV ep11tok_decrypt(SESSION *session, CK_BYTE_PTR input_data,
		      CK_ULONG input_data_len, CK_BYTE_PTR output_data,
		      CK_ULONG_PTR p_output_data_len);

CK_RV ep11tok_decrypt_update(SESSION *session, CK_BYTE_PTR input_part,
			     CK_ULONG input_part_len, CK_BYTE_PTR output_part,
			     CK_ULONG_PTR p_output_part_len);

CK_RV ep11tok_encrypt_final(SESSION *session, CK_BYTE_PTR output_part,
			    CK_ULONG_PTR p_output_part_len);

CK_RV ep11tok_encrypt(SESSION *session, CK_BYTE_PTR input_data,
		      CK_ULONG input_data_len, CK_BYTE_PTR output_data,
		      CK_ULONG_PTR p_output_data_len);

CK_RV ep11tok_encrypt_update(SESSION *session, CK_BYTE_PTR input_part,
			     CK_ULONG input_part_len, CK_BYTE_PTR output_part,
			     CK_ULONG_PTR p_output_part_len);

CK_RV ep11tok_encrypt_init(SESSION *session, CK_MECHANISM_PTR mech,
			   CK_OBJECT_HANDLE key);

CK_RV ep11tok_decrypt_init(SESSION *session, CK_MECHANISM_PTR mech,
			   CK_OBJECT_HANDLE key);

CK_RV ep11tok_wrap_key(SESSION *session, CK_MECHANISM_PTR mech,
		       CK_OBJECT_HANDLE wrapping_key, CK_OBJECT_HANDLE key,
		       CK_BYTE_PTR wrapped_key, CK_ULONG_PTR p_wrapped_key_len);


CK_RV ep11tok_wrap_key(SESSION *session, CK_MECHANISM_PTR mech,
		       CK_OBJECT_HANDLE wrapping_key, CK_OBJECT_HANDLE key,
		       CK_BYTE_PTR wrapped_key, CK_ULONG_PTR p_wrapped_key_len);

CK_RV ep11tok_unwrap_key(SESSION *session, CK_MECHANISM_PTR mech,
			 CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len,
			 CK_BYTE_PTR wrapped_key, CK_ULONG wrapped_key_len,
			 CK_OBJECT_HANDLE wrapping_key,
			 CK_OBJECT_HANDLE_PTR p_key);

#endif
