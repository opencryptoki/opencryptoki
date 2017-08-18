/*
 * COPYRIGHT (c) International Business Machines Corp. 2015-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * OpenCryptoki EP11 token - EP11 token functions
 *
 */

#ifndef EP11_SPECIFIC_H
#define EP11_SPECIFIC_H

CK_RV ep11tok_get_mechanism_list(STDLL_TokData_t *tokdata,
				 CK_MECHANISM_TYPE_PTR pMechanismList,
				 CK_ULONG_PTR pulCount);

CK_RV ep11tok_get_mechanism_info(STDLL_TokData_t *tokdata,
				 CK_MECHANISM_TYPE type,
				 CK_MECHANISM_INFO_PTR pInfo);

CK_RV ep11tok_init(STDLL_TokData_t *tokdata, CK_SLOT_ID SlotNumber,
		   char *conf_name);

CK_RV ep11tok_final(STDLL_TokData_t *tokdata);

CK_RV ep11tok_generate_key(STDLL_TokData_t *tokdata, SESSION *session,
			   CK_MECHANISM_PTR mech, CK_ATTRIBUTE_PTR attrs,
			   CK_ULONG attrs_len, CK_OBJECT_HANDLE_PTR handle);

CK_RV ep11tok_derive_key(STDLL_TokData_t *tokdata, SESSION *session,
			 CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE hBaseKey,
			 CK_OBJECT_HANDLE_PTR handle, CK_ATTRIBUTE_PTR attrs,
			 CK_ULONG attrs_len);

CK_RV ep11tok_generate_key_pair(STDLL_TokData_t *tokdata, SESSION * sess,
				CK_MECHANISM_PTR pMechanism,
				CK_ATTRIBUTE_PTR pPublicKeyTemplate,
				CK_ULONG ulPublicKeyAttributeCount,
				CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
				CK_ULONG ulPrivateKeyAttributeCount,
				CK_OBJECT_HANDLE_PTR phPublicKey,
				CK_OBJECT_HANDLE_PTR phPrivateKey);

CK_RV ep11tok_sign_init(STDLL_TokData_t *tokdata, SESSION *session,
			CK_MECHANISM *mech, CK_BBOOL recover_mode,
			CK_OBJECT_HANDLE key);

CK_RV ep11tok_sign(STDLL_TokData_t *tokdata, SESSION *session,
		   CK_BBOOL length_only, CK_BYTE *in_data,
		   CK_ULONG in_data_len, CK_BYTE *signature,
		   CK_ULONG *sig_len);

CK_RV ep11tok_sign_update(STDLL_TokData_t *tokdata, SESSION *session,
			  CK_BYTE *in_data, CK_ULONG in_data_len);

CK_RV ep11tok_sign_final(STDLL_TokData_t *tokdata, SESSION *session,
			 CK_BBOOL length_only, CK_BYTE *signature,
			 CK_ULONG *sig_len);

CK_RV ep11tok_verify_init(STDLL_TokData_t *tokdata, SESSION *session,
			  CK_MECHANISM *mech, CK_BBOOL recover_mode,
			  CK_OBJECT_HANDLE key);

CK_RV ep11tok_verify(STDLL_TokData_t *tokdata, SESSION *session,
		     CK_BYTE *in_data, CK_ULONG in_data_len,
		     CK_BYTE *signature, CK_ULONG sig_len);

CK_RV ep11tok_verify_update(STDLL_TokData_t *tokdata, SESSION *session,
			    CK_BYTE *in_data, CK_ULONG in_data_len);

CK_RV ep11tok_verify_final(STDLL_TokData_t *tokdata, SESSION *session,
			   CK_BYTE *signature, CK_ULONG sig_len);

CK_RV ep11tok_decrypt_final(STDLL_TokData_t *tokdata, SESSION *session,
			    CK_BYTE_PTR output_part,
			    CK_ULONG_PTR p_output_part_len);

CK_RV ep11tok_decrypt(STDLL_TokData_t *tokdata, SESSION *session,
		      CK_BYTE_PTR input_data, CK_ULONG input_data_len,
		      CK_BYTE_PTR output_data,
		      CK_ULONG_PTR p_output_data_len);

CK_RV ep11tok_decrypt_update(STDLL_TokData_t *tokdata, SESSION *session,
			     CK_BYTE_PTR input_part, CK_ULONG input_part_len,
			     CK_BYTE_PTR output_part,
			     CK_ULONG_PTR p_output_part_len);

CK_RV ep11tok_encrypt_final(STDLL_TokData_t *tokdata, SESSION *session,
			    CK_BYTE_PTR output_part,
			    CK_ULONG_PTR p_output_part_len);

CK_RV ep11tok_encrypt(STDLL_TokData_t *tokdata, SESSION *session,
		      CK_BYTE_PTR input_data, CK_ULONG input_data_len,
		      CK_BYTE_PTR output_data, CK_ULONG_PTR p_output_data_len);

CK_RV ep11tok_encrypt_update(STDLL_TokData_t *tokdata, SESSION *session,
			     CK_BYTE_PTR input_part,
			     CK_ULONG input_part_len, CK_BYTE_PTR output_part,
			     CK_ULONG_PTR p_output_part_len);

CK_RV ep11tok_encrypt_init(STDLL_TokData_t *tokdata, SESSION *session,
			   CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key);

CK_RV ep11tok_decrypt_init(STDLL_TokData_t *tokdata, SESSION *session,
			   CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key);

CK_RV ep11tok_wrap_key(STDLL_TokData_t *tokdata, SESSION *session,
		       CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE wrapping_key,
		       CK_OBJECT_HANDLE key, CK_BYTE_PTR wrapped_key,
		       CK_ULONG_PTR p_wrapped_key_len);

CK_RV ep11tok_unwrap_key(STDLL_TokData_t *tokdata, SESSION *session,
			 CK_MECHANISM_PTR mech, CK_ATTRIBUTE_PTR attrs,
			 CK_ULONG attrs_len, CK_BYTE_PTR wrapped_key,
			 CK_ULONG wrapped_key_len,
			 CK_OBJECT_HANDLE wrapping_key,
			 CK_OBJECT_HANDLE_PTR p_key);

#endif
