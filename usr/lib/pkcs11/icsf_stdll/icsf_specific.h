/*
 * Licensed materials, Property of IBM Corp.
 *
 * OpenCryptoki ICSF token - ICSF token functions
 *
 * (C) COPYRIGHT International Business Machines Corp. 2015
 *
 */

#ifndef ICSF_SPECIFIC_H
#define ICSF_SPECIFIC_H

#include "pkcs11types.h"

CK_RV icsftok_init(CK_SLOT_ID slot_id, char *conf_name);

CK_RV icsftok_final(void);

CK_RV icsftok_init_token(CK_SLOT_ID slot_id, CK_CHAR_PTR pin, CK_ULONG pin_len,
			 CK_CHAR_PTR label);

CK_RV icsftok_init_pin(SESSION *sess, CK_CHAR_PTR pPin, CK_ULONG ulPinLen);

CK_RV icsftok_set_pin(SESSION *sess, CK_CHAR_PTR pOldPin, CK_ULONG ulOldLen,
		      CK_CHAR_PTR pNewPin, CK_ULONG ulNewLen);

CK_RV icsftok_open_session(SESSION *sess);

CK_RV icsftok_close_session(SESSION *session);

CK_RV icsftok_login(SESSION *sess, CK_USER_TYPE userType, CK_CHAR_PTR pPin,
		    CK_ULONG ulPinLen);

CK_RV icsftok_create_object(SESSION *session, CK_ATTRIBUTE_PTR attrs,
			    CK_ULONG attrs_len, CK_OBJECT_HANDLE_PTR handle);

CK_RV icsftok_copy_object(SESSION * session, CK_ATTRIBUTE_PTR attrs,
			  CK_ULONG attrs_len, CK_OBJECT_HANDLE src,
			  CK_OBJECT_HANDLE_PTR dst);

CK_RV icsftok_destroy_object(SESSION *sess, CK_OBJECT_HANDLE handle);

CK_RV icsftok_get_attribute_value(SESSION *sess, CK_OBJECT_HANDLE handle,
				  CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount);

CK_RV icsftok_set_attribute_value(SESSION *sess, CK_OBJECT_HANDLE handle,
				  CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount);


CK_RV icsftok_find_objects_init(SESSION *sess, CK_ATTRIBUTE *pTemplate,
				CK_ULONG ulCount);

CK_RV icsftok_encrypt_init(SESSION *session, CK_MECHANISM_PTR mech,
			   CK_OBJECT_HANDLE key);

CK_RV icsftok_encrypt(SESSION *session, CK_BYTE_PTR input_data,
		      CK_ULONG input_data_len, CK_BYTE_PTR output_data,
		      CK_ULONG_PTR p_output_data_len);

CK_RV icsftok_encrypt_update(SESSION *session, CK_BYTE_PTR input_part,
			     CK_ULONG input_part_len, CK_BYTE_PTR output_part,
			     CK_ULONG_PTR p_output_part_len);

CK_RV icsftok_encrypt_final(SESSION *session, CK_BYTE_PTR output_part,
			    CK_ULONG_PTR p_output_part_len);

CK_RV icsftok_decrypt_init(SESSION *session, CK_MECHANISM_PTR mech,
			   CK_OBJECT_HANDLE key);

CK_RV icsftok_decrypt(SESSION *session, CK_BYTE_PTR input_data,
		      CK_ULONG input_data_len, CK_BYTE_PTR output_data,
		      CK_ULONG_PTR p_output_data_len);

CK_RV icsftok_decrypt_update(SESSION *session, CK_BYTE_PTR input_part,
			     CK_ULONG input_part_len, CK_BYTE_PTR output_part,
			     CK_ULONG_PTR p_output_part_len);

CK_RV icsftok_decrypt_final(SESSION *session, CK_BYTE_PTR output_part,
			    CK_ULONG_PTR p_output_part_len);

CK_RV icsftok_sign_init(SESSION *session, CK_MECHANISM *mech,
			CK_BBOOL recover_mode, CK_OBJECT_HANDLE key);

CK_RV icsftok_sign(SESSION *session, CK_BBOOL length_only, CK_BYTE *in_data,
		   CK_ULONG in_data_len, CK_BYTE *signature, CK_ULONG *sig_len);

CK_RV icsftok_sign_update(SESSION *session, CK_BYTE *in_data,
			  CK_ULONG in_data_len);

CK_RV icsftok_sign_final(SESSION *session, CK_BBOOL length_only,
			 CK_BYTE *signature, CK_ULONG *sig_len);

CK_RV icsftok_verify_init(SESSION *session, CK_MECHANISM *mech,
			  CK_BBOOL recover_mode, CK_OBJECT_HANDLE key);

CK_RV icsftok_verify(SESSION *session, CK_BYTE *in_data, CK_ULONG in_data_len,
		     CK_BYTE *signature, CK_ULONG sig_len);

CK_RV icsftok_verify_update(SESSION *session, CK_BYTE *in_data,
			    CK_ULONG in_data_len);

CK_RV icsftok_verify_final(SESSION *session, CK_BYTE *signature,
			   CK_ULONG sig_len);

CK_RV icsftok_wrap_key(SESSION *session, CK_MECHANISM_PTR mech,
		       CK_OBJECT_HANDLE wrapping_key, CK_OBJECT_HANDLE key,
		       CK_BYTE_PTR wrapped_key, CK_ULONG_PTR p_wrapped_key_len);

CK_RV icsftok_unwrap_key(SESSION *session, CK_MECHANISM_PTR mech,
			 CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len,
			 CK_BYTE_PTR wrapped_key, CK_ULONG wrapped_key_len,
			 CK_OBJECT_HANDLE wrapping_key,
			 CK_OBJECT_HANDLE_PTR p_key);

CK_RV icsftok_derive_key(SESSION *session, CK_MECHANISM_PTR mech,
			 CK_OBJECT_HANDLE hBaseKey, CK_OBJECT_HANDLE_PTR handle,
			 CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len);

CK_RV icsftok_generate_key_pair(SESSION *session, CK_MECHANISM_PTR mech,
				CK_ATTRIBUTE_PTR pub_attrs,
				CK_ULONG pub_attrs_len,
				CK_ATTRIBUTE_PTR priv_attrs,
				CK_ULONG priv_attrs_len,
				CK_OBJECT_HANDLE_PTR p_pub_key,
				CK_OBJECT_HANDLE_PTR p_priv_key);

CK_RV icsftok_generate_key(SESSION *session, CK_MECHANISM_PTR mech,
			   CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len,
			   CK_OBJECT_HANDLE_PTR handle);
#endif
