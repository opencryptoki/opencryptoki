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
 * OpenCryptoki ICSF token - ICSF token functions
 *
 */

#ifndef ICSF_SPECIFIC_H
#define ICSF_SPECIFIC_H

#include "pkcs11types.h"

CK_RV icsftok_init(STDLL_TokData_t *tokdata, CK_SLOT_ID slot_id, char *conf_name);

CK_RV icsftok_close_all_sessions(void);

CK_RV icsftok_init_token(STDLL_TokData_t *tokdata, CK_SLOT_ID slot_id,
			 CK_CHAR_PTR pin, CK_ULONG pin_len, CK_CHAR_PTR label);

CK_RV icsftok_init_pin(STDLL_TokData_t *tokdata, SESSION *sess,
		       CK_CHAR_PTR pPin, CK_ULONG ulPinLen);

CK_RV icsftok_set_pin(STDLL_TokData_t *tokdata, SESSION *sess,
		      CK_CHAR_PTR pOldPin, CK_ULONG ulOldLen,
		      CK_CHAR_PTR pNewPin, CK_ULONG ulNewLen);

CK_RV icsftok_open_session(STDLL_TokData_t *tokdata, SESSION *sess);

CK_RV icsftok_close_session(STDLL_TokData_t *tokdata, SESSION *session);

CK_RV icsftok_login(STDLL_TokData_t *tokdata, SESSION *sess,
		    CK_USER_TYPE userType, CK_CHAR_PTR pPin,
		    CK_ULONG ulPinLen);

CK_RV icsftok_create_object(STDLL_TokData_t *tokdata, SESSION *session,
			    CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len,
			    CK_OBJECT_HANDLE_PTR handle);

CK_RV icsftok_copy_object(SESSION * session, CK_ATTRIBUTE_PTR attrs,
			  CK_ULONG attrs_len, CK_OBJECT_HANDLE src,
			  CK_OBJECT_HANDLE_PTR dst);

CK_RV icsftok_destroy_object(STDLL_TokData_t *tokdata, SESSION *sess,
			     CK_OBJECT_HANDLE handle);

CK_RV icsftok_get_attribute_value(SESSION *sess, CK_OBJECT_HANDLE handle,
				CK_ATTRIBUTE *pTemplate,
				CK_ULONG ulCount, CK_ULONG *obj_size);

CK_RV icsftok_set_attribute_value(SESSION *sess, CK_OBJECT_HANDLE handle,
				  CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount);


CK_RV icsftok_find_objects_init(STDLL_TokData_t *tokdata, SESSION *sess,
				CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount);

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
			CK_OBJECT_HANDLE key);

CK_RV icsftok_sign(SESSION *session, CK_BYTE *in_data, CK_ULONG in_data_len,
		   CK_BYTE *signature, CK_ULONG *sig_len);

CK_RV icsftok_sign_update(SESSION *session, CK_BYTE *in_data,
			  CK_ULONG in_data_len);

CK_RV icsftok_sign_final(SESSION *session, CK_BYTE *signature,
			 CK_ULONG *sig_len);

CK_RV icsftok_verify_init(SESSION *session, CK_MECHANISM *mech,
			  CK_OBJECT_HANDLE key);

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

CK_RV icsftok_derive_key(STDLL_TokData_t *tokdata, SESSION *session,
			 CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE hBaseKey,
			 CK_OBJECT_HANDLE_PTR handle, CK_ATTRIBUTE_PTR attrs,
			 CK_ULONG attrs_len);

CK_RV icsftok_generate_key_pair(STDLL_TokData_t *tokdata, SESSION *session,
				CK_MECHANISM_PTR mech,
				CK_ATTRIBUTE_PTR pub_attrs,
				CK_ULONG pub_attrs_len,
				CK_ATTRIBUTE_PTR priv_attrs,
				CK_ULONG priv_attrs_len,
				CK_OBJECT_HANDLE_PTR p_pub_key,
				CK_OBJECT_HANDLE_PTR p_priv_key);

CK_RV icsftok_generate_key(STDLL_TokData_t *tokdata, SESSION *session,
			   CK_MECHANISM_PTR mech,
			   CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len,
			   CK_OBJECT_HANDLE_PTR handle);

CK_RV icsf_get_handles(STDLL_TokData_t *tokdata, CK_SLOT_ID slot_id);

#endif
