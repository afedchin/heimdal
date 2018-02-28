/* This is a generated file */
#ifndef __ntlm_private_h__
#define __ntlm_private_h__

#include <stdarg.h>

gssapi_mech_interface
__gss_ntlm_initialize (void);

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_accept_sec_context (
	OM_uint32*,
	gss_ctx_id_t*,
	gss_const_cred_id_t,
	const gss_buffer_t,
	const gss_channel_bindings_t,
	gss_name_t*,
	gss_OID*,
	gss_buffer_t,
	OM_uint32*,
	OM_uint32*,
	gss_cred_id_t* delegated_cred_handle );

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_acquire_cred (
	OM_uint32*,
	gss_const_name_t,
	OM_uint32,
	const gss_OID_set,
	gss_cred_usage_t,
	gss_cred_id_t*,
	gss_OID_set*,
	OM_uint32*);

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_add_cred (
	 OM_uint32*,
	gss_const_cred_id_t,
	gss_const_name_t,
	const gss_OID,
	gss_cred_usage_t,
	OM_uint32,
	OM_uint32,
	gss_cred_id_t*,
	gss_OID_set*,
	OM_uint32*,
	OM_uint32*);

OM_uint32
_gss_ntlm_allocate_ctx (
	OM_uint32*,
	ntlm_ctx*);

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_canonicalize_name (
	 OM_uint32*,
	gss_const_name_t,
	const gss_OID,
	gss_name_t* output_name );

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_compare_name (
	OM_uint32*,
	gss_const_name_t,
	gss_const_name_t,
	int* name_equal );

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_context_time (
	OM_uint32*,
	gss_const_ctx_id_t,
	OM_uint32* time_rec );

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_delete_sec_context (
	OM_uint32*,
	gss_ctx_id_t*,
	gss_buffer_t output_token );

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_destroy_cred (
	OM_uint32*,
	gss_cred_id_t*);

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_display_name (
	OM_uint32*,
	gss_const_name_t,
	gss_buffer_t,
	gss_OID* output_name_type );

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_display_status (
	OM_uint32*,
	OM_uint32,
	int,
	const gss_OID,
	OM_uint32*,
	gss_buffer_t);

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_duplicate_name (
	 OM_uint32*,
	gss_const_name_t,
	gss_name_t* dest_name );

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_export_name (
	OM_uint32*,
	gss_const_name_t,
	gss_buffer_t exported_name );

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_export_sec_context (
	 OM_uint32*,
	gss_ctx_id_t*,
	gss_buffer_t interprocess_token );

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_get_mic (
	OM_uint32*,
	gss_const_ctx_id_t,
	gss_qop_t,
	const gss_buffer_t,
	gss_buffer_t message_token );

int
_gss_ntlm_get_user_cred (
	const ntlm_name,
	ntlm_cred*);

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_import_name (
	OM_uint32*,
	const gss_buffer_t,
	const gss_OID,
	gss_name_t* output_name );

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_import_sec_context (
	 OM_uint32*,
	const gss_buffer_t,
	gss_ctx_id_t* context_handle );

OM_uint32
_gss_ntlm_indicate_mechs (
	OM_uint32*,
	gss_OID_set* mech_set );

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_init_sec_context (
	OM_uint32*,
	gss_const_cred_id_t,
	gss_ctx_id_t*,
	gss_const_name_t,
	const gss_OID,
	OM_uint32,
	OM_uint32,
	const gss_channel_bindings_t,
	const gss_buffer_t,
	gss_OID*,
	gss_buffer_t,
	OM_uint32*,
	OM_uint32* time_rec );

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_inquire_context (
	 OM_uint32*,
	gss_const_ctx_id_t,
	gss_name_t*,
	gss_name_t*,
	OM_uint32*,
	gss_OID*,
	OM_uint32*,
	int*,
	int* open_context );

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_inquire_cred (
	OM_uint32*,
	gss_const_cred_id_t,
	gss_name_t*,
	OM_uint32*,
	gss_cred_usage_t*,
	gss_OID_set* mechanisms );

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_inquire_cred_by_mech (
	 OM_uint32*,
	gss_const_cred_id_t,
	const gss_OID,
	gss_name_t*,
	OM_uint32*,
	OM_uint32*,
	gss_cred_usage_t* cred_usage );

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_inquire_mechs_for_name (
	 OM_uint32*,
	gss_const_name_t,
	gss_OID_set* mech_types );

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_inquire_names_for_mech (
	 OM_uint32*,
	const gss_OID,
	gss_OID_set* name_types );

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_inquire_sec_context_by_oid (
	OM_uint32*,
	gss_const_ctx_id_t,
	const gss_OID,
	gss_buffer_set_t*);

void GSSAPI_CALLCONV
_gss_ntlm_iter_creds_f (
	OM_uint32,
	void*userctx ,
	void (*)(void*, gss_OID, gss_cred_id_t));

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_process_context_token (
	 OM_uint32*,
	gss_const_ctx_id_t,
	const gss_buffer_t token_buffer );

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_release_cred (
	OM_uint32*,
	gss_cred_id_t* cred_handle );

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_release_name (
	OM_uint32*,
	gss_name_t* input_name );

void
_gss_ntlm_set_key (
	struct ntlmv2_key*,
	int,
	int,
	unsigned char*,
	size_t);

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_unwrap (
	OM_uint32*,
	gss_const_ctx_id_t,
	const gss_buffer_t,
	gss_buffer_t,
	int*,
	gss_qop_t* qop_state );

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_verify_mic (
	OM_uint32*,
	gss_const_ctx_id_t,
	const gss_buffer_t,
	const gss_buffer_t,
	gss_qop_t* qop_state );

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_wrap (
	OM_uint32*,
	gss_const_ctx_id_t,
	int,
	gss_qop_t,
	const gss_buffer_t,
	int*,
	gss_buffer_t output_message_buffer );

OM_uint32 GSSAPI_CALLCONV
_gss_ntlm_wrap_size_limit (
	 OM_uint32*,
	gss_const_ctx_id_t,
	int,
	gss_qop_t,
	OM_uint32,
	OM_uint32* max_input_size );

#endif /* __ntlm_private_h__ */
