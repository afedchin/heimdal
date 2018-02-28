/* This is a generated file */
#ifndef __spnego_private_h__
#define __spnego_private_h__

#include <stdarg.h>

gssapi_mech_interface
__gss_spnego_initialize (void);

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_accept_sec_context (
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
	gss_cred_id_t*delegated_cred_handle );

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_acquire_cred (
	OM_uint32*,
	gss_const_name_t,
	OM_uint32,
	const gss_OID_set,
	gss_cred_usage_t,
	gss_cred_id_t*,
	gss_OID_set*,
	OM_uint32* time_rec );

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_alloc_sec_context (
	OM_uint32*,
	gss_ctx_id_t*);

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_canonicalize_name (
	 OM_uint32*,
	gss_const_name_t,
	const gss_OID,
	gss_name_t* output_name );

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_compare_name (
	OM_uint32*,
	gss_const_name_t,
	gss_const_name_t,
	int* name_equal );

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_context_time (
	OM_uint32*,
	gss_const_ctx_id_t,
	OM_uint32*time_rec );

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_delete_sec_context (
	OM_uint32*,
	gss_ctx_id_t*,
	gss_buffer_t output_token );

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_display_name (
	OM_uint32*,
	gss_const_name_t,
	gss_buffer_t,
	gss_OID* output_name_type );

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_duplicate_name (
	 OM_uint32*,
	gss_const_name_t,
	gss_name_t* dest_name );

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_export_cred (
	OM_uint32*,
	gss_cred_id_t,
	gss_buffer_t);

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_export_name (
	OM_uint32*,
	gss_const_name_t,
	gss_buffer_t exported_name );

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_export_sec_context (
	 OM_uint32*,
	gss_ctx_id_t*,
	gss_buffer_t interprocess_token );

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_get_mic (
	OM_uint32*,
	gss_const_ctx_id_t,
	gss_qop_t,
	const gss_buffer_t,
	gss_buffer_t message_token );

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_import_cred (
	OM_uint32*,
	gss_buffer_t,
	gss_cred_id_t*);

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_import_name (
	OM_uint32*,
	const gss_buffer_t,
	const gss_OID,
	gss_name_t* output_name );

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_import_sec_context (
	 OM_uint32*,
	const gss_buffer_t,
	gss_ctx_id_t*context_handle );

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_indicate_mechtypelist (
	OM_uint32*,
	gss_name_t,
	OM_uint32 (*)(gss_name_t, gss_OID),
	int,
	gss_const_cred_id_t,
	MechTypeList*,
	gss_OID*);

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_init_sec_context (
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
_gss_spnego_inquire_context (
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
_gss_spnego_inquire_cred (
	OM_uint32*,
	gss_const_cred_id_t,
	gss_name_t*,
	OM_uint32*,
	gss_cred_usage_t*,
	gss_OID_set* mechanisms );

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_inquire_cred_by_mech (
	 OM_uint32*,
	gss_const_cred_id_t,
	const gss_OID,
	gss_name_t*,
	OM_uint32*,
	OM_uint32*,
	gss_cred_usage_t* cred_usage );

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_inquire_cred_by_oid (
	OM_uint32*,
	gss_const_cred_id_t,
	const gss_OID,
	gss_buffer_set_t*);

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_inquire_mechs_for_name (
	 OM_uint32*,
	gss_const_name_t,
	gss_OID_set* mech_types );

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_inquire_names_for_mech (
	 OM_uint32*,
	const gss_OID,
	gss_OID_set* name_types );

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_inquire_sec_context_by_oid (
	OM_uint32*,
	gss_const_ctx_id_t,
	const gss_OID,
	gss_buffer_set_t*);

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_internal_delete_sec_context (
	OM_uint32*,
	gss_ctx_id_t*,
	gss_buffer_t output_token );

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_process_context_token (
	OM_uint32*,
	gss_const_ctx_id_t,
	const gss_buffer_t token_buffer );

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_pseudo_random (
	OM_uint32*,
	gss_ctx_id_t,
	int,
	const gss_buffer_t,
	ssize_t,
	gss_buffer_t);

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_release_cred (
	OM_uint32*,
	gss_cred_id_t*);

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_release_name (
	OM_uint32*,
	gss_name_t* input_name );

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_require_mechlist_mic (
	OM_uint32*,
	gssspnego_ctx,
	int*);

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_set_cred_option (
	OM_uint32*,
	gss_cred_id_t*,
	const gss_OID,
	const gss_buffer_t);

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_set_sec_context_option (
	OM_uint32*,
	gss_ctx_id_t*,
	const gss_OID,
	const gss_buffer_t);

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_unwrap (
	OM_uint32*,
	gss_const_ctx_id_t,
	const gss_buffer_t,
	gss_buffer_t,
	int*,
	gss_qop_t* qop_state );

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_unwrap_iov (
	OM_uint32*,
	gss_ctx_id_t,
	int*,
	gss_qop_t*,
	gss_iov_buffer_desc*,
	int);

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_verify_mic (
	OM_uint32*,
	gss_const_ctx_id_t,
	const gss_buffer_t,
	const gss_buffer_t,
	gss_qop_t* qop_state );

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_wrap (
	OM_uint32*,
	gss_const_ctx_id_t,
	int,
	gss_qop_t,
	const gss_buffer_t,
	int*,
	gss_buffer_t output_message_buffer );

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_wrap_iov (
	OM_uint32*,
	gss_ctx_id_t,
	int,
	gss_qop_t,
	int*,
	gss_iov_buffer_desc*,
	int);

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_wrap_iov_length (
	OM_uint32*,
	gss_ctx_id_t,
	int,
	gss_qop_t,
	int*,
	gss_iov_buffer_desc*,
	int);

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_wrap_size_limit (
	 OM_uint32*,
	gss_const_ctx_id_t,
	int,
	gss_qop_t,
	OM_uint32,
	OM_uint32* max_input_size );

#endif /* __spnego_private_h__ */
