/* This is a generated file */
#ifndef __gsskrb5_private_h__
#define __gsskrb5_private_h__

#include <stdarg.h>

gssapi_mech_interface
__gss_krb5_initialize (void);

OM_uint32
__gsskrb5_ccache_lifetime (
	OM_uint32*,
	krb5_context,
	krb5_ccache,
	krb5_principal,
	OM_uint32*);

OM_uint32
_gk_allocate_buffer (
	OM_uint32*,
	gss_iov_buffer_desc*,
	size_t);

gss_iov_buffer_desc*
_gk_find_buffer (
	gss_iov_buffer_desc*,
	int,
	OM_uint32);

OM_uint32 GSSAPI_CALLCONV
_gk_unwrap_iov (
	OM_uint32*,
	gss_ctx_id_t,
	int*,
	gss_qop_t*,
	gss_iov_buffer_desc*,
	int);

OM_uint32
_gk_verify_buffers (
	OM_uint32*,
	const gsskrb5_ctx,
	const gss_iov_buffer_desc*,
	const gss_iov_buffer_desc*,
	const gss_iov_buffer_desc*);

OM_uint32 GSSAPI_CALLCONV
_gk_wrap_iov (
	OM_uint32*,
	gss_ctx_id_t,
	int,
	gss_qop_t,
	int*,
	gss_iov_buffer_desc*,
	int);

OM_uint32 GSSAPI_CALLCONV
_gk_wrap_iov_length (
	OM_uint32*,
	gss_ctx_id_t,
	int,
	gss_qop_t,
	int*,
	gss_iov_buffer_desc*,
	int);

OM_uint32
_gss_DES3_get_mic_compat (
	OM_uint32*,
	gsskrb5_ctx,
	krb5_context);

OM_uint32
_gssapi_decapsulate (
	 OM_uint32*,
	gss_buffer_t,
	krb5_data*,
	const gss_OID mech );

void
_gssapi_encap_length (
	size_t,
	size_t*,
	size_t*,
	const gss_OID);

OM_uint32
_gssapi_encapsulate (
	 OM_uint32*,
	const krb5_data*,
	gss_buffer_t,
	const gss_OID mech );

OM_uint32
_gssapi_get_mic_arcfour (
	OM_uint32*,
	const gsskrb5_ctx,
	krb5_context,
	gss_qop_t,
	const gss_buffer_t,
	gss_buffer_t,
	krb5_keyblock*);

void*
_gssapi_make_mech_header (
	void*,
	size_t,
	const gss_OID);

OM_uint32
_gssapi_mic_cfx (
	OM_uint32*,
	const gsskrb5_ctx,
	krb5_context,
	gss_qop_t,
	const gss_buffer_t,
	gss_buffer_t);

OM_uint32
_gssapi_msg_order_check (
	struct gss_msg_order*,
	OM_uint32);

OM_uint32
_gssapi_msg_order_create (
	OM_uint32*,
	struct gss_msg_order**,
	OM_uint32,
	OM_uint32,
	OM_uint32,
	int);

OM_uint32
_gssapi_msg_order_destroy (struct gss_msg_order**);

krb5_error_code
_gssapi_msg_order_export (
	krb5_storage*,
	struct gss_msg_order*);

OM_uint32
_gssapi_msg_order_f (OM_uint32);

OM_uint32
_gssapi_msg_order_import (
	OM_uint32*,
	krb5_storage*,
	struct gss_msg_order**);

OM_uint32
_gssapi_unwrap_arcfour (
	OM_uint32*,
	const gsskrb5_ctx,
	krb5_context,
	const gss_buffer_t,
	gss_buffer_t,
	int*,
	gss_qop_t*,
	krb5_keyblock*);

OM_uint32
_gssapi_unwrap_cfx (
	OM_uint32*,
	const gsskrb5_ctx,
	krb5_context,
	const gss_buffer_t,
	gss_buffer_t,
	int*,
	gss_qop_t*);

OM_uint32
_gssapi_unwrap_cfx_iov (
	OM_uint32*,
	gsskrb5_ctx,
	krb5_context,
	int*,
	gss_qop_t*,
	gss_iov_buffer_desc*,
	int);

OM_uint32
_gssapi_unwrap_iov_arcfour (
	OM_uint32*,
	gsskrb5_ctx,
	krb5_context,
	int*,
	gss_qop_t*,
	gss_iov_buffer_desc*,
	int,
	krb5_keyblock*);

OM_uint32
_gssapi_verify_mech_header (
	u_char**,
	size_t,
	gss_OID);

OM_uint32
_gssapi_verify_mic_arcfour (
	OM_uint32*,
	const gsskrb5_ctx,
	krb5_context,
	const gss_buffer_t,
	const gss_buffer_t,
	gss_qop_t*,
	krb5_keyblock*,
	const char*);

OM_uint32
_gssapi_verify_mic_cfx (
	OM_uint32*,
	const gsskrb5_ctx,
	krb5_context,
	const gss_buffer_t,
	const gss_buffer_t,
	gss_qop_t*);

OM_uint32
_gssapi_verify_pad (
	gss_buffer_t,
	size_t,
	size_t*);

OM_uint32
_gssapi_wrap_arcfour (
	OM_uint32*,
	const gsskrb5_ctx,
	krb5_context,
	int,
	gss_qop_t,
	const gss_buffer_t,
	int*,
	gss_buffer_t,
	krb5_keyblock*);

OM_uint32
_gssapi_wrap_cfx (
	OM_uint32*,
	const gsskrb5_ctx,
	krb5_context,
	int,
	const gss_buffer_t,
	int*,
	gss_buffer_t);

OM_uint32
_gssapi_wrap_cfx_iov (
	OM_uint32*,
	gsskrb5_ctx,
	krb5_context,
	int,
	int*,
	gss_iov_buffer_desc*,
	int);

OM_uint32
_gssapi_wrap_iov_arcfour (
	OM_uint32*,
	gsskrb5_ctx,
	krb5_context,
	int,
	int*,
	gss_iov_buffer_desc*,
	int,
	krb5_keyblock*);

OM_uint32
_gssapi_wrap_iov_length_arcfour (
	OM_uint32*,
	gsskrb5_ctx,
	krb5_context,
	int,
	gss_qop_t,
	int*,
	gss_iov_buffer_desc*,
	int);

OM_uint32
_gssapi_wrap_iov_length_cfx (
	OM_uint32*,
	gsskrb5_ctx,
	krb5_context,
	int,
	gss_qop_t,
	int*,
	gss_iov_buffer_desc*,
	int);

OM_uint32
_gssapi_wrap_size_arcfour (
	OM_uint32*,
	const gsskrb5_ctx,
	krb5_context,
	int,
	gss_qop_t,
	OM_uint32,
	OM_uint32*,
	krb5_keyblock*);

OM_uint32
_gssapi_wrap_size_cfx (
	OM_uint32*,
	const gsskrb5_ctx,
	krb5_context,
	int,
	gss_qop_t,
	OM_uint32,
	OM_uint32*);

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_accept_sec_context (
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
	gss_cred_id_t*);

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_acquire_cred (
	OM_uint32*,
	gss_const_name_t,
	OM_uint32,
	const gss_OID_set,
	gss_cred_usage_t,
	gss_cred_id_t*,
	gss_OID_set*,
	OM_uint32* time_rec );

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_acquire_cred_ext (
	OM_uint32*,
	gss_const_name_t,
	gss_const_OID,
	const void*,
	OM_uint32,
	gss_const_OID,
	gss_cred_usage_t,
	gss_cred_id_t* output_cred_handle );

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_add_cred (
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

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_authorize_localname (
	OM_uint32*,
	gss_const_name_t,
	gss_const_buffer_t,
	gss_const_OID);

OM_uint32
_gsskrb5_canon_name (
	OM_uint32*,
	krb5_context,
	gss_const_name_t,
	krb5_principal*);

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_canonicalize_name (
	 OM_uint32*,
	gss_const_name_t,
	const gss_OID,
	gss_name_t* output_name );

void
_gsskrb5_clear_status (void);

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_compare_name (
	OM_uint32*,
	gss_const_name_t,
	gss_const_name_t,
	int* name_equal );

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_context_time (
	OM_uint32*,
	gss_const_ctx_id_t,
	OM_uint32* time_rec );

OM_uint32
_gsskrb5_create_8003_checksum (
	 OM_uint32*,
	const gss_channel_bindings_t,
	OM_uint32,
	const krb5_data*,
	Checksum*);

OM_uint32
_gsskrb5_create_ctx (
	 OM_uint32*,
	gss_ctx_id_t*,
	krb5_context,
	const gss_channel_bindings_t,
	enum gss_ctx_id_t_state);

OM_uint32
_gsskrb5_decapsulate (
	OM_uint32*,
	gss_buffer_t,
	krb5_data*,
	const void*,
	gss_OID);

krb5_error_code
_gsskrb5_decode_be_om_uint32 (
	const void*,
	OM_uint32*);

krb5_error_code
_gsskrb5_decode_om_uint32 (
	const void*,
	OM_uint32*);

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_delete_sec_context (
	OM_uint32*,
	gss_ctx_id_t*,
	gss_buffer_t);

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_display_name (
	OM_uint32*,
	gss_const_name_t,
	gss_buffer_t,
	gss_OID* output_name_type );

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_display_status (
	OM_uint32*,
	OM_uint32,
	int,
	const gss_OID,
	OM_uint32*,
	gss_buffer_t);

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_duplicate_name (
	 OM_uint32*,
	gss_const_name_t,
	gss_name_t* dest_name );

void
_gsskrb5_encap_length (
	size_t,
	size_t*,
	size_t*,
	const gss_OID);

OM_uint32
_gsskrb5_encapsulate (
	 OM_uint32*,
	const krb5_data*,
	gss_buffer_t,
	const void*,
	const gss_OID mech );

krb5_error_code
_gsskrb5_encode_be_om_uint32 (
	OM_uint32,
	u_char*);

krb5_error_code
_gsskrb5_encode_om_uint32 (
	OM_uint32,
	u_char*);

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_export_cred (
	OM_uint32*,
	gss_cred_id_t,
	gss_buffer_t);

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_export_name (
	OM_uint32*,
	gss_const_name_t,
	gss_buffer_t exported_name );

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_export_sec_context (
	 OM_uint32*,
	gss_ctx_id_t*,
	gss_buffer_t interprocess_token );

ssize_t
_gsskrb5_get_mech (
	const u_char*,
	size_t,
	const u_char**);

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_get_mic (
	OM_uint32*,
	gss_const_ctx_id_t,
	gss_qop_t,
	const gss_buffer_t,
	gss_buffer_t message_token );

OM_uint32
_gsskrb5_get_tkt_flags (
	OM_uint32*,
	gsskrb5_ctx,
	OM_uint32*);

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_import_cred (
	OM_uint32*,
	gss_buffer_t,
	gss_cred_id_t*);

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_import_name (
	OM_uint32*,
	const gss_buffer_t,
	const gss_OID,
	gss_name_t* output_name );

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_import_sec_context (
	 OM_uint32*,
	const gss_buffer_t,
	gss_ctx_id_t* context_handle );

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_indicate_mechs (
	OM_uint32*,
	gss_OID_set* mech_set );

krb5_error_code
_gsskrb5_init (krb5_context*);

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_init_sec_context (
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
_gsskrb5_inquire_context (
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
_gsskrb5_inquire_cred (
	OM_uint32*,
	gss_const_cred_id_t,
	gss_name_t*,
	OM_uint32*,
	gss_cred_usage_t*,
	gss_OID_set* mechanisms );

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_inquire_cred_by_mech (
	 OM_uint32*,
	gss_const_cred_id_t,
	const gss_OID,
	gss_name_t*,
	OM_uint32*,
	OM_uint32*,
	gss_cred_usage_t* cred_usage );

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_inquire_cred_by_oid (
	OM_uint32*,
	gss_const_cred_id_t,
	const gss_OID,
	gss_buffer_set_t*);

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_inquire_mechs_for_name (
	 OM_uint32*,
	gss_const_name_t,
	gss_OID_set* mech_types );

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_inquire_names_for_mech (
	 OM_uint32*,
	const gss_OID,
	gss_OID_set* name_types );

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_inquire_sec_context_by_oid (
	OM_uint32*,
	gss_const_ctx_id_t,
	const gss_OID,
	gss_buffer_set_t*);

OM_uint32
_gsskrb5_krb5_ccache_name (
	OM_uint32*,
	const char*,
	const char**);

OM_uint32
_gsskrb5_krb5_import_cred (
	OM_uint32*,
	krb5_ccache,
	krb5_principal,
	krb5_keytab,
	gss_cred_id_t*);

OM_uint32
_gsskrb5_lifetime_left (
	OM_uint32*,
	krb5_context,
	OM_uint32,
	OM_uint32*);

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_localname (
	OM_uint32*,
	gss_const_name_t,
	const gss_OID,
	gss_buffer_t);

void*
_gsskrb5_make_header (
	void*,
	size_t,
	const void*,
	const gss_OID);

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_process_context_token (
	 OM_uint32*,
	gss_const_ctx_id_t,
	const gss_buffer_t token_buffer );

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_pseudo_random (
	OM_uint32*,
	gss_ctx_id_t,
	int,
	const gss_buffer_t,
	ssize_t,
	gss_buffer_t);

OM_uint32
_gsskrb5_register_acceptor_identity (
	OM_uint32*,
	const char*);

OM_uint32
_gsskrb5_release_buffer (
	OM_uint32*,
	gss_buffer_t buffer );

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_release_cred (
	OM_uint32*,
	gss_cred_id_t* cred_handle );

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_release_name (
	OM_uint32*,
	gss_name_t* input_name );

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_set_cred_option (
	OM_uint32*,
	gss_cred_id_t*,
	const gss_OID,
	const gss_buffer_t);

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_set_sec_context_option (
	OM_uint32*,
	gss_ctx_id_t*,
	const gss_OID,
	const gss_buffer_t);

void
_gsskrb5_set_status (
	int,
	const char*,
	...);

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_store_cred (
	OM_uint32*,
	gss_cred_id_t,
	gss_cred_usage_t,
	const gss_OID,
	OM_uint32,
	OM_uint32,
	gss_OID_set*,
	gss_cred_usage_t*);

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_unwrap (
	OM_uint32*,
	gss_const_ctx_id_t,
	const gss_buffer_t,
	gss_buffer_t,
	int*,
	gss_qop_t* qop_state );

OM_uint32
_gsskrb5_verify_8003_checksum (
	 OM_uint32*,
	const gss_channel_bindings_t,
	const Checksum*,
	OM_uint32*,
	krb5_data*);

OM_uint32
_gsskrb5_verify_header (
	u_char**,
	size_t,
	const void*,
	gss_OID);

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_verify_mic (
	OM_uint32*,
	gss_const_ctx_id_t,
	const gss_buffer_t,
	const gss_buffer_t,
	gss_qop_t* qop_state );

OM_uint32
_gsskrb5_verify_mic_internal (
	OM_uint32*,
	const gsskrb5_ctx,
	krb5_context,
	const gss_buffer_t,
	const gss_buffer_t,
	gss_qop_t*,
	const char* type );

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_wrap (
	OM_uint32*,
	gss_const_ctx_id_t,
	int,
	gss_qop_t,
	const gss_buffer_t,
	int*,
	gss_buffer_t output_message_buffer );

OM_uint32 GSSAPI_CALLCONV
_gsskrb5_wrap_size_limit (
	 OM_uint32*,
	gss_const_ctx_id_t,
	int,
	gss_qop_t,
	OM_uint32,
	OM_uint32* max_input_size );

krb5_error_code
_gsskrb5cfx_wrap_length_cfx (
	krb5_context,
	krb5_crypto,
	int,
	int,
	size_t,
	size_t*,
	size_t*,
	uint16_t*);

krb5_error_code
_gsskrb5i_address_to_krb5addr (
	krb5_context,
	OM_uint32,
	gss_buffer_desc*,
	int16_t,
	krb5_address*);

krb5_error_code
_gsskrb5i_get_acceptor_subkey (
	const gsskrb5_ctx,
	krb5_context,
	krb5_keyblock**);

krb5_error_code
_gsskrb5i_get_initiator_subkey (
	const gsskrb5_ctx,
	krb5_context,
	krb5_keyblock**);

OM_uint32
_gsskrb5i_get_token_key (
	const gsskrb5_ctx,
	krb5_context,
	krb5_keyblock**);

void
_gsskrb5i_is_cfx (
	krb5_context,
	gsskrb5_ctx,
	int);

#endif /* __gsskrb5_private_h__ */
