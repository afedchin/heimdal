/* This is a generated file */
#ifndef __krb5_private_h__
#define __krb5_private_h__

#include <stdarg.h>

#if !defined(__GNUC__) && !defined(__attribute__)
#define __attribute__(x)
#endif

#ifndef KRB5_DEPRECATED_FUNCTION
#ifndef __has_extension
#define __has_extension(x) 0
#define KRB5_DEPRECATED_FUNCTIONhas_extension 1
#endif
#if __has_extension(attribute_deprecated_with_message)
#define KRB5_DEPRECATED_FUNCTION(x) __attribute__((__deprecated__(x)))
#elif defined(__GNUC__) && ((__GNUC__ > 3) || ((__GNUC__ == 3) && (__GNUC_MINOR__ >= 1 )))
#define KRB5_DEPRECATED_FUNCTION(X) __attribute__((__deprecated__))
#else
#define KRB5_DEPRECATED_FUNCTION(X)
#endif
#ifdef KRB5_DEPRECATED_FUNCTIONhas_extension
#undef __has_extension
#undef KRB5_DEPRECATED_FUNCTIONhas_extension
#endif
#endif /* KRB5_DEPRECATED_FUNCTION */


KRB5_LIB_FUNCTION void KRB5_LIB_CALL
_heim_krb5_ipc_client_clear_target (void);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
_heim_krb5_ipc_client_set_target_uid (uid_t);

void
_krb5_DES3_random_to_key (
	krb5_context,
	krb5_keyblock*,
	const void*,
	size_t);

krb5_error_code
_krb5_HMAC_MD5_checksum (
	krb5_context,
	struct _krb5_key_data*,
	const void*,
	size_t,
	unsigned,
	Checksum*);

krb5_error_code
_krb5_SP800_108_HMAC_KDF (
	krb5_context,
	const krb5_data*,
	const krb5_data*,
	const krb5_data*,
	const EVP_MD*,
	krb5_data*);

krb5_error_code
_krb5_SP_HMAC_SHA1_checksum (
	krb5_context,
	struct _krb5_key_data*,
	const void*,
	size_t,
	unsigned,
	Checksum*);

krb5_error_code
_krb5_aes_sha2_md_for_enctype (
	krb5_context,
	krb5_enctype,
	const EVP_MD**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_build_authenticator (
	krb5_context,
	krb5_auth_context,
	krb5_enctype,
	krb5_creds*,
	Checksum*,
	krb5_data*,
	krb5_key_usage);

krb5_error_code
_krb5_build_authpack_subjectPK_EC (
	krb5_context,
	krb5_pk_init_ctx,
	AuthPack*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_cc_allocate (
	krb5_context,
	const krb5_cc_ops*,
	krb5_ccache*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_config_copy (
	krb5_context,
	krb5_config_section*,
	krb5_config_section**);

KRB5_LIB_FUNCTION const void* KRB5_LIB_CALL
_krb5_config_get (
	krb5_context,
	const krb5_config_section*,
	int,
	...);

KRB5_LIB_FUNCTION krb5_config_section* KRB5_LIB_CALL
_krb5_config_get_entry (
	krb5_config_section**,
	const char*,
	int);

KRB5_LIB_FUNCTION const void* KRB5_LIB_CALL
_krb5_config_get_next (
	krb5_context,
	const krb5_config_section*,
	const krb5_config_binding**,
	int,
	...);

KRB5_LIB_FUNCTION const void* KRB5_LIB_CALL
_krb5_config_vget (
	krb5_context,
	const krb5_config_section*,
	int,
	va_list);

KRB5_LIB_FUNCTION const void* KRB5_LIB_CALL
_krb5_config_vget_next (
	krb5_context,
	const krb5_config_section*,
	const krb5_config_binding**,
	int,
	va_list);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_copy_send_to_kdc_func (
	krb5_context,
	krb5_context);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
_krb5_crc_init_table (void);

KRB5_LIB_FUNCTION uint32_t KRB5_LIB_CALL
_krb5_crc_update (
	const char*,
	size_t,
	uint32_t);

void KRB5_LIB_FUNCTION
_krb5_debug (
	krb5_context,
	int,
	const char*,
	...)
     __attribute__ ((__format__ (__printf__, 3, 4)));

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
_krb5_debug_backtrace (krb5_context);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_derive_key (
	krb5_context,
	struct _krb5_encryption_type*,
	struct _krb5_key_data*,
	const void*,
	size_t);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_des_checksum (
	krb5_context,
	const EVP_MD*,
	struct _krb5_key_data*,
	const void*,
	size_t,
	Checksum*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_des_verify (
	krb5_context,
	const EVP_MD*,
	struct _krb5_key_data*,
	const void*,
	size_t,
	Checksum*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_dh_group_ok (
	krb5_context,
	unsigned long,
	heim_integer*,
	heim_integer*,
	heim_integer*,
	struct krb5_dh_moduli**,
	char**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_einval (
	krb5_context,
	const char*,
	unsigned long);

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
_krb5_enctype_requires_random_salt (
	krb5_context,
	krb5_enctype);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_erase_file (
	krb5_context,
	const char*);

void
_krb5_evp_cleanup (
	krb5_context,
	struct _krb5_key_data*);

krb5_error_code
_krb5_evp_encrypt (
	krb5_context,
	struct _krb5_key_data*,
	void*,
	size_t,
	krb5_boolean,
	int,
	void*);

krb5_error_code
_krb5_evp_encrypt_cts (
	krb5_context,
	struct _krb5_key_data*,
	void*,
	size_t,
	krb5_boolean,
	int,
	void*);

void
_krb5_evp_schedule (
	krb5_context,
	struct _krb5_key_type*,
	struct _krb5_key_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_expand_default_cc_name (
	krb5_context,
	const char*,
	char**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_expand_path_tokens (
	krb5_context,
	const char*,
	int,
	char**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_expand_path_tokensv (
	krb5_context,
	const char*,
	int,
	char**,
	...);

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
_krb5_extract_ticket (
	krb5_context,
	krb5_kdc_rep*,
	krb5_creds*,
	krb5_keyblock*,
	krb5_const_pointer,
	krb5_key_usage,
	krb5_addresses*,
	unsigned,
	unsigned,
	krb5_data*,
	krb5_decrypt_proc,
	krb5_const_pointer);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_fast_armor_key (
	krb5_context,
	krb5_keyblock*,
	krb5_keyblock*,
	krb5_keyblock*,
	krb5_crypto*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_fast_cf2 (
	krb5_context,
	krb5_keyblock*,
	const char*,
	krb5_keyblock*,
	const char*,
	krb5_keyblock*,
	krb5_crypto*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_find_capath (
	krb5_context,
	const char*,
	const char*,
	const char*,
	krb5_boolean,
	char***,
	size_t*);

KRB5_LIB_FUNCTION struct _krb5_checksum_type* KRB5_LIB_CALL
_krb5_find_checksum (krb5_cksumtype);

KRB5_LIB_FUNCTION struct _krb5_encryption_type* KRB5_LIB_CALL
_krb5_find_enctype (krb5_enctype);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
_krb5_free_capath (
	krb5_context,
	char**);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
_krb5_free_key_data (
	krb5_context,
	struct _krb5_key_data*,
	struct _krb5_encryption_type*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
_krb5_free_krbhst_info (krb5_krbhst_info*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
_krb5_free_moduli (struct krb5_dh_moduli**);

KRB5_LIB_FUNCTION void
_krb5_free_name_canon_rules (
	krb5_context,
	krb5_name_canon_rule);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_get_ad (
	krb5_context,
	const AuthorizationData*,
	krb5_keyblock*,
	int,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_get_cred_kdc_any (
	krb5_context,
	krb5_kdc_flags,
	krb5_ccache,
	krb5_creds*,
	krb5_principal,
	Ticket*,
	krb5_creds**,
	krb5_creds***);

KRB5_LIB_FUNCTION char* KRB5_LIB_CALL
_krb5_get_default_cc_name_from_registry (krb5_context);

KRB5_LIB_FUNCTION char* KRB5_LIB_CALL
_krb5_get_default_config_config_files_from_registry (void);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_get_default_principal_local (
	krb5_context,
	krb5_principal*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_get_host_realm_int (
	krb5_context,
	const char*,
	krb5_boolean,
	krb5_realm**);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
_krb5_get_init_creds_opt_free_pkinit (krb5_get_init_creds_opt*);

KRB5_LIB_FUNCTION krb5_ssize_t KRB5_LIB_CALL
_krb5_get_int (
	void*,
	unsigned long*,
	size_t);

KRB5_LIB_FUNCTION krb5_ssize_t KRB5_LIB_CALL
_krb5_get_int64 (
	void*,
	uint64_t*,
	size_t);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_get_krbtgt (
	krb5_context,
	krb5_ccache,
	krb5_realm,
	krb5_creds**);

KRB5_LIB_FUNCTION krb5_error_code
_krb5_get_name_canon_rules (
	krb5_context,
	krb5_name_canon_rule*);

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
_krb5_have_debug (
	krb5_context,
	int);

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
_krb5_homedir_access (krb5_context);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_init_etype (
	krb5_context,
	krb5_pdu,
	unsigned*,
	krb5_enctype**,
	const krb5_enctype*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_internal_hmac (
	krb5_context,
	struct _krb5_checksum_type*,
	const void*,
	size_t,
	unsigned,
	struct _krb5_key_data*,
	Checksum*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_kcm_get_initial_ticket (
	krb5_context,
	krb5_ccache,
	krb5_principal,
	krb5_keyblock*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_kcm_get_ticket (
	krb5_context,
	krb5_ccache,
	krb5_kdc_flags,
	krb5_enctype,
	krb5_principal);

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
_krb5_kcm_is_running (krb5_context);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_kcm_noop (
	krb5_context,
	krb5_ccache);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_kdc_retry (
	krb5_context,
	krb5_sendto_ctx,
	void*,
	const krb5_data*,
	int*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_krbhost_info_move (
	krb5_context,
	krb5_krbhst_info*,
	krb5_krbhst_info**);

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
_krb5_krbhst_get_realm (krb5_krbhst_handle);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_kt_principal_not_found (
	krb5_context,
	krb5_error_code,
	krb5_keytab,
	krb5_const_principal,
	krb5_enctype,
	int);

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
_krb5_kuserok (
	krb5_context,
	krb5_principal,
	const char*,
	krb5_boolean);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_load_ccache_plugins (krb5_context);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_load_config_from_registry (
	krb5_context,
	krb5_config_section**);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
_krb5_load_db_plugins (krb5_context);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
_krb5_load_plugins (
	krb5_context,
	const char*,
	const char**);

krb5_error_code
_krb5_make_fast_ap_fxarmor (
	krb5_context,
	krb5_ccache,
	krb5_data*,
	krb5_keyblock*,
	krb5_crypto*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_mk_req_internal (
	krb5_context,
	krb5_auth_context*,
	const krb5_flags,
	krb5_data*,
	krb5_creds*,
	krb5_data*,
	krb5_key_usage,
	krb5_key_usage);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_n_fold (
	const void*,
	size_t,
	void*,
	size_t);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_pac_sign (
	krb5_context,
	krb5_pac,
	time_t,
	krb5_principal,
	const krb5_keyblock*,
	const krb5_keyblock*,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_parse_moduli (
	krb5_context,
	const char*,
	struct krb5_dh_moduli***);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_parse_moduli_line (
	krb5_context,
	const char*,
	int,
	char*,
	struct krb5_dh_moduli**);

KRB5_LIB_FUNCTION char* KRB5_LIB_CALL
_krb5_parse_reg_value_as_multi_string (
	krb5_context,
	HKEY,
	const char*,
	DWORD,
	DWORD,
	char*);

KRB5_LIB_FUNCTION char* KRB5_LIB_CALL
_krb5_parse_reg_value_as_string (
	krb5_context,
	HKEY,
	const char*,
	DWORD,
	DWORD);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
_krb5_pk_cert_free (struct krb5_pk_cert*);

void
_krb5_pk_eckey_free (void*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_pk_kdf (
	krb5_context,
	const struct AlgorithmIdentifier*,
	const void*,
	size_t,
	krb5_const_principal,
	krb5_const_principal,
	krb5_enctype,
	const krb5_data*,
	const krb5_data*,
	const Ticket*,
	krb5_keyblock*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_pk_load_id (
	krb5_context,
	struct krb5_pk_identity**,
	const char*,
	const char*,
	char* const*,
	char* const*,
	krb5_prompter_fct,
	void*,
	char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_pk_mk_ContentInfo (
	krb5_context,
	const krb5_data*,
	const heim_oid*,
	struct ContentInfo*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_pk_mk_padata (
	krb5_context,
	void*,
	int,
	int,
	const KDC_REQ_BODY*,
	unsigned,
	METHOD_DATA*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_pk_octetstring2key (
	krb5_context,
	krb5_enctype,
	const void*,
	size_t,
	const heim_octet_string*,
	const heim_octet_string*,
	krb5_keyblock*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_pk_rd_pa_reply (
	krb5_context,
	const char*,
	void*,
	krb5_enctype,
	const krb5_krbhst_info*,
	unsigned,
	const krb5_data*,
	PA_DATA*,
	krb5_keyblock**);

krb5_error_code
_krb5_pk_rd_pa_reply_ecdh_compute_key (
	krb5_context,
	krb5_pk_init_ctx,
	const unsigned char*,
	size_t,
	unsigned char**,
	int*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_plugin_find (
	krb5_context,
	enum krb5_plugin_type,
	const char*,
	struct krb5_plugin**);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
_krb5_plugin_free (struct krb5_plugin*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_plugin_run_f (
	krb5_context,
	const char*,
	const char*,
	int,
	int,
	void*,
	krb5_error_code (KRB5_LIB_CALL*func)(krb5_context, const void*, void*, void*));

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_principal2principalname (
	PrincipalName*,
	const krb5_principal);

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
_krb5_principal_compare_PrincipalName (
	krb5_context,
	krb5_const_principal,
	PrincipalName*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_principalname2krb5_principal (
	krb5_context,
	krb5_principal*,
	const PrincipalName,
	const Realm);

KRB5_LIB_FUNCTION krb5_ssize_t KRB5_LIB_CALL
_krb5_put_int (
	void*,
	uint64_t,
	size_t);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_s4u2self_to_checksumdata (
	krb5_context,
	const PA_S4U2Self*,
	krb5_data*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
_krb5_sendto_ctx_set_krb5hst (
	krb5_context,
	krb5_sendto_ctx,
	krb5_krbhst_handle);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
_krb5_sendto_ctx_set_prexmit (
	krb5_sendto_ctx,
	krb5_sendto_prexmit,
	void*);

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
_krb5_set_default_cc_name_to_registry (
	krb5_context,
	krb5_ccache);

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
_krb5_store_string_to_reg_value (
	krb5_context,
	HKEY,
	const char*,
	DWORD,
	const char*,
	DWORD,
	const char*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
_krb5_unload_plugins (
	krb5_context,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_usage2arcfour (
	krb5_context,
	unsigned*);

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
_krb5_xlock (
	krb5_context,
	int,
	krb5_boolean,
	const char*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
_krb5_xor8 (
	unsigned char*,
	const unsigned char*);

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
_krb5_xunlock (
	krb5_context,
	int);

#undef KRB5_DEPRECATED_FUNCTION
#define KRB5_DEPRECATED_FUNCTION(X)

#endif /* __krb5_private_h__ */
