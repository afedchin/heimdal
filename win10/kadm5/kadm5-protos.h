/* This is a generated file */
#ifndef __kadm5_protos_h__
#define __kadm5_protos_h__
#ifndef DOXY

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

kadm5_ret_t
kadm5_ad_init_with_password (
	const char*,
	const char*,
	const char*,
	kadm5_config_params*,
	unsigned long,
	unsigned long,
	void**);

kadm5_ret_t
kadm5_ad_init_with_password_ctx (
	krb5_context,
	const char*,
	const char*,
	const char*,
	kadm5_config_params*,
	unsigned long,
	unsigned long,
	void**);

krb5_error_code
kadm5_add_passwd_quality_verifier (
	krb5_context,
	const char*);

int
kadm5_all_keys_are_bogus (
	size_t,
	krb5_key_data*);

const char*
kadm5_check_password_quality (
	krb5_context,
	krb5_principal,
	krb5_data*);

kadm5_ret_t
kadm5_chpass_principal (
	void*,
	krb5_principal,
	const char*);

kadm5_ret_t
kadm5_chpass_principal_3 (
	void*,
	krb5_principal,
	krb5_boolean,
	int,
	krb5_key_salt_tuple*,
	const char*);

kadm5_ret_t
kadm5_chpass_principal_with_key (
	void*,
	krb5_principal,
	int,
	krb5_key_data*);

kadm5_ret_t
kadm5_chpass_principal_with_key_3 (
	void*,
	krb5_principal,
	int,
	int,
	krb5_key_data*);

kadm5_ret_t
kadm5_create_policy (
	void*,
	kadm5_policy_ent_t,
	long);

kadm5_ret_t
kadm5_create_principal (
	void*,
	kadm5_principal_ent_t,
	uint32_t,
	const char*);

kadm5_ret_t
kadm5_create_principal_3 (
	void*,
	kadm5_principal_ent_t,
	uint32_t,
	int,
	krb5_key_salt_tuple*,
	char*);

/**
 * Extract decrypted keys from kadm5_principal_ent_t object.  Mostly a
 * no-op for Heimdal because we fetch the entry with decrypted keys.
 * Sadly this is not fully a no-op, as we have to allocate a copy.
 *
 * @server_handle is the kadm5 handle
 * @entry is the HDB entry for the principal in question
 * @ktype is the enctype to get a key for, or -1 to get the first one
 * @stype is the salttype to get a key for, or -1 to get the first match
 * @kvno is the kvno to search for, or -1 to get the first match (highest kvno)
 * @keyblock is where the key will be placed
 * @keysalt, if not NULL, is where the salt will be placed
 * @kvnop, if not NULL, is where the selected kvno will be placed
 */

kadm5_ret_t
kadm5_decrypt_key (
	void*,
	kadm5_principal_ent_t,
	int32_t,
	int32_t,
	int32_t,
	krb5_keyblock*,
	krb5_keysalt*,
	int*);

kadm5_ret_t
kadm5_delete_policy (
	void*,
	char*);

kadm5_ret_t
kadm5_delete_principal (
	void*,
	krb5_principal);

kadm5_ret_t
kadm5_destroy (void*);

kadm5_ret_t
kadm5_flush (void*);

void
kadm5_free_key_data (
	void*,
	int16_t*,
	krb5_key_data*);

void
kadm5_free_name_list (
	void*,
	char**,
	int*);

kadm5_ret_t
kadm5_free_policy_ent (kadm5_policy_ent_t);

void
kadm5_free_principal_ent (
	void*,
	kadm5_principal_ent_t);

kadm5_ret_t
kadm5_get_policies (
	void*,
	char*,
	char***,
	int*);

kadm5_ret_t
kadm5_get_policy (
	void*,
	char*,
	kadm5_policy_ent_t);

kadm5_ret_t
kadm5_get_principal (
	void*,
	krb5_principal,
	kadm5_principal_ent_t,
	uint32_t);

kadm5_ret_t
kadm5_get_principals (
	void*,
	const char*,
	char***,
	int*);

kadm5_ret_t
kadm5_get_privs (
	void*,
	uint32_t*);

kadm5_ret_t
kadm5_init_with_creds (
	const char*,
	krb5_ccache,
	const char*,
	kadm5_config_params*,
	unsigned long,
	unsigned long,
	void**);

kadm5_ret_t
kadm5_init_with_creds_ctx (
	krb5_context,
	const char*,
	krb5_ccache,
	const char*,
	kadm5_config_params*,
	unsigned long,
	unsigned long,
	void**);

kadm5_ret_t
kadm5_init_with_password (
	const char*,
	const char*,
	const char*,
	kadm5_config_params*,
	unsigned long,
	unsigned long,
	void**);

kadm5_ret_t
kadm5_init_with_password_ctx (
	krb5_context,
	const char*,
	const char*,
	const char*,
	kadm5_config_params*,
	unsigned long,
	unsigned long,
	void**);

kadm5_ret_t
kadm5_init_with_skey (
	const char*,
	const char*,
	const char*,
	kadm5_config_params*,
	unsigned long,
	unsigned long,
	void**);

kadm5_ret_t
kadm5_init_with_skey_ctx (
	krb5_context,
	const char*,
	const char*,
	const char*,
	kadm5_config_params*,
	unsigned long,
	unsigned long,
	void**);

kadm5_ret_t
kadm5_lock (void*);

kadm5_ret_t
kadm5_modify_policy (
	void*,
	kadm5_policy_ent_t,
	uint32_t);

kadm5_ret_t
kadm5_modify_principal (
	void*,
	kadm5_principal_ent_t,
	uint32_t);

kadm5_ret_t
kadm5_randkey_principal (
	void*,
	krb5_principal,
	krb5_keyblock**,
	int*);

kadm5_ret_t
kadm5_randkey_principal_3 (
	void*,
	krb5_principal,
	krb5_boolean,
	int,
	krb5_key_salt_tuple*,
	krb5_keyblock**,
	int*);

kadm5_ret_t
kadm5_rename_principal (
	void*,
	krb5_principal,
	krb5_principal);

kadm5_ret_t
kadm5_ret_key_data (
	krb5_storage*,
	krb5_key_data*);

kadm5_ret_t
kadm5_ret_principal_ent (
	krb5_storage*,
	kadm5_principal_ent_t);

kadm5_ret_t
kadm5_ret_principal_ent_mask (
	krb5_storage*,
	kadm5_principal_ent_t,
	uint32_t*);

kadm5_ret_t
kadm5_ret_tl_data (
	krb5_storage*,
	krb5_tl_data*);

/**
 * This function is allows the caller to set new keys for a principal.
 * This is a trivial wrapper around kadm5_setkey_principal_3().
 */

kadm5_ret_t
kadm5_setkey_principal (
	void*,
	krb5_principal,
	krb5_keyblock*,
	int);

/**
 * This function is allows the caller to set new keys for a principal.
 * This is a simple wrapper around kadm5_get_principal() and
 * kadm5_modify_principal().
 */

kadm5_ret_t
kadm5_setkey_principal_3 (
	void*,
	krb5_principal,
	krb5_boolean,
	int,
	krb5_key_salt_tuple*,
	krb5_keyblock*,
	int);

void
kadm5_setup_passwd_quality_check (
	krb5_context,
	const char*,
	const char*);

int
kadm5_some_keys_are_bogus (
	size_t,
	krb5_key_data*);

kadm5_ret_t
kadm5_store_fake_key_data (
	krb5_storage*,
	krb5_key_data*);

kadm5_ret_t
kadm5_store_key_data (
	krb5_storage*,
	krb5_key_data*);

kadm5_ret_t
kadm5_store_principal_ent (
	krb5_storage*,
	kadm5_principal_ent_t);

kadm5_ret_t
kadm5_store_principal_ent_mask (
	krb5_storage*,
	kadm5_principal_ent_t,
	uint32_t);

kadm5_ret_t
kadm5_store_principal_ent_nokeys (
	krb5_storage*,
	kadm5_principal_ent_t);

kadm5_ret_t
kadm5_store_tl_data (
	krb5_storage*,
	krb5_tl_data*);

kadm5_ret_t
kadm5_unlock (void*);

#ifdef __cplusplus
}
#endif

#endif /* DOXY */
#endif /* __kadm5_protos_h__ */
