/* This is a generated file */
#ifndef __kadm5_private_h__
#define __kadm5_private_h__

#include <stdarg.h>

kadm5_ret_t
_kadm5_acl_check_permission (
	kadm5_server_context*,
	unsigned,
	krb5_const_principal);

kadm5_ret_t
_kadm5_acl_init (kadm5_server_context*);

kadm5_ret_t
_kadm5_bump_pw_expire (
	kadm5_server_context*,
	hdb_entry*);

krb5_error_code
_kadm5_c_get_cred_cache (
	krb5_context,
	const char*,
	const char*,
	const char*,
	krb5_prompter_fct,
	const char*,
	krb5_ccache,
	krb5_ccache*);

kadm5_ret_t
_kadm5_c_init_context (
	kadm5_client_context**,
	kadm5_config_params*,
	krb5_context);

kadm5_ret_t
_kadm5_client_recv (
	kadm5_client_context*,
	krb5_data*);

kadm5_ret_t
_kadm5_client_send (
	kadm5_client_context*,
	krb5_storage*);

kadm5_ret_t
_kadm5_connect (void*);

kadm5_ret_t
_kadm5_error_code (kadm5_ret_t);

int
_kadm5_exists_keys_hist (
	Key*,
	int,
	HDB_Ext_KeySet*);

void
_kadm5_free_keys (
	krb5_context,
	int,
	Key*);

void
_kadm5_init_keys (
	Key*,
	int);

kadm5_ret_t
_kadm5_marshal_params (
	krb5_context,
	kadm5_config_params*,
	krb5_data*);

kadm5_ret_t
_kadm5_privs_to_string (
	uint32_t,
	char*,
	size_t);

HDB*
_kadm5_s_get_db (void*);

kadm5_ret_t
_kadm5_s_init_context (
	kadm5_server_context**,
	kadm5_config_params*,
	krb5_context);

kadm5_ret_t
_kadm5_set_keys (
	kadm5_server_context*,
	hdb_entry*,
	int,
	krb5_key_salt_tuple*,
	const char*);

kadm5_ret_t
_kadm5_set_keys2 (
	kadm5_server_context*,
	hdb_entry*,
	int16_t,
	krb5_key_data*);

kadm5_ret_t
_kadm5_set_keys3 (
	kadm5_server_context*,
	hdb_entry*,
	int,
	krb5_keyblock*);

kadm5_ret_t
_kadm5_set_keys_randomly (
	kadm5_server_context*,
	hdb_entry*,
	int,
	krb5_key_salt_tuple*,
	krb5_keyblock**,
	int*);

kadm5_ret_t
_kadm5_set_modifier (
	kadm5_server_context*,
	hdb_entry*);

kadm5_ret_t
_kadm5_setup_entry (
	kadm5_server_context*,
	hdb_entry_ex*,
	uint32_t,
	kadm5_principal_ent_t,
	uint32_t,
	kadm5_principal_ent_t,
	uint32_t);

kadm5_ret_t
_kadm5_string_to_privs (
	const char*,
	uint32_t*);

kadm5_ret_t
_kadm5_unmarshal_params (
	krb5_context,
	krb5_data*,
	kadm5_config_params*);

kadm5_ret_t
kadm5_c_chpass_principal (
	void*,
	krb5_principal,
	int,
	int,
	krb5_key_salt_tuple*,
	const char*);

kadm5_ret_t
kadm5_c_chpass_principal_with_key (
	void*,
	krb5_principal,
	int,
	int,
	krb5_key_data*);

kadm5_ret_t
kadm5_c_create_principal (
	void*,
	kadm5_principal_ent_t,
	uint32_t,
	int,
	krb5_key_salt_tuple*,
	const char*);

kadm5_ret_t
kadm5_c_delete_principal (
	void*,
	krb5_principal);

kadm5_ret_t
kadm5_c_destroy (void*);

kadm5_ret_t
kadm5_c_flush (void*);

kadm5_ret_t
kadm5_c_get_principal (
	void*,
	krb5_principal,
	kadm5_principal_ent_t,
	uint32_t);

kadm5_ret_t
kadm5_c_get_principals (
	void*,
	const char*,
	char***,
	int*);

kadm5_ret_t
kadm5_c_get_privs (
	void*,
	uint32_t*);

kadm5_ret_t
kadm5_c_init_with_creds (
	const char*,
	krb5_ccache,
	const char*,
	kadm5_config_params*,
	unsigned long,
	unsigned long,
	void**);

kadm5_ret_t
kadm5_c_init_with_creds_ctx (
	krb5_context,
	const char*,
	krb5_ccache,
	const char*,
	kadm5_config_params*,
	unsigned long,
	unsigned long,
	void**);

kadm5_ret_t
kadm5_c_init_with_password (
	const char*,
	const char*,
	const char*,
	kadm5_config_params*,
	unsigned long,
	unsigned long,
	void**);

kadm5_ret_t
kadm5_c_init_with_password_ctx (
	krb5_context,
	const char*,
	const char*,
	const char*,
	kadm5_config_params*,
	unsigned long,
	unsigned long,
	void**);

kadm5_ret_t
kadm5_c_init_with_skey (
	const char*,
	const char*,
	const char*,
	kadm5_config_params*,
	unsigned long,
	unsigned long,
	void**);

kadm5_ret_t
kadm5_c_init_with_skey_ctx (
	krb5_context,
	const char*,
	const char*,
	const char*,
	kadm5_config_params*,
	unsigned long,
	unsigned long,
	void**);

kadm5_ret_t
kadm5_c_modify_principal (
	void*,
	kadm5_principal_ent_t,
	uint32_t);

kadm5_ret_t
kadm5_c_randkey_principal (
	void*,
	krb5_principal,
	krb5_boolean,
	int,
	krb5_key_salt_tuple*,
	krb5_keyblock**,
	int*);

kadm5_ret_t
kadm5_c_rename_principal (
	void*,
	krb5_principal,
	krb5_principal);

kadm5_ret_t
kadm5_log_create (
	kadm5_server_context*,
	hdb_entry*);

kadm5_ret_t
kadm5_log_delete (
	kadm5_server_context*,
	krb5_principal);

kadm5_ret_t
kadm5_log_end (kadm5_server_context*);

kadm5_ret_t
kadm5_log_foreach (
	kadm5_server_context*,
	enum kadm_iter_opts,
	off_t*,
	kadm5_ret_t (*)(kadm5_server_context*server_context, uint32_t ver, time_t timestamp, enum kadm_ops op, uint32_t len, krb5_storage*sp, void*ctx),
	void*);

kadm5_ret_t
kadm5_log_get_version (
	kadm5_server_context*,
	uint32_t*);

kadm5_ret_t
kadm5_log_get_version_fd (
	kadm5_server_context*,
	int,
	int,
	uint32_t*,
	uint32_t*);

krb5_storage*
kadm5_log_goto_end (
	kadm5_server_context*,
	int);

kadm5_ret_t
kadm5_log_init (kadm5_server_context*);

kadm5_ret_t
kadm5_log_init_nb (kadm5_server_context*);

kadm5_ret_t
kadm5_log_init_nolock (kadm5_server_context*);

kadm5_ret_t
kadm5_log_init_sharedlock (
	kadm5_server_context*,
	int);

kadm5_ret_t
kadm5_log_modify (
	kadm5_server_context*,
	hdb_entry*,
	uint32_t);

kadm5_ret_t
kadm5_log_nop (
	kadm5_server_context*,
	enum kadm_nop_type);

kadm5_ret_t
kadm5_log_previous (
	krb5_context,
	krb5_storage*,
	uint32_t*,
	time_t*,
	enum kadm_ops*,
	uint32_t*);

kadm5_ret_t
kadm5_log_recover (
	kadm5_server_context*,
	enum kadm_recover_mode);

kadm5_ret_t
kadm5_log_reinit (
	kadm5_server_context*,
	uint32_t);

kadm5_ret_t
kadm5_log_rename (
	kadm5_server_context*,
	krb5_principal,
	hdb_entry*);

kadm5_ret_t
kadm5_log_replay (
	kadm5_server_context*,
	enum kadm_ops,
	uint32_t,
	uint32_t,
	krb5_storage*);

kadm5_ret_t
kadm5_log_set_version (
	kadm5_server_context*,
	uint32_t);

void
kadm5_log_signal_master (kadm5_server_context*);

const char*
kadm5_log_signal_socket (krb5_context);

kadm5_ret_t
kadm5_log_signal_socket_info (
	krb5_context,
	int,
	struct addrinfo**);

kadm5_ret_t
kadm5_log_truncate (
	kadm5_server_context*,
	size_t,
	size_t);

kadm5_ret_t
kadm5_s_chpass_principal (
	void*,
	krb5_principal,
	int,
	int,
	krb5_key_salt_tuple*,
	const char*);

kadm5_ret_t
kadm5_s_chpass_principal_cond (
	void*,
	krb5_principal,
	int,
	const char*);

kadm5_ret_t
kadm5_s_chpass_principal_with_key (
	void*,
	krb5_principal,
	int,
	int,
	krb5_key_data*);

kadm5_ret_t
kadm5_s_create_principal (
	void*,
	kadm5_principal_ent_t,
	uint32_t,
	int,
	krb5_key_salt_tuple*,
	const char*);

kadm5_ret_t
kadm5_s_create_principal_with_key (
	void*,
	kadm5_principal_ent_t,
	uint32_t);

kadm5_ret_t
kadm5_s_delete_principal (
	void*,
	krb5_principal);

kadm5_ret_t
kadm5_s_destroy (void*);

kadm5_ret_t
kadm5_s_flush (void*);

kadm5_ret_t
kadm5_s_get_principal (
	void*,
	krb5_principal,
	kadm5_principal_ent_t,
	uint32_t);

kadm5_ret_t
kadm5_s_get_principals (
	void*,
	const char*,
	char***,
	int*);

kadm5_ret_t
kadm5_s_get_privs (
	void*,
	uint32_t*);

kadm5_ret_t
kadm5_s_init_with_creds (
	const char*,
	krb5_ccache,
	const char*,
	kadm5_config_params*,
	unsigned long,
	unsigned long,
	void**);

kadm5_ret_t
kadm5_s_init_with_creds_ctx (
	krb5_context,
	const char*,
	krb5_ccache,
	const char*,
	kadm5_config_params*,
	unsigned long,
	unsigned long,
	void**);

kadm5_ret_t
kadm5_s_init_with_password (
	const char*,
	const char*,
	const char*,
	kadm5_config_params*,
	unsigned long,
	unsigned long,
	void**);

kadm5_ret_t
kadm5_s_init_with_password_ctx (
	krb5_context,
	const char*,
	const char*,
	const char*,
	kadm5_config_params*,
	unsigned long,
	unsigned long,
	void**);

kadm5_ret_t
kadm5_s_init_with_skey (
	const char*,
	const char*,
	const char*,
	kadm5_config_params*,
	unsigned long,
	unsigned long,
	void**);

kadm5_ret_t
kadm5_s_init_with_skey_ctx (
	krb5_context,
	const char*,
	const char*,
	const char*,
	kadm5_config_params*,
	unsigned long,
	unsigned long,
	void**);

kadm5_ret_t
kadm5_s_modify_principal (
	void*,
	kadm5_principal_ent_t,
	uint32_t);

kadm5_ret_t
kadm5_s_randkey_principal (
	void*,
	krb5_principal,
	krb5_boolean,
	int,
	krb5_key_salt_tuple*,
	krb5_keyblock**,
	int*);

kadm5_ret_t
kadm5_s_rename_principal (
	void*,
	krb5_principal,
	krb5_principal);

kadm5_ret_t
kadm5_s_setkey_principal_3 (
	void*,
	krb5_principal,
	krb5_boolean,
	int,
	krb5_key_salt_tuple*,
	krb5_keyblock*,
	int);

#endif /* __kadm5_private_h__ */
