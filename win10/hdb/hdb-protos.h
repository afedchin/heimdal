/* This is a generated file */
#ifndef __hdb_protos_h__
#define __hdb_protos_h__
#ifndef DOXY

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

krb5_error_code
entry2mit_string_int (
	krb5_context,
	krb5_storage*,
	hdb_entry*);

/**
 * This function adds an HDB entry's current keyset to the entry's key
 * history.  The current keyset is left alone; the caller is responsible
 * for freeing it.
 *
 * @param context   Context
 * @param entry	    HDB entry
 */

krb5_error_code
hdb_add_current_keys_to_history (
	krb5_context,
	hdb_entry*);

/**
 * This function adds a key to an HDB entry's key history.
 *
 * @param context   Context
 * @param entry	    HDB entry
 * @param kvno	    Key version number of the key to add to the history
 * @param key	    The Key to add
 */

krb5_error_code
hdb_add_history_key (
	krb5_context,
	hdb_entry*,
	krb5_kvno,
	Key*);

krb5_error_code
hdb_add_master_key (
	krb5_context,
	krb5_keyblock*,
	hdb_master_key*);

/**
 * This function changes an hdb_entry's kvno, swapping the current key
 * set with a historical keyset.  If no historical keys are found then
 * an error is returned (the caller can still set entry->kvno directly).
 *
 * @param context	krb5_context
 * @param new_kvno	New kvno for the entry
 * @param entry		hdb_entry to modify
 */

krb5_error_code
hdb_change_kvno (
	krb5_context,
	krb5_kvno,
	hdb_entry*);

krb5_error_code
hdb_check_db_format (
	krb5_context,
	HDB*);

krb5_error_code
hdb_clear_extension (
	krb5_context,
	hdb_entry*,
	int);

krb5_error_code
hdb_clear_master_key (
	krb5_context,
	HDB*);

/**
 * Create a handle for a Kerberos database
 *
 * Create a handle for a Kerberos database backend specified by a
 * filename.  Doesn't create a file if its doesn't exists, you have to
 * use O_CREAT to tell the backend to create the file.
 */

krb5_error_code
hdb_create (
	krb5_context,
	HDB**,
	const char*);

krb5_error_code
hdb_db1_create (
	krb5_context,
	HDB**,
	const char*);

krb5_error_code
hdb_db3_create (
	krb5_context,
	HDB**,
	const char*);

/**
 * Return the directory where the hdb database resides.
 *
 * @param context Kerberos 5 context.
 *
 * @return string pointing to directory.
 */

const char*
hdb_db_dir (krb5_context);

const char*
hdb_dbinfo_get_acl_file (
	krb5_context,
	struct hdb_dbinfo*);

const krb5_config_binding*
hdb_dbinfo_get_binding (
	krb5_context,
	struct hdb_dbinfo*);

const char*
hdb_dbinfo_get_dbname (
	krb5_context,
	struct hdb_dbinfo*);

const char*
hdb_dbinfo_get_label (
	krb5_context,
	struct hdb_dbinfo*);

const char*
hdb_dbinfo_get_log_file (
	krb5_context,
	struct hdb_dbinfo*);

const char*
hdb_dbinfo_get_mkey_file (
	krb5_context,
	struct hdb_dbinfo*);

struct hdb_dbinfo*
hdb_dbinfo_get_next (
	struct hdb_dbinfo*,
	struct hdb_dbinfo*);

const char*
hdb_dbinfo_get_realm (
	krb5_context,
	struct hdb_dbinfo*);

/**
 * Return the default hdb database resides.
 *
 * @param context Kerberos 5 context.
 *
 * @return string pointing to directory.
 */

const char*
hdb_default_db (krb5_context);

krb5_error_code
hdb_enctype2key (
	krb5_context,
	hdb_entry*,
	const Keys*,
	krb5_enctype,
	Key**);

krb5_error_code
hdb_entry2string (
	krb5_context,
	hdb_entry*,
	char**);

int
hdb_entry2value (
	krb5_context,
	const hdb_entry*,
	krb5_data*);

int
hdb_entry_alias2value (
	krb5_context,
	const hdb_entry_alias*,
	krb5_data*);

krb5_error_code
hdb_entry_check_mandatory (
	krb5_context,
	const hdb_entry*);

krb5_error_code
hdb_entry_clear_kvno_diff_clnt (
	krb5_context,
	hdb_entry*);

krb5_error_code
hdb_entry_clear_kvno_diff_svc (
	krb5_context,
	hdb_entry*);

int
hdb_entry_clear_password (
	krb5_context,
	hdb_entry*);

krb5_error_code
hdb_entry_get_ConstrainedDelegACL (
	const hdb_entry*,
	const HDB_Ext_Constrained_delegation_acl**);

krb5_error_code
hdb_entry_get_aliases (
	const hdb_entry*,
	const HDB_Ext_Aliases**);

unsigned int
hdb_entry_get_kvno_diff_clnt (const hdb_entry*);

unsigned int
hdb_entry_get_kvno_diff_svc (const hdb_entry*);

int
hdb_entry_get_password (
	krb5_context,
	HDB*,
	const hdb_entry*,
	char**);

krb5_error_code
hdb_entry_get_pkinit_acl (
	const hdb_entry*,
	const HDB_Ext_PKINIT_acl**);

krb5_error_code
hdb_entry_get_pkinit_cert (
	const hdb_entry*,
	const HDB_Ext_PKINIT_cert**);

krb5_error_code
hdb_entry_get_pkinit_hash (
	const hdb_entry*,
	const HDB_Ext_PKINIT_hash**);

krb5_error_code
hdb_entry_get_pw_change_time (
	const hdb_entry*,
	time_t*);

krb5_error_code
hdb_entry_set_kvno_diff_clnt (
	krb5_context,
	hdb_entry*,
	unsigned int);

krb5_error_code
hdb_entry_set_kvno_diff_svc (
	krb5_context,
	hdb_entry*,
	unsigned int);

int
hdb_entry_set_password (
	krb5_context,
	HDB*,
	hdb_entry*,
	const char*);

krb5_error_code
hdb_entry_set_pw_change_time (
	krb5_context,
	hdb_entry*,
	time_t);

HDB_extension*
hdb_find_extension (
	const hdb_entry*,
	int);

krb5_error_code
hdb_foreach (
	krb5_context,
	HDB*,
	unsigned,
	hdb_foreach_func_t,
	void*);

void
hdb_free_dbinfo (
	krb5_context,
	struct hdb_dbinfo**);

void
hdb_free_entry (
	krb5_context,
	hdb_entry_ex*);

void
hdb_free_key (Key*);

void
hdb_free_keys (
	krb5_context,
	int,
	Key*);

void
hdb_free_master_key (
	krb5_context,
	hdb_master_key);

krb5_error_code
hdb_generate_key_set (
	krb5_context,
	krb5_principal,
	krb5_key_salt_tuple*,
	int,
	Key**,
	size_t*,
	int);

krb5_error_code
hdb_generate_key_set_password (
	krb5_context,
	krb5_principal,
	const char*,
	Key**,
	size_t*);

krb5_error_code
hdb_generate_key_set_password_with_ks_tuple (
	krb5_context,
	krb5_principal,
	const char*,
	krb5_key_salt_tuple*,
	int,
	Key**,
	size_t*);

int
hdb_get_dbinfo (
	krb5_context,
	struct hdb_dbinfo**);

krb5_error_code
hdb_init_db (
	krb5_context,
	HDB*);

int
hdb_key2principal (
	krb5_context,
	krb5_data*,
	krb5_principal);

krb5_error_code
hdb_keytab_create (
	krb5_context,
	HDB**,
	const char*);

const Keys*
hdb_kvno2keys (
	krb5_context,
	const hdb_entry*,
	krb5_kvno);

krb5_error_code
hdb_ldap_create (
	krb5_context,
	HDB**,
	const char*);

krb5_error_code
hdb_ldapi_create (
	krb5_context,
	HDB**,
	const char*);

krb5_error_code
hdb_list_builtin (
	krb5_context,
	char**);

krb5_error_code
hdb_lock (
	int,
	int);

krb5_error_code
hdb_mdb_create (
	krb5_context,
	HDB**,
	const char*);

krb5_error_code
hdb_mitdb_create (
	krb5_context,
	HDB**,
	const char*);

krb5_error_code
hdb_ndbm_create (
	krb5_context,
	HDB**,
	const char*);

krb5_error_code
hdb_next_enctype2key (
	krb5_context,
	const hdb_entry*,
	const Keys*,
	krb5_enctype,
	Key**);

int
hdb_principal2key (
	krb5_context,
	krb5_const_principal,
	krb5_data*);

krb5_error_code
hdb_print_entry (
	krb5_context,
	HDB*,
	hdb_entry_ex*,
	void*);

krb5_error_code
hdb_process_master_key (
	krb5_context,
	int,
	krb5_keyblock*,
	krb5_enctype,
	hdb_master_key*);

/**
 * This function prunes an HDB entry's keys that are too old to have been used
 * to mint still valid tickets (based on the entry's maximum ticket lifetime).
 * 
 * @param context   Context
 * @param entry	    HDB entry
 */

krb5_error_code
hdb_prune_keys (
	krb5_context,
	hdb_entry*);

krb5_error_code
hdb_read_master_key (
	krb5_context,
	const char*,
	hdb_master_key*);

krb5_error_code
hdb_replace_extension (
	krb5_context,
	hdb_entry*,
	const HDB_extension*);

krb5_error_code
hdb_seal_key (
	krb5_context,
	HDB*,
	Key*);

krb5_error_code
hdb_seal_key_mkey (
	krb5_context,
	Key*,
	hdb_master_key);

krb5_error_code
hdb_seal_keys (
	krb5_context,
	HDB*,
	hdb_entry*);

krb5_error_code
hdb_seal_keys_mkey (
	krb5_context,
	hdb_entry*,
	hdb_master_key);

krb5_error_code
hdb_set_last_modified_by (
	krb5_context,
	hdb_entry*,
	krb5_principal,
	time_t);

krb5_error_code
hdb_set_master_key (
	krb5_context,
	HDB*,
	krb5_keyblock*);

krb5_error_code
hdb_set_master_keyfile (
	krb5_context,
	HDB*,
	const char*);

/**
 * Create SQLITE object, and creates the on disk database if its doesn't exists.
 *
 * @param context A Kerberos 5 context.
 * @param db a returned database handle.
 * @param filename filename
 *
 * @return        0 on success, an error code if not
 */

krb5_error_code
hdb_sqlite_create (
	krb5_context,
	HDB**,
	const char*);

krb5_error_code
hdb_unlock (int);

krb5_error_code
hdb_unseal_key (
	krb5_context,
	HDB*,
	Key*);

krb5_error_code
hdb_unseal_key_mkey (
	krb5_context,
	Key*,
	hdb_master_key);

krb5_error_code
hdb_unseal_keys (
	krb5_context,
	HDB*,
	hdb_entry*);

krb5_error_code
hdb_unseal_keys_kvno (
	krb5_context,
	HDB*,
	krb5_kvno,
	unsigned,
	hdb_entry*);

krb5_error_code
hdb_unseal_keys_mkey (
	krb5_context,
	hdb_entry*,
	hdb_master_key);

int
hdb_value2entry (
	krb5_context,
	krb5_data*,
	hdb_entry*);

int
hdb_value2entry_alias (
	krb5_context,
	krb5_data*,
	hdb_entry_alias*);

krb5_error_code
hdb_write_master_key (
	krb5_context,
	const char*,
	hdb_master_key);

#ifdef __cplusplus
}
#endif

#endif /* DOXY */
#endif /* __hdb_protos_h__ */
