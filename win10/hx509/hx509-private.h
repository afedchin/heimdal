/* This is a generated file */
#ifndef __hx509_private_h__
#define __hx509_private_h__

#include <stdarg.h>

#if !defined(__GNUC__) && !defined(__attribute__)
#define __attribute__(x)
#endif

int
_hx509_AlgorithmIdentifier_cmp (
	const AlgorithmIdentifier*,
	const AlgorithmIdentifier*);

int
_hx509_Certificate_cmp (
	const Certificate*,
	const Certificate*);

int
_hx509_Name_to_string (
	const Name*,
	char**);

time_t
_hx509_Time2time_t (const Time*);

void
_hx509_abort (
	const char*,
	...)
     __attribute__ ((__noreturn__, __format__ (__printf__, 1, 2)));

int
_hx509_calculate_path (
	hx509_context,
	int,
	time_t,
	hx509_certs,
	unsigned int,
	hx509_cert,
	hx509_certs,
	hx509_path*);

int
_hx509_cert_assign_key (
	hx509_cert,
	hx509_private_key);

int
_hx509_cert_get_eku (
	hx509_context,
	hx509_cert,
	ExtKeyUsage*);

int
_hx509_cert_get_keyusage (
	hx509_context,
	hx509_cert,
	KeyUsage*);

int
_hx509_cert_get_version (const Certificate*);

int
_hx509_cert_is_parent_cmp (
	const Certificate*,
	const Certificate*,
	int);

int
_hx509_cert_private_decrypt (
	hx509_context,
	const heim_octet_string*,
	const heim_oid*,
	hx509_cert,
	heim_octet_string*);

hx509_private_key
_hx509_cert_private_key (hx509_cert);

int
_hx509_cert_private_key_exportable (hx509_cert);

void
_hx509_cert_set_release (
	hx509_cert,
	_hx509_cert_release_func,
	void*);

int
_hx509_cert_to_env (
	hx509_context,
	hx509_cert,
	hx509_env*);

int
_hx509_certs_keys_add (
	hx509_context,
	hx509_certs,
	hx509_private_key);

void
_hx509_certs_keys_free (
	hx509_context,
	hx509_private_key*);

int
_hx509_certs_keys_get (
	hx509_context,
	hx509_certs,
	hx509_private_key**);

int
_hx509_check_key_usage (
	hx509_context,
	hx509_cert,
	unsigned,
	int);

int
_hx509_collector_alloc (
	hx509_context,
	hx509_lock,
	struct hx509_collector**);

int
_hx509_collector_certs_add (
	hx509_context,
	struct hx509_collector*,
	hx509_cert);

int
_hx509_collector_collect_certs (
	hx509_context,
	struct hx509_collector*,
	hx509_certs*);

int
_hx509_collector_collect_private_keys (
	hx509_context,
	struct hx509_collector*,
	hx509_private_key**);

void
_hx509_collector_free (struct hx509_collector*);

hx509_lock
_hx509_collector_get_lock (struct hx509_collector*);

int
_hx509_collector_private_key_add (
	hx509_context,
	struct hx509_collector*,
	const AlgorithmIdentifier*,
	hx509_private_key,
	const heim_octet_string*,
	const heim_octet_string*);

int
_hx509_create_signature (
	hx509_context,
	const hx509_private_key,
	const AlgorithmIdentifier*,
	const heim_octet_string*,
	AlgorithmIdentifier*,
	heim_octet_string*);

int
_hx509_create_signature_bitstring (
	hx509_context,
	const hx509_private_key,
	const AlgorithmIdentifier*,
	const heim_octet_string*,
	AlgorithmIdentifier*,
	heim_bit_string*);

int
_hx509_expr_eval (
	hx509_context,
	hx509_env,
	struct hx_expr*);

void
_hx509_expr_free (struct hx_expr*);

struct hx_expr*
_hx509_expr_parse (const char*);

int
_hx509_find_extension_subject_key_id (
	const Certificate*,
	SubjectKeyIdentifier*);

const struct signature_alg*
_hx509_find_sig_alg (const heim_oid*);

int
_hx509_generate_private_key (
	hx509_context,
	struct hx509_generate_private_context*,
	hx509_private_key*);

int
_hx509_generate_private_key_bits (
	hx509_context,
	struct hx509_generate_private_context*,
	unsigned long);

void
_hx509_generate_private_key_free (struct hx509_generate_private_context**);

int
_hx509_generate_private_key_init (
	hx509_context,
	const heim_oid*,
	struct hx509_generate_private_context**);

int
_hx509_generate_private_key_is_ca (
	hx509_context,
	struct hx509_generate_private_context*);

Certificate*
_hx509_get_cert (hx509_cert);

void
_hx509_ks_dir_register (hx509_context);

void
_hx509_ks_file_register (hx509_context);

void
_hx509_ks_keychain_register (hx509_context);

void
_hx509_ks_mem_register (hx509_context);

void
_hx509_ks_null_register (hx509_context);

void
_hx509_ks_pkcs11_register (hx509_context);

void
_hx509_ks_pkcs12_register (hx509_context);

void
_hx509_ks_register (
	hx509_context,
	struct hx509_keyset_ops*);

int
_hx509_lock_find_cert (
	hx509_lock,
	const hx509_query*,
	hx509_cert*);

const struct _hx509_password*
_hx509_lock_get_passwords (hx509_lock);

hx509_certs
_hx509_lock_unlock_certs (hx509_lock);

struct hx_expr*
_hx509_make_expr (
	enum hx_expr_op,
	void*,
	void*);

int
_hx509_map_file_os (
	const char*,
	heim_octet_string*);

int
_hx509_match_keys (
	hx509_cert,
	hx509_private_key);

int
_hx509_name_cmp (
	const Name*,
	const Name*,
	int*);

int
_hx509_name_ds_cmp (
	const DirectoryString*,
	const DirectoryString*,
	int*);

int
_hx509_name_from_Name (
	const Name*,
	hx509_name*);

int
_hx509_name_modify (
	hx509_context,
	Name*,
	int,
	const heim_oid*,
	const char*);

int
_hx509_path_append (
	hx509_context,
	hx509_path*,
	hx509_cert);

void
_hx509_path_free (hx509_path*);

int
_hx509_pbe_decrypt (
	hx509_context,
	hx509_lock,
	const AlgorithmIdentifier*,
	const heim_octet_string*,
	heim_octet_string*);

int
_hx509_pbe_encrypt (
	hx509_context,
	hx509_lock,
	const AlgorithmIdentifier*,
	const heim_octet_string*,
	heim_octet_string*);

void
_hx509_pi_printf (
	int (*)(void*, const char*),
	void*,
	const char*,
	...);

void
_hx509_private_eckey_free (void*);

int
_hx509_private_key_export (
	hx509_context,
	const hx509_private_key,
	hx509_key_format_t,
	heim_octet_string*);

int
_hx509_private_key_exportable (hx509_private_key);

BIGNUM*
_hx509_private_key_get_internal (
	hx509_context,
	hx509_private_key,
	const char*);

int
_hx509_private_key_oid (
	hx509_context,
	const hx509_private_key,
	heim_oid*);

hx509_private_key
_hx509_private_key_ref (hx509_private_key);

const char*
_hx509_private_pem_name (hx509_private_key);

int
_hx509_public_encrypt (
	hx509_context,
	const heim_octet_string*,
	const Certificate*,
	heim_oid*,
	heim_octet_string*);

void
_hx509_query_clear (hx509_query*);

int
_hx509_query_match_cert (
	hx509_context,
	const hx509_query*,
	hx509_cert);

void
_hx509_query_statistic (
	hx509_context,
	int,
	const hx509_query*);

int
_hx509_request_add_dns_name (
	hx509_context,
	hx509_request,
	const char*);

int
_hx509_request_add_eku (
	hx509_context,
	hx509_request,
	const heim_oid*);

int
_hx509_request_add_email (
	hx509_context,
	hx509_request,
	const char*);

int
_hx509_request_parse (
	hx509_context,
	const char*,
	hx509_request*);

int
_hx509_request_print (
	hx509_context,
	hx509_request,
	FILE*);

int
_hx509_request_to_pkcs10 (
	hx509_context,
	const hx509_request,
	const hx509_private_key,
	heim_octet_string*);

hx509_revoke_ctx
_hx509_revoke_ref (hx509_revoke_ctx);

void
_hx509_sel_yyerror (const char*);

int
_hx509_self_signed_valid (
	hx509_context,
	const AlgorithmIdentifier*);

int
_hx509_set_cert_attribute (
	hx509_context,
	hx509_cert,
	const heim_oid*,
	const heim_octet_string*);

int
_hx509_set_digest_alg (
	DigestAlgorithmIdentifier*,
	const heim_oid*,
	const void*,
	size_t);

int
_hx509_signature_is_weak (
	hx509_context,
	const AlgorithmIdentifier*);

void
_hx509_unmap_file_os (heim_octet_string*);

int
_hx509_unparse_Name (
	const Name*,
	char**);

time_t
_hx509_verify_get_time (hx509_verify_ctx);

int
_hx509_verify_signature (
	hx509_context,
	const hx509_cert,
	const AlgorithmIdentifier*,
	const heim_octet_string*,
	const heim_octet_string*);

int
_hx509_verify_signature_bitstring (
	hx509_context,
	const hx509_cert,
	const AlgorithmIdentifier*,
	const heim_octet_string*,
	const heim_bit_string*);

int
_hx509_write_file (
	const char*,
	const void*,
	size_t);

#endif /* __hx509_private_h__ */
