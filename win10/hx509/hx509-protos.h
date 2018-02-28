/* This is a generated file */
#ifndef __hx509_protos_h__
#define __hx509_protos_h__
#ifndef DOXY

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HX509_LIB
#ifndef HX509_LIB_FUNCTION
#if defined(_WIN32)
#define HX509_LIB_FUNCTION __declspec(dllimport)
#define HX509_LIB_CALL __stdcall
#define HX509_LIB_VARIABLE __declspec(dllimport)
#else
#define HX509_LIB_FUNCTION
#define HX509_LIB_CALL
#define HX509_LIB_VARIABLE
#endif
#endif
#endif
/**
 * Print a bitstring using a hx509_vprint_func function. To print to
 * stdout use hx509_print_stdout().
 *
 * @param b bit string to print.
 * @param func hx509_vprint_func to print with.
 * @param ctx context variable to hx509_vprint_func function.
 *
 * @ingroup hx509_print
 */

void
hx509_bitstring_print (
	const heim_bit_string*,
	hx509_vprint_func,
	void*);

/**
 * Sign a to-be-signed certificate object with a issuer certificate.
 *
 * The caller needs to at least have called the following functions on the
 * to-be-signed certificate object:
 * - hx509_ca_tbs_init()
 * - hx509_ca_tbs_set_subject()
 * - hx509_ca_tbs_set_spki()
 *
 * When done the to-be-signed certificate object should be freed with
 * hx509_ca_tbs_free().
 *
 * When creating self-signed certificate use hx509_ca_sign_self() instead.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param signer the CA certificate object to sign with (need private key).
 * @param certificate return cerificate, free with hx509_cert_free().
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

int
hx509_ca_sign (
	hx509_context,
	hx509_ca_tbs,
	hx509_cert,
	hx509_cert*);

/**
 * Work just like hx509_ca_sign() but signs it-self.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param signer private key to sign with.
 * @param certificate return cerificate, free with hx509_cert_free().
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

int
hx509_ca_sign_self (
	hx509_context,
	hx509_ca_tbs,
	hx509_private_key,
	hx509_cert*);

/**
 * Add CRL distribution point URI to the to-be-signed certificate
 * object.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param uri uri to the CRL.
 * @param issuername name of the issuer.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

int
hx509_ca_tbs_add_crl_dp_uri (
	hx509_context,
	hx509_ca_tbs,
	const char*,
	hx509_name);

/**
 * An an extended key usage to the to-be-signed certificate object.
 * Duplicates will detected and not added.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param oid extended key usage to add.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

int
hx509_ca_tbs_add_eku (
	hx509_context,
	hx509_ca_tbs,
	const heim_oid*);

/**
 * Add a Subject Alternative Name hostname to to-be-signed certificate
 * object. A domain match starts with ., an exact match does not.
 *
 * Example of a an domain match: .domain.se matches the hostname
 * host.domain.se.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param dnsname a hostame.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

int
hx509_ca_tbs_add_san_hostname (
	hx509_context,
	hx509_ca_tbs,
	const char*);

/**
 * Add a Jabber/XMPP jid Subject Alternative Name to the to-be-signed
 * certificate object. The jid is an UTF8 string.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param jid string of an a jabber id in UTF8.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

int
hx509_ca_tbs_add_san_jid (
	hx509_context,
	hx509_ca_tbs,
	const char*);

/**
 * Add Microsoft UPN Subject Alternative Name to the to-be-signed
 * certificate object. The principal string is a UTF8 string.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param principal Microsoft UPN string.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

int
hx509_ca_tbs_add_san_ms_upn (
	hx509_context,
	hx509_ca_tbs,
	const char*);

/**
 * Add Subject Alternative Name otherName to the to-be-signed
 * certificate object.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param oid the oid of the OtherName.
 * @param os data in the other name.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

int
hx509_ca_tbs_add_san_otherName (
	hx509_context,
	hx509_ca_tbs,
	const heim_oid*,
	const heim_octet_string*);

/**
 * Add Kerberos Subject Alternative Name to the to-be-signed
 * certificate object. The principal string is a UTF8 string.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param principal Kerberos principal to add to the certificate.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

int
hx509_ca_tbs_add_san_pkinit (
	hx509_context,
	hx509_ca_tbs,
	const char*);

/**
 * Add a Subject Alternative Name rfc822 (email address) to
 * to-be-signed certificate object.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param rfc822Name a string to a email address.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

int
hx509_ca_tbs_add_san_rfc822name (
	hx509_context,
	hx509_ca_tbs,
	const char*);

/**
 * Free an To Be Signed object.
 *
 * @param tbs object to free.
 *
 * @ingroup hx509_ca
 */

void
hx509_ca_tbs_free (hx509_ca_tbs*);

/**
 * Allocate an to-be-signed certificate object that will be converted
 * into an certificate.
 *
 * @param context A hx509 context.
 * @param tbs returned to-be-signed certicate object, free with
 * hx509_ca_tbs_free().
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

int
hx509_ca_tbs_init (
	hx509_context,
	hx509_ca_tbs*);

/**
 * Make the to-be-signed certificate object a CA certificate. If the
 * pathLenConstraint is negative path length constraint is used.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param pathLenConstraint path length constraint, negative, no
 * constraint.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

int
hx509_ca_tbs_set_ca (
	hx509_context,
	hx509_ca_tbs,
	int);

/**
 * Make the to-be-signed certificate object a windows domain controller certificate.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

int
hx509_ca_tbs_set_domaincontroller (
	hx509_context,
	hx509_ca_tbs);

/**
 * Set the absolute time when the certificate is valid to.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param t time when the certificate will expire
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

int
hx509_ca_tbs_set_notAfter (
	hx509_context,
	hx509_ca_tbs,
	time_t);

/**
 * Set the relative time when the certificiate is going to expire.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param delta seconds to the certificate is going to expire.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

int
hx509_ca_tbs_set_notAfter_lifetime (
	hx509_context,
	hx509_ca_tbs,
	time_t);

/**
 * Set the absolute time when the certificate is valid from. If not
 * set the current time will be used.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param t time the certificated will start to be valid
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

int
hx509_ca_tbs_set_notBefore (
	hx509_context,
	hx509_ca_tbs,
	time_t);

/**
 * Make the to-be-signed certificate object a proxy certificate. If the
 * pathLenConstraint is negative path length constraint is used.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param pathLenConstraint path length constraint, negative, no
 * constraint.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

int
hx509_ca_tbs_set_proxy (
	hx509_context,
	hx509_ca_tbs,
	int);

/**
 * Set the serial number to use for to-be-signed certificate object.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param serialNumber serial number to use for the to-be-signed
 * certificate object.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

int
hx509_ca_tbs_set_serialnumber (
	hx509_context,
	hx509_ca_tbs,
	const heim_integer*);

/**
 * Set signature algorithm on the to be signed certificate
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param sigalg signature algorithm to use
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

int
hx509_ca_tbs_set_signature_algorithm (
	hx509_context,
	hx509_ca_tbs,
	const AlgorithmIdentifier*);

/**
 * Set the subject public key info (SPKI) in the to-be-signed certificate
 * object. SPKI is the public key and key related parameters in the
 * certificate.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param spki subject public key info to use for the to-be-signed certificate object.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

int
hx509_ca_tbs_set_spki (
	hx509_context,
	hx509_ca_tbs,
	const SubjectPublicKeyInfo*);

/**
 * Set the subject name of a to-be-signed certificate object.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param subject the name to set a subject.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

int
hx509_ca_tbs_set_subject (
	hx509_context,
	hx509_ca_tbs,
	hx509_name);

/**
 * Initialize the to-be-signed certificate object from a template certifiate.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param flags bit field selecting what to copy from the template
 * certifiate.
 * @param cert template certificate.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

int
hx509_ca_tbs_set_template (
	hx509_context,
	hx509_ca_tbs,
	int,
	hx509_cert);

/**
 * Set the issuerUniqueID and subjectUniqueID
 *
 * These are only supposed to be used considered with version 2
 * certificates, replaced by the two extensions SubjectKeyIdentifier
 * and IssuerKeyIdentifier. This function is to allow application
 * using legacy protocol to issue them.
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param issuerUniqueID to be set
 * @param subjectUniqueID to be set
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

int
hx509_ca_tbs_set_unique (
	hx509_context,
	hx509_ca_tbs,
	const heim_bit_string*,
	const heim_bit_string*);

/**
 * Expand the the subject name in the to-be-signed certificate object
 * using hx509_name_expand().
 *
 * @param context A hx509 context.
 * @param tbs object to be signed.
 * @param env environment variable to expand variables in the subject
 * name, see hx509_env_init().
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_ca
 */

int
hx509_ca_tbs_subject_expand (
	hx509_context,
	hx509_ca_tbs,
	hx509_env);

/**
 * Make of template units, use to build flags argument to
 * hx509_ca_tbs_set_template() with parse_units().
 *
 * @return an units structure.
 *
 * @ingroup hx509_ca
 */

const struct units*
hx509_ca_tbs_template_units (void);

/**
 * Encodes the hx509 certificate as a DER encode binary.
 *
 * @param context A hx509 context.
 * @param c the certificate to encode.
 * @param os the encode certificate, set to NULL, 0 on case of
 * error. Free the os->data with hx509_xfree().
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_cert
 */

int
hx509_cert_binary (
	hx509_context,
	hx509_cert,
	heim_octet_string*);

/**
 * Check the extended key usage on the hx509 certificate.
 *
 * @param context A hx509 context.
 * @param cert A hx509 context.
 * @param eku the EKU to check for
 * @param allow_any_eku if the any EKU is set, allow that to be a
 * substitute.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_cert
 */

int
hx509_cert_check_eku (
	hx509_context,
	hx509_cert,
	const heim_oid*,
	int);

/**
 * Compare to hx509 certificate object, useful for sorting.
 *
 * @param p a hx509 certificate object.
 * @param q a hx509 certificate object.
 *
 * @return 0 the objects are the same, returns > 0 is p is "larger"
 * then q, < 0 if p is "smaller" then q.
 *
 * @ingroup hx509_cert
 */

int
hx509_cert_cmp (
	hx509_cert,
	hx509_cert);

/**
 * Return a list of subjectAltNames specified by oid in the
 * certificate. On error the
 *
 * The returned list of octet string should be freed with
 * hx509_free_octet_string_list().
 *
 * @param context A hx509 context.
 * @param cert a hx509 certificate object.
 * @param oid an oid to for SubjectAltName.
 * @param list list of matching SubjectAltName.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_cert
 */

int
hx509_cert_find_subjectAltName_otherName (
	hx509_context,
	hx509_cert,
	const heim_oid*,
	hx509_octet_string_list*);

/**
 * Free reference to the hx509 certificate object, if the refcounter
 * reaches 0, the object if freed. Its allowed to pass in NULL.
 *
 * @param cert the cert to free.
 *
 * @ingroup hx509_cert
 */

void
hx509_cert_free (hx509_cert);

/**
 * Get the SubjectPublicKeyInfo structure from the hx509 certificate.
 *
 * @param context a hx509 context.
 * @param p a hx509 certificate object.
 * @param spki SubjectPublicKeyInfo, should be freed with
 * free_SubjectPublicKeyInfo().
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_cert
 */

int
hx509_cert_get_SPKI (
	hx509_context,
	hx509_cert,
	SubjectPublicKeyInfo*);

/**
 * Get the AlgorithmIdentifier from the hx509 certificate.
 *
 * @param context a hx509 context.
 * @param p a hx509 certificate object.
 * @param alg AlgorithmIdentifier, should be freed with
 *            free_AlgorithmIdentifier(). The algorithmidentifier is
 *            typicly rsaEncryption, or id-ecPublicKey, or some other
 *            public key mechanism.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_cert
 */

int
hx509_cert_get_SPKI_AlgorithmIdentifier (
	hx509_context,
	hx509_cert,
	AlgorithmIdentifier*);

/**
 * Get an external attribute for the certificate, examples are
 * friendly name and id.
 *
 * @param cert hx509 certificate object to search
 * @param oid an oid to search for.
 *
 * @return an hx509_cert_attribute, only valid as long as the
 * certificate is referenced.
 *
 * @ingroup hx509_cert
 */

hx509_cert_attribute
hx509_cert_get_attribute (
	hx509_cert,
	const heim_oid*);

/**
 * Return the name of the base subject of the hx509 certificate. If
 * the certiicate is a verified proxy certificate, the this function
 * return the base certificate (root of the proxy chain). If the proxy
 * certificate is not verified with the base certificate
 * HX509_PROXY_CERTIFICATE_NOT_CANONICALIZED is returned.
 *
 * @param context a hx509 context.
 * @param c a hx509 certificate object.
 * @param name a pointer to a hx509 name, should be freed by
 * hx509_name_free(). See also hx509_cert_get_subject().
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_cert
 */

int
hx509_cert_get_base_subject (
	hx509_context,
	hx509_cert,
	hx509_name*);

/**
 * Get friendly name of the certificate.
 *
 * @param cert cert to get the friendly name from.
 *
 * @return an friendly name or NULL if there is. The friendly name is
 * only valid as long as the certificate is referenced.
 *
 * @ingroup hx509_cert
 */

const char*
hx509_cert_get_friendly_name (hx509_cert);

/**
 * Return the name of the issuer of the hx509 certificate.
 *
 * @param p a hx509 certificate object.
 * @param name a pointer to a hx509 name, should be freed by
 * hx509_name_free().
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_cert
 */

int
hx509_cert_get_issuer (
	hx509_cert,
	hx509_name*);

/**
 * Get a copy of the Issuer Unique ID
 *
 * @param context a hx509_context
 * @param p a hx509 certificate
 * @param issuer the issuer id returned, free with der_free_bit_string()
 *
 * @return An hx509 error code, see hx509_get_error_string(). The
 * error code HX509_EXTENSION_NOT_FOUND is returned if the certificate
 * doesn't have a issuerUniqueID
 *
 * @ingroup hx509_cert
 */

int
hx509_cert_get_issuer_unique_id (
	hx509_context,
	hx509_cert,
	heim_bit_string*);

/**
 * Get notAfter time of the certificate.
 *
 * @param p a hx509 certificate object.
 *
 * @return return not after time.
 *
 * @ingroup hx509_cert
 */

time_t
hx509_cert_get_notAfter (hx509_cert);

/**
 * Get notBefore time of the certificate.
 *
 * @param p a hx509 certificate object.
 *
 * @return return not before time
 *
 * @ingroup hx509_cert
 */

time_t
hx509_cert_get_notBefore (hx509_cert);

/**
 * Get serial number of the certificate.
 *
 * @param p a hx509 certificate object.
 * @param i serial number, should be freed ith der_free_heim_integer().
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_cert
 */

int
hx509_cert_get_serialnumber (
	hx509_cert,
	heim_integer*);

/**
 * Return the name of the subject of the hx509 certificate.
 *
 * @param p a hx509 certificate object.
 * @param name a pointer to a hx509 name, should be freed by
 * hx509_name_free(). See also hx509_cert_get_base_subject().
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_cert
 */

int
hx509_cert_get_subject (
	hx509_cert,
	hx509_name*);

/**
 * Get a copy of the Subect Unique ID
 *
 * @param context a hx509_context
 * @param p a hx509 certificate
 * @param subject the subject id returned, free with der_free_bit_string()
 *
 * @return An hx509 error code, see hx509_get_error_string(). The
 * error code HX509_EXTENSION_NOT_FOUND is returned if the certificate
 * doesn't have a subjectUniqueID
 *
 * @ingroup hx509_cert
 */

int
hx509_cert_get_subject_unique_id (
	hx509_context,
	hx509_cert,
	heim_bit_string*);

int
hx509_cert_have_private_key (hx509_cert);

/**
 * Allocate and init an hx509 certificate object from the decoded
 * certificate `c´.
 *
 * @param context A hx509 context.
 * @param c
 * @param error
 *
 * @return Returns an hx509 certificate
 *
 * @ingroup hx509_cert
 */

hx509_cert
hx509_cert_init (
	hx509_context,
	const Certificate*,
	heim_error_t*);

/**
 * Just like hx509_cert_init(), but instead of a decode certificate
 * takes an pointer and length to a memory region that contains a
 * DER/BER encoded certificate.
 *
 * If the memory region doesn't contain just the certificate and
 * nothing more the function will fail with
 * HX509_EXTRA_DATA_AFTER_STRUCTURE.
 *
 * @param context A hx509 context.
 * @param ptr pointer to memory region containing encoded certificate.
 * @param len length of memory region.
 * @param error possibly returns an error
 *
 * @return An hx509 certificate
 *
 * @ingroup hx509_cert
 */

hx509_cert
hx509_cert_init_data (
	hx509_context,
	const void*,
	size_t,
	heim_error_t*);

/**
 * Print certificate usage for a certificate to a string.
 *
 * @param context A hx509 context.
 * @param c a certificate print the keyusage for.
 * @param s the return string with the keysage printed in to, free
 * with hx509_xfree().
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_print
 */

int
hx509_cert_keyusage_print (
	hx509_context,
	hx509_cert,
	char**);

int
hx509_cert_public_encrypt (
	hx509_context,
	const heim_octet_string*,
	const hx509_cert,
	heim_oid*,
	heim_octet_string*);

/**
 * Add a reference to a hx509 certificate object.
 *
 * @param cert a pointer to an hx509 certificate object.
 *
 * @return the same object as is passed in.
 *
 * @ingroup hx509_cert
 */

hx509_cert
hx509_cert_ref (hx509_cert);

/**
 * Set the friendly name on the certificate.
 *
 * @param cert The certificate to set the friendly name on
 * @param name Friendly name.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_cert
 */

int
hx509_cert_set_friendly_name (
	hx509_cert,
	const char*);

/**
 * Add a certificate to the certificiate store.
 *
 * The receiving keyset certs will either increase reference counter
 * of the cert or make a deep copy, either way, the caller needs to
 * free the cert itself.
 *
 * @param context a hx509 context.
 * @param certs certificate store to add the certificate to.
 * @param cert certificate to add.
 *
 * @return Returns an hx509 error code.
 *
 * @ingroup hx509_keyset
 */

int
hx509_certs_add (
	hx509_context,
	hx509_certs,
	hx509_cert);

/**
 * Same a hx509_certs_merge() but use a lock and name to describe the
 * from source.
 *
 * @param context a hx509 context.
 * @param to the store to merge into.
 * @param lock a lock that unlocks the certificates store, use NULL to
 * select no password/certifictes/prompt lock (see @ref page_lock).
 * @param name name of the source store
 *
 * @return Returns an hx509 error code.
 *
 * @ingroup hx509_keyset
 */

int
hx509_certs_append (
	hx509_context,
	hx509_certs,
	hx509_lock,
	const char*);

/**
 * End the iteration over certificates.
 *
 * @param context a hx509 context.
 * @param certs certificate store to iterate over.
 * @param cursor cursor that will keep track of progress, freed.
 *
 * @return Returns an hx509 error code.
 *
 * @ingroup hx509_keyset
 */

int
hx509_certs_end_seq (
	hx509_context,
	hx509_certs,
	hx509_cursor);

/**
 * Filter certificate matching the query.
 *
 * @param context a hx509 context.
 * @param certs certificate store to search.
 * @param q query allocated with @ref hx509_query functions.
 * @param result the filtered certificate store, caller must free with
 *        hx509_certs_free().
 *
 * @return Returns an hx509 error code.
 *
 * @ingroup hx509_keyset
 */

int
hx509_certs_filter (
	hx509_context,
	hx509_certs,
	const hx509_query*,
	hx509_certs*);

/**
 * Find a certificate matching the query.
 *
 * @param context a hx509 context.
 * @param certs certificate store to search.
 * @param q query allocated with @ref hx509_query functions.
 * @param r return certificate (or NULL on error), should be freed
 * with hx509_cert_free().
 *
 * @return Returns an hx509 error code.
 *
 * @ingroup hx509_keyset
 */

int
hx509_certs_find (
	hx509_context,
	hx509_certs,
	const hx509_query*,
	hx509_cert*);

/**
 * Free a certificate store.
 *
 * @param certs certificate store to free.
 *
 * @ingroup hx509_keyset
 */

void
hx509_certs_free (hx509_certs*);

/**
 * Print some info about the certificate store.
 *
 * @param context a hx509 context.
 * @param certs certificate store to print information about.
 * @param func function that will get each line of the information, if
 * NULL is used the data is printed on a FILE descriptor that should
 * be passed in ctx, if ctx also is NULL, stdout is used.
 * @param ctx parameter to func.
 *
 * @return Returns an hx509 error code.
 *
 * @ingroup hx509_keyset
 */

int
hx509_certs_info (
	hx509_context,
	hx509_certs,
	int (*)(void*, const char*),
	void*);

/**
 * Open or creates a new hx509 certificate store.
 *
 * @param context A hx509 context
 * @param name name of the store, format is TYPE:type-specific-string,
 * if NULL is used the MEMORY store is used.
 * @param flags list of flags:
 * - HX509_CERTS_CREATE create a new keystore of the specific TYPE.
 * - HX509_CERTS_UNPROTECT_ALL fails if any private key failed to be extracted.
 * @param lock a lock that unlocks the certificates store, use NULL to
 * select no password/certifictes/prompt lock (see @ref page_lock).
 * @param certs return pointer, free with hx509_certs_free().
 *
 * @return Returns an hx509 error code.
 *
 * @ingroup hx509_keyset
 */

int
hx509_certs_init (
	hx509_context,
	const char*,
	int,
	hx509_lock,
	hx509_certs*);

/**
 * Iterate over all certificates in a keystore and call a block
 * for each of them.
 *
 * @param context a hx509 context.
 * @param certs certificate store to iterate over.
 * @param func block to call for each certificate. The function
 * should return non-zero to abort the iteration, that value is passed
 * back to the caller of hx509_certs_iter().
 *
 * @return Returns an hx509 error code.
 *
 * @ingroup hx509_keyset
 */

#ifdef __BLOCKS__
int
hx509_certs_iter (
	hx509_context,
	hx509_certs,
	int (^func)(hx509_cert));
#endif /* __BLOCKS__ */

/**
 * Iterate over all certificates in a keystore and call a function
 * for each of them.
 *
 * @param context a hx509 context.
 * @param certs certificate store to iterate over.
 * @param func function to call for each certificate. The function
 * should return non-zero to abort the iteration, that value is passed
 * back to the caller of hx509_certs_iter_f().
 * @param ctx context variable that will passed to the function.
 *
 * @return Returns an hx509 error code.
 *
 * @ingroup hx509_keyset
 */

int
hx509_certs_iter_f (
	hx509_context,
	hx509_certs,
	int (*)(hx509_context, void*, hx509_cert),
	void*);

/**
 * Merge a certificate store into another. The from store is keep
 * intact.
 *
 * @param context a hx509 context.
 * @param to the store to merge into.
 * @param from the store to copy the object from.
 *
 * @return Returns an hx509 error code.
 *
 * @ingroup hx509_keyset
 */

int
hx509_certs_merge (
	hx509_context,
	hx509_certs,
	hx509_certs);

/**
 * Get next ceritificate from the certificate keystore pointed out by
 * cursor.
 *
 * @param context a hx509 context.
 * @param certs certificate store to iterate over.
 * @param cursor cursor that keeps track of progress.
 * @param cert return certificate next in store, NULL if the store
 * contains no more certificates. Free with hx509_cert_free().
 *
 * @return Returns an hx509 error code.
 *
 * @ingroup hx509_keyset
 */

int
hx509_certs_next_cert (
	hx509_context,
	hx509_certs,
	hx509_cursor,
	hx509_cert*);

hx509_certs
hx509_certs_ref (hx509_certs);

/**
 * Start the integration
 *
 * @param context a hx509 context.
 * @param certs certificate store to iterate over
 * @param cursor cursor that will keep track of progress, free with
 * hx509_certs_end_seq().
 *
 * @return Returns an hx509 error code. HX509_UNSUPPORTED_OPERATION is
 * returned if the certificate store doesn't support the iteration
 * operation.
 *
 * @ingroup hx509_keyset
 */

int
hx509_certs_start_seq (
	hx509_context,
	hx509_certs,
	hx509_cursor*);

/**
 * Write the certificate store to stable storage.
 *
 * @param context A hx509 context.
 * @param certs a certificate store to store.
 * @param flags currently unused, use 0.
 * @param lock a lock that unlocks the certificates store, use NULL to
 * select no password/certifictes/prompt lock (see @ref page_lock).
 *
 * @return Returns an hx509 error code. HX509_UNSUPPORTED_OPERATION if
 * the certificate store doesn't support the store operation.
 *
 * @ingroup hx509_keyset
 */

int
hx509_certs_store (
	hx509_context,
	hx509_certs,
	int,
	hx509_lock);

/**
 * Function to use to hx509_certs_iter_f() as a function argument, the
 * ctx variable to hx509_certs_iter_f() should be a FILE file descriptor.
 *
 * @param context a hx509 context.
 * @param ctx used by hx509_certs_iter_f().
 * @param c a certificate
 *
 * @return Returns an hx509 error code.
 *
 * @ingroup hx509_keyset
 */

int
hx509_ci_print_names (
	hx509_context,
	void*,
	hx509_cert);

/**
 * Resets the error strings the hx509 context.
 *
 * @param context A hx509 context.
 *
 * @ingroup hx509_error
 */

void
hx509_clear_error_string (hx509_context);

int
hx509_cms_create_signed (
	hx509_context,
	int,
	const heim_oid*,
	const void*,
	size_t,
	const AlgorithmIdentifier*,
	hx509_certs,
	hx509_peer_info,
	hx509_certs,
	hx509_certs,
	heim_octet_string*);

/**
 * Decode SignedData and verify that the signature is correct.
 *
 * @param context A hx509 context.
 * @param flags
 * @param eContentType the type of the data.
 * @param data data to sign
 * @param length length of the data that data point to.
 * @param digest_alg digest algorithm to use, use NULL to get the
 * default or the peer determined algorithm.
 * @param cert certificate to use for sign the data.
 * @param peer info about the peer the message to send the message to,
 * like what digest algorithm to use.
 * @param anchors trust anchors that the client will use, used to
 * polulate the certificates included in the message
 * @param pool certificates to use in try to build the path to the
 * trust anchors.
 * @param signed_data the output of the function, free with
 * der_free_octet_string().
 *
 * @return Returns an hx509 error code.
 *
 * @ingroup hx509_cms
 */

int
hx509_cms_create_signed_1 (
	hx509_context,
	int,
	const heim_oid*,
	const void*,
	size_t,
	const AlgorithmIdentifier*,
	hx509_cert,
	hx509_peer_info,
	hx509_certs,
	hx509_certs,
	heim_octet_string*);

/**
     * Use HX509_CMS_SIGNATURE_NO_SIGNER to create no sigInfo (no
     * signatures).
 */

int
hx509_cms_decrypt_encrypted (
	hx509_context,
	hx509_lock,
	const void*,
	size_t,
	heim_oid*,
	heim_octet_string*);

/**
 * Encrypt end encode EnvelopedData.
 *
 * Encrypt and encode EnvelopedData. The data is encrypted with a
 * random key and the the random key is encrypted with the
 * certificates private key. This limits what private key type can be
 * used to RSA.
 *
 * @param context A hx509 context.
 * @param flags flags to control the behavior.
 *    - HX509_CMS_EV_NO_KU_CHECK - Don't check KU on certificate
 *    - HX509_CMS_EV_ALLOW_WEAK - Allow weak crytpo
 *    - HX509_CMS_EV_ID_NAME - prefer issuer name and serial number
 * @param cert Certificate to encrypt the EnvelopedData encryption key
 * with.
 * @param data pointer the data to encrypt.
 * @param length length of the data that data point to.
 * @param encryption_type Encryption cipher to use for the bulk data,
 * use NULL to get default.
 * @param contentType type of the data that is encrypted
 * @param content the output of the function,
 * free with der_free_octet_string().
 *
 * @return an hx509 error code.
 *
 * @ingroup hx509_cms
 */

int
hx509_cms_envelope_1 (
	hx509_context,
	int,
	hx509_cert,
	const void*,
	size_t,
	const heim_oid*,
	const heim_oid*,
	heim_octet_string*);

/**
 * Decode and unencrypt EnvelopedData.
 *
 * Extract data and parameteres from from the EnvelopedData. Also
 * supports using detached EnvelopedData.
 *
 * @param context A hx509 context.
 * @param certs Certificate that can decrypt the EnvelopedData
 * encryption key.
 * @param flags HX509_CMS_UE flags to control the behavior.
 * @param data pointer the structure the contains the DER/BER encoded
 * EnvelopedData stucture.
 * @param length length of the data that data point to.
 * @param encryptedContent in case of detached signature, this
 * contains the actual encrypted data, othersize its should be NULL.
 * @param time_now set the current time, if zero the library uses now as the date.
 * @param contentType output type oid, should be freed with der_free_oid().
 * @param content the data, free with der_free_octet_string().
 *
 * @return an hx509 error code.
 *
 * @ingroup hx509_cms
 */

int
hx509_cms_unenvelope (
	hx509_context,
	hx509_certs,
	int,
	const void*,
	size_t,
	const heim_octet_string*,
	time_t,
	heim_oid*,
	heim_octet_string*);

/**
 * Decode an ContentInfo and unwrap data and oid it.
 *
 * @param in the encoded buffer.
 * @param oid type of the content.
 * @param out data to be wrapped.
 * @param have_data since the data is optional, this flags show dthe
 * diffrence between no data and the zero length data.
 *
 * @return Returns an hx509 error code.
 *
 * @ingroup hx509_cms
 */

int
hx509_cms_unwrap_ContentInfo (
	const heim_octet_string*,
	heim_oid*,
	heim_octet_string*,
	int*);

/**
 * Decode SignedData and verify that the signature is correct.
 *
 * @param context A hx509 context.
 * @param ctx a hx509 verify context.
 * @param flags to control the behaivor of the function.
 *    - HX509_CMS_VS_NO_KU_CHECK - Don't check KeyUsage
 *    - HX509_CMS_VS_ALLOW_DATA_OID_MISMATCH - allow oid mismatch
 *    - HX509_CMS_VS_ALLOW_ZERO_SIGNER - no signer, see below.
 * @param data pointer to CMS SignedData encoded data.
 * @param length length of the data that data point to.
 * @param signedContent external data used for signature.
 * @param pool certificate pool to build certificates paths.
 * @param contentType free with der_free_oid().
 * @param content the output of the function, free with
 * der_free_octet_string().
 * @param signer_certs list of the cerficates used to sign this
 * request, free with hx509_certs_free().
 *
 * @return an hx509 error code.
 *
 * @ingroup hx509_cms
 */

int
hx509_cms_verify_signed (
	hx509_context,
	hx509_verify_ctx,
	unsigned int,
	const void*,
	size_t,
	const heim_octet_string*,
	hx509_certs,
	heim_oid*,
	heim_octet_string*,
	hx509_certs*);

/**
 * Wrap data and oid in a ContentInfo and encode it.
 *
 * @param oid type of the content.
 * @param buf data to be wrapped. If a NULL pointer is passed in, the
 * optional content field in the ContentInfo is not going be filled
 * in.
 * @param res the encoded buffer, the result should be freed with
 * der_free_octet_string().
 *
 * @return Returns an hx509 error code.
 *
 * @ingroup hx509_cms
 */

int
hx509_cms_wrap_ContentInfo (
	const heim_oid*,
	const heim_octet_string*,
	heim_octet_string*);

/**
 * Free the context allocated by hx509_context_init().
 *
 * @param context context to be freed.
 *
 * @ingroup hx509
 */

void
hx509_context_free (hx509_context*);

/**
 * Creates a hx509 context that most functions in the library
 * uses. The context is only allowed to be used by one thread at each
 * moment. Free the context with hx509_context_free().
 *
 * @param context Returns a pointer to new hx509 context.
 *
 * @return Returns an hx509 error code.
 *
 * @ingroup hx509
 */

int
hx509_context_init (hx509_context*);

/**
 * Selects if the hx509_revoke_verify() function is going to require
 * the existans of a revokation method (OCSP, CRL) or not. Note that
 * hx509_verify_path(), hx509_cms_verify_signed(), and other function
 * call hx509_revoke_verify().
 *
 * @param context hx509 context to change the flag for.
 * @param flag zero, revokation method required, non zero missing
 * revokation method ok
 *
 * @ingroup hx509_verify
 */

void
hx509_context_set_missing_revoke (
	hx509_context,
	int);

/**
 * Add revoked certificate to an CRL context.
 *
 * @param context a hx509 context.
 * @param crl the CRL to add the revoked certificate to.
 * @param certs keyset of certificate to revoke.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_verify
 */

int
hx509_crl_add_revoked_certs (
	hx509_context,
	hx509_crl,
	hx509_certs);

/**
 * Create a CRL context. Use hx509_crl_free() to free the CRL context.
 *
 * @param context a hx509 context.
 * @param crl return pointer to a newly allocated CRL context.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_verify
 */

int
hx509_crl_alloc (
	hx509_context,
	hx509_crl*);

/**
 * Free a CRL context.
 *
 * @param context a hx509 context.
 * @param crl a CRL context to free.
 *
 * @ingroup hx509_verify
 */

void
hx509_crl_free (
	hx509_context,
	hx509_crl*);

/**
 * Set the lifetime of a CRL context.
 *
 * @param context a hx509 context.
 * @param crl a CRL context
 * @param delta delta time the certificate is valid, library adds the
 * current time to this.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_verify
 */

int
hx509_crl_lifetime (
	hx509_context,
	hx509_crl,
	int);

/**
 * Sign a CRL and return an encode certificate.
 *
 * @param context a hx509 context.
 * @param signer certificate to sign the CRL with
 * @param crl the CRL to sign
 * @param os return the signed and encoded CRL, free with
 * free_heim_octet_string()
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_verify
 */

int
hx509_crl_sign (
	hx509_context,
	hx509_cert,
	hx509_crl,
	heim_octet_string*);

const AlgorithmIdentifier*
hx509_crypto_aes128_cbc (void);

const AlgorithmIdentifier*
hx509_crypto_aes256_cbc (void);

void
hx509_crypto_allow_weak (hx509_crypto);

int
hx509_crypto_available (
	hx509_context,
	int,
	hx509_cert,
	AlgorithmIdentifier**,
	unsigned int*);

int
hx509_crypto_decrypt (
	hx509_crypto,
	const void*,
	const size_t,
	heim_octet_string*,
	heim_octet_string*);

const AlgorithmIdentifier*
hx509_crypto_des_rsdi_ede3_cbc (void);

void
hx509_crypto_destroy (hx509_crypto);

int
hx509_crypto_encrypt (
	hx509_crypto,
	const void*,
	const size_t,
	const heim_octet_string*,
	heim_octet_string**);

const heim_oid*
hx509_crypto_enctype_by_name (const char*);

void
hx509_crypto_free_algs (
	AlgorithmIdentifier*,
	unsigned int);

int
hx509_crypto_get_params (
	hx509_context,
	hx509_crypto,
	const heim_octet_string*,
	heim_octet_string*);

int
hx509_crypto_init (
	hx509_context,
	const char*,
	const heim_oid*,
	hx509_crypto*);

const char*
hx509_crypto_provider (hx509_crypto);

int
hx509_crypto_random_iv (
	hx509_crypto,
	heim_octet_string*);

int
hx509_crypto_select (
	const hx509_context,
	int,
	const hx509_private_key,
	hx509_peer_info,
	AlgorithmIdentifier*);

int
hx509_crypto_set_key_data (
	hx509_crypto,
	const void*,
	size_t);

int
hx509_crypto_set_key_name (
	hx509_crypto,
	const char*);

void
hx509_crypto_set_padding (
	hx509_crypto,
	int);

int
hx509_crypto_set_params (
	hx509_context,
	hx509_crypto,
	const heim_octet_string*,
	heim_octet_string*);

int
hx509_crypto_set_random_key (
	hx509_crypto,
	heim_octet_string*);

/**
 * Add a new key/value pair to the hx509_env.
 *
 * @param context A hx509 context.
 * @param env environment to add the environment variable too.
 * @param key key to add
 * @param value value to add
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_env
 */

int
hx509_env_add (
	hx509_context,
	hx509_env*,
	const char*,
	const char*);

/**
 * Add a new key/binding pair to the hx509_env.
 *
 * @param context A hx509 context.
 * @param env environment to add the environment variable too.
 * @param key key to add
 * @param list binding list to add
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_env
 */

int
hx509_env_add_binding (
	hx509_context,
	hx509_env*,
	const char*,
	hx509_env);

/**
 * Search the hx509_env for a key.
 *
 * @param context A hx509 context.
 * @param env environment to add the environment variable too.
 * @param key key to search for.
 *
 * @return the value if the key is found, NULL otherwise.
 *
 * @ingroup hx509_env
 */

const char*
hx509_env_find (
	hx509_context,
	hx509_env,
	const char*);

/**
 * Search the hx509_env for a binding.
 *
 * @param context A hx509 context.
 * @param env environment to add the environment variable too.
 * @param key key to search for.
 *
 * @return the binding if the key is found, NULL if not found.
 *
 * @ingroup hx509_env
 */

hx509_env
hx509_env_find_binding (
	hx509_context,
	hx509_env,
	const char*);

/**
 * Free an hx509_env environment context.
 *
 * @param env the environment to free.
 *
 * @ingroup hx509_env
 */

void
hx509_env_free (hx509_env*);

/**
 * Search the hx509_env for a length based key.
 *
 * @param context A hx509 context.
 * @param env environment to add the environment variable too.
 * @param key key to search for.
 * @param len length of key.
 *
 * @return the value if the key is found, NULL otherwise.
 *
 * @ingroup hx509_env
 */

const char*
hx509_env_lfind (
	hx509_context,
	hx509_env,
	const char*,
	size_t);

/**
 * Print error message and fatally exit from error code
 *
 * @param context A hx509 context.
 * @param exit_code exit() code from process.
 * @param error_code Error code for the reason to exit.
 * @param fmt format string with the exit message.
 * @param ... argument to format string.
 *
 * @ingroup hx509_error
 */

void
hx509_err (
	hx509_context,
	int,
	int,
	const char*,
	...);

hx509_private_key_ops*
hx509_find_private_alg (const heim_oid*);

/**
 * Free error string returned by hx509_get_error_string().
 *
 * @param str error string to free.
 *
 * @ingroup hx509_error
 */

void
hx509_free_error_string (char*);

/**
 * Free a list of octet strings returned by another hx509 library
 * function.
 *
 * @param list list to be freed.
 *
 * @ingroup hx509_misc
 */

void
hx509_free_octet_string_list (hx509_octet_string_list*);

/**
 * Unparse the hx509 name in name into a string.
 *
 * @param name the name to print
 * @param str an allocated string returns the name in string form
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_name
 */

int
hx509_general_name_unparse (
	GeneralName*,
	char**);

/**
 * Get an error string from context associated with error_code.
 *
 * @param context A hx509 context.
 * @param error_code Get error message for this error code.
 *
 * @return error string, free with hx509_free_error_string().
 *
 * @ingroup hx509_error
 */

char*
hx509_get_error_string (
	hx509_context,
	int);

/**
 * Get one random certificate from the certificate store.
 *
 * @param context a hx509 context.
 * @param certs a certificate store to get the certificate from.
 * @param c return certificate, should be freed with hx509_cert_free().
 *
 * @return Returns an hx509 error code.
 *
 * @ingroup hx509_keyset
 */

int
hx509_get_one_cert (
	hx509_context,
	hx509_certs,
	hx509_cert*);

int
hx509_lock_add_cert (
	hx509_context,
	hx509_lock,
	hx509_cert);

int
hx509_lock_add_certs (
	hx509_context,
	hx509_lock,
	hx509_certs);

int
hx509_lock_add_password (
	hx509_lock,
	const char*);

int
hx509_lock_command_string (
	hx509_lock,
	const char*);

void
hx509_lock_free (hx509_lock);

/**
 * @page page_lock Locking and unlocking certificates and encrypted data.
 *
 * See the library functions here: @ref hx509_lock
 */

int
hx509_lock_init (
	hx509_context,
	hx509_lock*);

int
hx509_lock_prompt (
	hx509_lock,
	hx509_prompt*);

void
hx509_lock_reset_certs (
	hx509_context,
	hx509_lock);

void
hx509_lock_reset_passwords (hx509_lock);

void
hx509_lock_reset_promper (hx509_lock);

int
hx509_lock_set_prompter (
	hx509_lock,
	hx509_prompter_fct,
	void*);

/**
 * Convert a hx509_name object to DER encoded name.
 *
 * @param name name to concert
 * @param os data to a DER encoded name, free the resulting octet
 * string with hx509_xfree(os->data).
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_name
 */

int
hx509_name_binary (
	const hx509_name,
	heim_octet_string*);

/**
 * Compare to hx509 name object, useful for sorting.
 *
 * @param n1 a hx509 name object.
 * @param n2 a hx509 name object.
 *
 * @return 0 the objects are the same, returns > 0 is n2 is "larger"
 * then n2, < 0 if n1 is "smaller" then n2.
 *
 * @ingroup hx509_name
 */

int
hx509_name_cmp (
	hx509_name,
	hx509_name);

/**
 * Copy a hx509 name object.
 *
 * @param context A hx509 cotext.
 * @param from the name to copy from
 * @param to the name to copy to
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_name
 */

int
hx509_name_copy (
	hx509_context,
	const hx509_name,
	hx509_name*);

/**
 * Expands variables in the name using env. Variables are on the form
 * ${name}. Useful when dealing with certificate templates.
 *
 * @param context A hx509 cotext.
 * @param name the name to expand.
 * @param env environment variable to expand.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_name
 */

int
hx509_name_expand (
	hx509_context,
	hx509_name,
	hx509_env);

/**
 * Free a hx509 name object, upond return *name will be NULL.
 *
 * @param name a hx509 name object to be freed.
 *
 * @ingroup hx509_name
 */

void
hx509_name_free (hx509_name*);

/**
 * Unparse the hx509 name in name into a string.
 *
 * @param name the name to check if its empty/null.
 *
 * @return non zero if the name is empty/null.
 *
 * @ingroup hx509_name
 */

int
hx509_name_is_null_p (const hx509_name);

int
hx509_name_normalize (
	hx509_context,
	hx509_name);

/**
 * Convert a hx509_name into a Name.
 *
 * @param from the name to copy from
 * @param to the name to copy to
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_name
 */

int
hx509_name_to_Name (
	const hx509_name,
	Name*);

/**
 * Convert the hx509 name object into a printable string.
 * The resulting string should be freed with free().
 *
 * @param name name to print
 * @param str the string to return
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_name
 */

int
hx509_name_to_string (
	const hx509_name,
	char**);

/**
 * Create an OCSP request for a set of certificates.
 *
 * @param context a hx509 context
 * @param reqcerts list of certificates to request ocsp data for
 * @param pool certificate pool to use when signing
 * @param signer certificate to use to sign the request
 * @param digest the signing algorithm in the request, if NULL use the
 * default signature algorithm,
 * @param request the encoded request, free with free_heim_octet_string().
 * @param nonce nonce in the request, free with free_heim_octet_string().
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_revoke
 */

int
hx509_ocsp_request (
	hx509_context,
	hx509_certs,
	hx509_certs,
	hx509_cert,
	const AlgorithmIdentifier*,
	heim_octet_string*,
	heim_octet_string*);

/**
 * Verify that the certificate is part of the OCSP reply and it's not
 * expired. Doesn't verify signature the OCSP reply or it's done by a
 * authorized sender, that is assumed to be already done.
 *
 * @param context a hx509 context
 * @param now the time right now, if 0, use the current time.
 * @param cert the certificate to verify
 * @param flags flags control the behavior
 * @param data pointer to the encode ocsp reply
 * @param length the length of the encode ocsp reply
 * @param expiration return the time the OCSP will expire and need to
 * be rechecked.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_verify
 */

int
hx509_ocsp_verify (
	hx509_context,
	time_t,
	hx509_cert,
	int,
	const void*,
	size_t,
	time_t*);

/**
 * Print a oid using a hx509_vprint_func function. To print to stdout
 * use hx509_print_stdout().
 *
 * @param oid oid to print
 * @param func hx509_vprint_func to print with.
 * @param ctx context variable to hx509_vprint_func function.
 *
 * @ingroup hx509_print
 */

void
hx509_oid_print (
	const heim_oid*,
	hx509_vprint_func,
	void*);

/**
 * Print a oid to a string.
 *
 * @param oid oid to print
 * @param str allocated string, free with hx509_xfree().
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_print
 */

int
hx509_oid_sprint (
	const heim_oid*,
	char**);

/**
 * Parse a string into a hx509 name object.
 *
 * @param context A hx509 context.
 * @param str a string to parse.
 * @param name the resulting object, NULL in case of error.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_name
 */

int
hx509_parse_name (
	hx509_context,
	const char*,
	hx509_name*);

int
hx509_parse_private_key (
	hx509_context,
	const AlgorithmIdentifier*,
	const void*,
	size_t,
	hx509_key_format_t,
	hx509_private_key*);

/**
 * Add an additional algorithm that the peer supports.
 *
 * @param context A hx509 context.
 * @param peer the peer to set the new algorithms for
 * @param val an AlgorithmsIdentier to add
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_peer
 */

int
hx509_peer_info_add_cms_alg (
	hx509_context,
	hx509_peer_info,
	const AlgorithmIdentifier*);

/**
 * Allocate a new peer info structure an init it to default values.
 *
 * @param context A hx509 context.
 * @param peer return an allocated peer, free with hx509_peer_info_free().
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_peer
 */

int
hx509_peer_info_alloc (
	hx509_context,
	hx509_peer_info*);

/**
 * Free a peer info structure.
 *
 * @param peer peer info to be freed.
 *
 * @ingroup hx509_peer
 */

void
hx509_peer_info_free (hx509_peer_info);

/**
 * Set the certificate that remote peer is using.
 *
 * @param peer peer info to update
 * @param cert cerificate of the remote peer.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_peer
 */

int
hx509_peer_info_set_cert (
	hx509_peer_info,
	hx509_cert);

/**
 * Set the algorithms that the peer supports.
 *
 * @param context A hx509 context.
 * @param peer the peer to set the new algorithms for
 * @param val array of supported AlgorithmsIdentiers
 * @param len length of array val.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_peer
 */

int
hx509_peer_info_set_cms_algs (
	hx509_context,
	hx509_peer_info,
	const AlgorithmIdentifier*,
	size_t);

int
hx509_pem_add_header (
	hx509_pem_header**,
	const char*,
	const char*);

const char*
hx509_pem_find_header (
	const hx509_pem_header*,
	const char*);

void
hx509_pem_free_header (hx509_pem_header*);

int
hx509_pem_read (
	hx509_context,
	FILE*,
	hx509_pem_read_func,
	void*);

int
hx509_pem_write (
	hx509_context,
	const char*,
	hx509_pem_header*,
	FILE*,
	const void*,
	size_t);

/**
 * Print a simple representation of a certificate
 *
 * @param context A hx509 context, can be NULL
 * @param cert certificate to print
 * @param out the stdio output stream, if NULL, stdout is used
 *
 * @return An hx509 error code
 *
 * @ingroup hx509_cert
 */

int
hx509_print_cert (
	hx509_context,
	hx509_cert,
	FILE*);

/**
 * Helper function to print on stdout for:
 * - hx509_oid_print(),
 * - hx509_bitstring_print(),
 * - hx509_validate_ctx_set_print().
 *
 * @param ctx the context to the print function. If the ctx is NULL,
 * stdout is used.
 * @param fmt the printing format.
 * @param va the argumet list.
 *
 * @ingroup hx509_print
 */

void
hx509_print_stdout (
	void*,
	const char*,
	va_list);

int
hx509_private_key2SPKI (
	hx509_context,
	hx509_private_key,
	SubjectPublicKeyInfo*);

void
hx509_private_key_assign_rsa (
	hx509_private_key,
	void*);

int
hx509_private_key_free (hx509_private_key*);

int
hx509_private_key_init (
	hx509_private_key*,
	hx509_private_key_ops*,
	void*);

int
hx509_private_key_private_decrypt (
	hx509_context,
	const heim_octet_string*,
	const heim_oid*,
	hx509_private_key,
	heim_octet_string*);

int
hx509_prompt_hidden (hx509_prompt_type);

/**
 * Allocate an query controller. Free using hx509_query_free().
 *
 * @param context A hx509 context.
 * @param q return pointer to a hx509_query.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_cert
 */

int
hx509_query_alloc (
	hx509_context,
	hx509_query**);

/**
 * Free the query controller.
 *
 * @param context A hx509 context.
 * @param q a pointer to the query controller.
 *
 * @ingroup hx509_cert
 */

void
hx509_query_free (
	hx509_context,
	hx509_query*);

/**
 * Set the query controller to match using a specific match function.
 *
 * @param q a hx509 query controller.
 * @param func function to use for matching, if the argument is NULL,
 * the match function is removed.
 * @param ctx context passed to the function.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_cert
 */

int
hx509_query_match_cmp_func (
	hx509_query*,
	int (*)(hx509_context, hx509_cert, void*),
	void*);

/**
 * Set the query controller to require an one specific EKU (extended
 * key usage). Any previous EKU matching is overwitten. If NULL is
 * passed in as the eku, the EKU requirement is reset.
 *
 * @param q a hx509 query controller.
 * @param eku an EKU to match on.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_cert
 */

int
hx509_query_match_eku (
	hx509_query*,
	const heim_oid*);

int
hx509_query_match_expr (
	hx509_context,
	hx509_query*,
	const char*);

/**
 * Set the query controller to match on a friendly name
 *
 * @param q a hx509 query controller.
 * @param name a friendly name to match on
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_cert
 */

int
hx509_query_match_friendly_name (
	hx509_query*,
	const char*);

/**
 * Set the issuer and serial number of match in the query
 * controller. The function make copies of the isser and serial number.
 *
 * @param q a hx509 query controller
 * @param issuer issuer to search for
 * @param serialNumber the serialNumber of the issuer.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_cert
 */

int
hx509_query_match_issuer_serial (
	hx509_query*,
	const Name*,
	const heim_integer*);

/**
 * Set match options for the hx509 query controller.
 *
 * @param q query controller.
 * @param option options to control the query controller.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_cert
 */

void
hx509_query_match_option (
	hx509_query*,
	hx509_query_option);

/**
 * Set a statistic file for the query statistics.
 *
 * @param context A hx509 context.
 * @param fn statistics file name
 *
 * @ingroup hx509_cert
 */

void
hx509_query_statistic_file (
	hx509_context,
	const char*);

/**
 * Unparse the statistics file and print the result on a FILE descriptor.
 *
 * @param context A hx509 context.
 * @param printtype tyep to print
 * @param out the FILE to write the data on.
 *
 * @ingroup hx509_cert
 */

void
hx509_query_unparse_stats (
	hx509_context,
	int,
	FILE*);

void
hx509_request_free (hx509_request*);

int
hx509_request_get_SubjectPublicKeyInfo (
	hx509_context,
	hx509_request,
	SubjectPublicKeyInfo*);

int
hx509_request_get_name (
	hx509_context,
	hx509_request,
	hx509_name*);

int
hx509_request_init (
	hx509_context,
	hx509_request*);

int
hx509_request_set_SubjectPublicKeyInfo (
	hx509_context,
	hx509_request,
	const SubjectPublicKeyInfo*);

int
hx509_request_set_name (
	hx509_context,
	hx509_request,
	hx509_name);

/**
 * Add a CRL file to the revokation context.
 *
 * @param context hx509 context
 * @param ctx hx509 revokation context
 * @param path path to file that is going to be added to the context.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_revoke
 */

int
hx509_revoke_add_crl (
	hx509_context,
	hx509_revoke_ctx,
	const char*);

/**
 * Add a OCSP file to the revokation context.
 *
 * @param context hx509 context
 * @param ctx hx509 revokation context
 * @param path path to file that is going to be added to the context.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_revoke
 */

int
hx509_revoke_add_ocsp (
	hx509_context,
	hx509_revoke_ctx,
	const char*);

/**
 * Free a hx509 revokation context.
 *
 * @param ctx context to be freed
 *
 * @ingroup hx509_revoke
 */

void
hx509_revoke_free (hx509_revoke_ctx*);

/**
 * Allocate a revokation context. Free with hx509_revoke_free().
 *
 * @param context A hx509 context.
 * @param ctx returns a newly allocated revokation context.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_revoke
 */

int
hx509_revoke_init (
	hx509_context,
	hx509_revoke_ctx*);

/**
 * Print the OCSP reply stored in a file.
 *
 * @param context a hx509 context
 * @param path path to a file with a OCSP reply
 * @param out the out FILE descriptor to print the reply on
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_revoke
 */

int
hx509_revoke_ocsp_print (
	hx509_context,
	const char*,
	FILE*);

int
hx509_revoke_print (
	hx509_context,
	hx509_revoke_ctx,
	FILE*);

/**
 * Check that a certificate is not expired according to a revokation
 * context. Also need the parent certificte to the check OCSP
 * parent identifier.
 *
 * @param context hx509 context
 * @param ctx hx509 revokation context
 * @param certs
 * @param now
 * @param cert
 * @param parent_cert
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_revoke
 */

int
hx509_revoke_verify (
	hx509_context,
	hx509_revoke_ctx,
	hx509_certs,
	time_t,
	hx509_cert,
	hx509_cert);

/**
 * See hx509_set_error_stringv().
 *
 * @param context A hx509 context.
 * @param flags
 * - HX509_ERROR_APPEND appends the error string to the old messages
     (code is updated).
 * @param code error code related to error message
 * @param fmt error message format
 * @param ... arguments to error message format
 *
 * @ingroup hx509_error
 */

void
hx509_set_error_string (
	hx509_context,
	int,
	int,
	const char*,
	...);

/**
 * Add an error message to the hx509 context.
 *
 * @param context A hx509 context.
 * @param flags
 * - HX509_ERROR_APPEND appends the error string to the old messages
     (code is updated).
 * @param code error code related to error message
 * @param fmt error message format
 * @param ap arguments to error message format
 *
 * @ingroup hx509_error
 */

void
hx509_set_error_stringv (
	hx509_context,
	int,
	int,
	const char*,
	va_list);

const AlgorithmIdentifier*
hx509_signature_ecPublicKey (void);

const AlgorithmIdentifier*
hx509_signature_ecdsa_with_sha256 (void);

const AlgorithmIdentifier*
hx509_signature_md5 (void);

const AlgorithmIdentifier*
hx509_signature_rsa (void);

const AlgorithmIdentifier*
hx509_signature_rsa_pkcs1_x509 (void);

const AlgorithmIdentifier*
hx509_signature_rsa_with_md5 (void);

const AlgorithmIdentifier*
hx509_signature_rsa_with_sha1 (void);

const AlgorithmIdentifier*
hx509_signature_rsa_with_sha256 (void);

const AlgorithmIdentifier*
hx509_signature_rsa_with_sha384 (void);

const AlgorithmIdentifier*
hx509_signature_rsa_with_sha512 (void);

const AlgorithmIdentifier*
hx509_signature_sha1 (void);

const AlgorithmIdentifier*
hx509_signature_sha256 (void);

const AlgorithmIdentifier*
hx509_signature_sha384 (void);

const AlgorithmIdentifier*
hx509_signature_sha512 (void);

/**
 * Convert a DER encoded name info a string.
 *
 * @param data data to a DER/BER encoded name
 * @param length length of data
 * @param str the resulting string, is NULL on failure.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_name
 */

int
hx509_unparse_der_name (
	const void*,
	size_t,
	char**);

/**
 * Validate/Print the status of the certificate.
 *
 * @param context A hx509 context.
 * @param ctx A hx509 validation context.
 * @param cert the cerificate to validate/print.

 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_print
 */

int
hx509_validate_cert (
	hx509_context,
	hx509_validate_ctx,
	hx509_cert);

/**
 * Add flags to control the behaivor of the hx509_validate_cert()
 * function.
 *
 * @param ctx A hx509 validation context.
 * @param flags flags to add to the validation context.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_print
 */

void
hx509_validate_ctx_add_flags (
	hx509_validate_ctx,
	int);

/**
 * Free an hx509 validate context.
 *
 * @param ctx the hx509 validate context to free.
 *
 * @ingroup hx509_print
 */

void
hx509_validate_ctx_free (hx509_validate_ctx);

/**
 * Allocate a hx509 validation/printing context.
 *
 * @param context A hx509 context.
 * @param ctx a new allocated hx509 validation context, free with
 * hx509_validate_ctx_free().

 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_print
 */

int
hx509_validate_ctx_init (
	hx509_context,
	hx509_validate_ctx*);

/**
 * Set the printing functions for the validation context.
 *
 * @param ctx a hx509 valication context.
 * @param func the printing function to usea.
 * @param c the context variable to the printing function.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_print
 */

void
hx509_validate_ctx_set_print (
	hx509_validate_ctx,
	hx509_vprint_func,
	void*);

/**
 * Set the trust anchors in the verification context, makes an
 * reference to the keyset, so the consumer can free the keyset
 * independent of the destruction of the verification context (ctx).
 * If there already is a keyset attached, it's released.
 *
 * @param ctx a verification context
 * @param set a keyset containing the trust anchors.
 *
 * @ingroup hx509_verify
 */

void
hx509_verify_attach_anchors (
	hx509_verify_ctx,
	hx509_certs);

/**
 * Attach an revocation context to the verfication context, , makes an
 * reference to the revoke context, so the consumer can free the
 * revoke context independent of the destruction of the verification
 * context. If there is no revoke context, the verification process is
 * NOT going to check any verification status.
 *
 * @param ctx a verification context.
 * @param revoke_ctx a revoke context.
 *
 * @ingroup hx509_verify
 */

void
hx509_verify_attach_revoke (
	hx509_verify_ctx,
	hx509_revoke_ctx);

void
hx509_verify_ctx_f_allow_best_before_signature_algs (
	hx509_context,
	int);

/**
 * Allow using the operating system builtin trust anchors if no other
 * trust anchors are configured.
 *
 * @param ctx a verification context
 * @param boolean if non zero, useing the operating systems builtin
 * trust anchors.
 *
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_cert
 */

void
hx509_verify_ctx_f_allow_default_trustanchors (
	hx509_verify_ctx,
	int);

/**
 * Free an hx509 verification context.
 *
 * @param ctx the context to be freed.
 *
 * @ingroup hx509_verify
 */

void
hx509_verify_destroy_ctx (hx509_verify_ctx);

/**
 * Verify that the certificate is allowed to be used for the hostname
 * and address.
 *
 * @param context A hx509 context.
 * @param cert the certificate to match with
 * @param flags Flags to modify the behavior:
 * - HX509_VHN_F_ALLOW_NO_MATCH no match is ok
 * @param type type of hostname:
 * - HX509_HN_HOSTNAME for plain hostname.
 * - HX509_HN_DNSSRV for DNS SRV names.
 * @param hostname the hostname to check
 * @param sa address of the host
 * @param sa_size length of address
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_cert
 */

int
hx509_verify_hostname (
	hx509_context,
	const hx509_cert,
	int,
	hx509_hostname_type,
	const char*,
	const struct sockaddr*,
	int);

/**
 * Allocate an verification context that is used fo control the
 * verification process.
 *
 * @param context A hx509 context.
 * @param ctx returns a pointer to a hx509_verify_ctx object.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_verify
 */

int
hx509_verify_init_ctx (
	hx509_context,
	hx509_verify_ctx*);

/**
 * Build and verify the path for the certificate to the trust anchor
 * specified in the verify context. The path is constructed from the
 * certificate, the pool and the trust anchors.
 *
 * @param context A hx509 context.
 * @param ctx A hx509 verification context.
 * @param cert the certificate to build the path from.
 * @param pool A keyset of certificates to build the chain from.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_verify
 */

int
hx509_verify_path (
	hx509_context,
	hx509_verify_ctx,
	hx509_cert,
	hx509_certs);

/**
 * Set the maximum depth of the certificate chain that the path
 * builder is going to try.
 *
 * @param ctx a verification context
 * @param max_depth maxium depth of the certificate chain, include
 * trust anchor.
 *
 * @ingroup hx509_verify
 */

void
hx509_verify_set_max_depth (
	hx509_verify_ctx,
	unsigned int);

/**
 * Allow or deny the use of proxy certificates
 *
 * @param ctx a verification context
 * @param boolean if non zero, allow proxy certificates.
 *
 * @ingroup hx509_verify
 */

void
hx509_verify_set_proxy_certificate (
	hx509_verify_ctx,
	int);

/**
 * Select strict RFC3280 verification of certificiates. This means
 * checking key usage on CA certificates, this will make version 1
 * certificiates unuseable.
 *
 * @param ctx a verification context
 * @param boolean if non zero, use strict verification.
 *
 * @ingroup hx509_verify
 */

void
hx509_verify_set_strict_rfc3280_verification (
	hx509_verify_ctx,
	int);

/**
 * Set the clock time the the verification process is going to
 * use. Used to check certificate in the past and future time. If not
 * set the current time will be used.
 *
 * @param ctx a verification context.
 * @param t the time the verifiation is using.
 *
 *
 * @ingroup hx509_verify
 */

void
hx509_verify_set_time (
	hx509_verify_ctx,
	time_t);

/**
 * Verify a signature made using the private key of an certificate.
 *
 * @param context A hx509 context.
 * @param signer the certificate that made the signature.
 * @param alg algorthm that was used to sign the data.
 * @param data the data that was signed.
 * @param sig the sigature to verify.
 *
 * @return An hx509 error code, see hx509_get_error_string().
 *
 * @ingroup hx509_crypto
 */

int
hx509_verify_signature (
	hx509_context,
	const hx509_cert,
	const AlgorithmIdentifier*,
	const heim_octet_string*,
	const heim_octet_string*);

/**
 * Free a data element allocated in the library.
 *
 * @param ptr data to be freed.
 *
 * @ingroup hx509_misc
 */

void
hx509_xfree (void*);

int
yywrap (void);

#ifdef __cplusplus
}
#endif

#endif /* DOXY */
#endif /* __hx509_protos_h__ */
