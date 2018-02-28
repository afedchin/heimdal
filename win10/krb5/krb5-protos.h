/* This is a generated file */
#ifndef __krb5_protos_h__
#define __krb5_protos_h__
#ifndef DOXY

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


#ifdef __cplusplus
extern "C" {
#endif

#ifndef KRB5_LIB
#ifndef KRB5_LIB_FUNCTION
#if defined(_WIN32)
#define KRB5_LIB_FUNCTION __declspec(dllimport)
#define KRB5_LIB_CALL __stdcall
#define KRB5_LIB_VARIABLE __declspec(dllimport)
#else
#define KRB5_LIB_FUNCTION
#define KRB5_LIB_CALL
#define KRB5_LIB_VARIABLE
#endif
#endif
#endif
/**
 * Log a warning to the log, default stderr, include the error from
 * the last failure and then abort.
 *
 * @param context A Kerberos 5 context
 * @param code error code of the last error
 * @param fmt message to print
 * @param ... arguments for format string
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_abort (
	krb5_context,
	krb5_error_code,
	const char*,
	...)
     __attribute__ ((__noreturn__, __format__ (__printf__, 3, 4)));

/**
 * Log a warning to the log, default stderr, and then abort.
 *
 * @param context A Kerberos 5 context
 * @param fmt printf format string of message to print
 * @param ... arguments for format string
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_abortx (
	krb5_context,
	const char*,
	...)
     __attribute__ ((__noreturn__, __format__ (__printf__, 2, 3)));

/**
 * krb5_acl_match_file matches ACL format against each line in a file
 * using krb5_acl_match_string(). Lines starting with # are treated
 * like comments and ignored.
 *
 * @param context Kerberos 5 context.
 * @param file file with acl listed in the file.
 * @param format format to match.
 * @param ... parameter to format string.
 *
 * @return Return an error code or 0.
 *
 * @sa krb5_acl_match_string
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_acl_match_file (
	krb5_context,
	const char*,
	const char*,
	...);

/**
 * krb5_acl_match_string matches ACL format against a string.
 *
 * The ACL format has three format specifiers: s, f, and r.  Each
 * specifier will retrieve one argument from the variable arguments
 * for either matching or storing data.  The input string is split up
 * using " " (space) and "\t" (tab) as a delimiter; multiple and "\t"
 * in a row are considered to be the same.
 *
 * List of format specifiers:
 * - s Matches a string using strcmp(3) (case sensitive).
 * - f Matches the string with fnmatch(3). Theflags
 *     argument (the last argument) passed to the fnmatch function is 0.
 * - r Returns a copy of the string in the char ** passed in; the copy
 *     must be freed with free(3). There is no need to free(3) the
 *     string on error: the function will clean up and set the pointer
 *     to NULL.
 *
 * @param context Kerberos 5 context
 * @param string string to match with
 * @param format format to match
 * @param ... parameter to format string
 *
 * @return Return an error code or 0.
 *
 *
 * @code
 * char *s;
 *
 * ret = krb5_acl_match_string(context, "foo", "s", "foo");
 * if (ret)
 *     krb5_errx(context, 1, "acl didn't match");
 * ret = krb5_acl_match_string(context, "foo foo baz/kaka",
 *     "ss", "foo", &s, "foo/\\*");
 * if (ret) {
 *     // no need to free(s) on error
 *     assert(s == NULL);
 *     krb5_errx(context, 1, "acl didn't match");
 * }
 * free(s);
 * @endcode
 *
 * @sa krb5_acl_match_file
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_acl_match_string (
	krb5_context,
	const char*,
	const char*,
	...);

/**
 * Add a specified list of error messages to the et list in context.
 * Call func (probably a comerr-generated function) with a pointer to
 * the current et_list.
 *
 * @param context A kerberos context.
 * @param func The generated com_err et function.
 *
 * @return Returns 0 to indicate success.  Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_add_et_list (
	krb5_context,
	void (*)(struct et_list**));

/**
 * Add extra address to the address list that the library will add to
 * the client's address list when communicating with the KDC.
 *
 * @param context Kerberos 5 context.
 * @param addresses addreses to add
 *
 * @return Returns 0 to indicate success. Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_add_extra_addresses (
	krb5_context,
	krb5_addresses*);

/**
 * Add extra addresses to ignore when fetching addresses from the
 * underlaying operating system.
 *
 * @param context Kerberos 5 context.
 * @param addresses addreses to ignore
 *
 * @return Returns 0 to indicate success. Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_add_ignore_addresses (
	krb5_context,
	krb5_addresses*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_addlog_dest (
	krb5_context,
	krb5_log_facility*,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_addlog_func (
	krb5_context,
	krb5_log_facility*,
	int,
	int,
	krb5_log_log_func_t,
	krb5_log_close_func_t,
	void*);

/**
 * krb5_addr2sockaddr sets the "struct sockaddr sockaddr" from addr
 * and port. The argument sa_size should initially contain the size of
 * the sa and after the call, it will contain the actual length of the
 * address. In case of the sa is too small to fit the whole address,
 * the up to *sa_size will be stored, and then *sa_size will be set to
 * the required length.
 *
 * @param context a Keberos context
 * @param addr the address to copy the from
 * @param sa the struct sockaddr that will be filled in
 * @param sa_size pointer to length of sa, and after the call, it will
 * contain the actual length of the address.
 * @param port set port in sa.
 *
 * @return Return an error code or 0. Will return
 * KRB5_PROG_ATYPE_NOSUPP in case address type is not supported.
 *
 * @ingroup krb5_address
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_addr2sockaddr (
	krb5_context,
	const krb5_address*,
	struct sockaddr*,
	krb5_socklen_t*,
	int);

/**
 * krb5_address_compare compares the addresses  addr1 and addr2.
 * Returns TRUE if the two addresses are the same.
 *
 * @param context a Keberos context
 * @param addr1 address to compare
 * @param addr2 address to compare
 *
 * @return Return an TRUE is the address are the same FALSE if not
 *
 * @ingroup krb5_address
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_address_compare (
	krb5_context,
	const krb5_address*,
	const krb5_address*);

/**
 * krb5_address_order compares the addresses addr1 and addr2 so that
 * it can be used for sorting addresses. If the addresses are the same
 * address krb5_address_order will return 0. Behavies like memcmp(2).
 *
 * @param context a Keberos context
 * @param addr1 krb5_address to compare
 * @param addr2 krb5_address to compare
 *
 * @return < 0 if address addr1 in "less" then addr2. 0 if addr1 and
 * addr2 is the same address, > 0 if addr2 is "less" then addr1.
 *
 * @ingroup krb5_address
 */

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_address_order (
	krb5_context,
	const krb5_address*,
	const krb5_address*);

/**
 * Calculate the boundary addresses of `inaddr'/`prefixlen' and store
 * them in `low' and `high'.
 *
 * @param context a Keberos context
 * @param inaddr address in prefixlen that the bondery searched
 * @param prefixlen width of boundery
 * @param low lowest address
 * @param high highest address
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_address
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_address_prefixlen_boundary (
	krb5_context,
	const krb5_address*,
	unsigned long,
	krb5_address*,
	krb5_address*);

/**
 * krb5_address_search checks if the address addr is a member of the
 * address set list addrlist .
 *
 * @param context a Keberos context.
 * @param addr address to search for.
 * @param addrlist list of addresses to look in for addr.
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_address
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_address_search (
	krb5_context,
	const krb5_address*,
	const krb5_addresses*);

/**
 * Enable or disable all weak encryption types
 *
 * @param context Kerberos 5 context
 * @param enable true to enable, false to disable
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_crypto
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_allow_weak_crypto (
	krb5_context,
	krb5_boolean);

/**
 * Map a principal name to a local username.
 *
 * Returns 0 on success, KRB5_NO_LOCALNAME if no mapping was found, or
 * some Kerberos or system error.
 *
 * Inputs:
 *
 * @param context    A krb5_context
 * @param aname      A principal name
 * @param lnsize     The size of the buffer into which the username will be written
 * @param lname      The buffer into which the username will be written
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_aname_to_localname (
	krb5_context,
	krb5_const_principal,
	size_t,
	char*);

/**
 * krb5_anyaddr fills in a "struct sockaddr sa" that can be used to
 * bind(2) to.  The argument sa_size should initially contain the size
 * of the sa, and after the call, it will contain the actual length
 * of the address.
 *
 * @param context a Keberos context
 * @param af address family
 * @param sa sockaddr
 * @param sa_size lenght of sa.
 * @param port for to fill into sa.
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_address
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_anyaddr (
	krb5_context,
	int,
	struct sockaddr*,
	krb5_socklen_t*,
	int);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_appdefault_boolean (
	krb5_context,
	const char*,
	krb5_const_realm,
	const char*,
	krb5_boolean,
	krb5_boolean*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_appdefault_string (
	krb5_context,
	const char*,
	krb5_const_realm,
	const char*,
	const char*,
	char**);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_appdefault_time (
	krb5_context,
	const char*,
	krb5_const_realm,
	const char*,
	time_t,
	time_t*);

/**
 * krb5_append_addresses adds the set of addresses in source to
 * dest. While copying the addresses, duplicates are also sorted out.
 *
 * @param context a Keberos context
 * @param dest destination of copy operation
 * @param source adresses that are going to be added to dest
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_address
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_append_addresses (
	krb5_context,
	krb5_addresses*,
	const krb5_addresses*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_add_AuthorizationData (
	krb5_context,
	krb5_auth_context,
	int,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_addflags (
	krb5_context,
	krb5_auth_context,
	int32_t,
	int32_t*);

/**
 * Deallocate an authentication context previously initialized with
 * krb5_auth_con_init().
 *
 * @param context      A kerberos context.
 * @param auth_context The authentication context to be deallocated.
 *
 * @return An krb5 error code, see krb5_get_error_message().
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_free (
	krb5_context,
	krb5_auth_context);

/**
 * Update the authentication context \a auth_context with the local
 * and remote addresses from socket \a fd, according to \a flags.
 *
 * @return An krb5 error code, see krb5_get_error_message().
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_genaddrs (
	krb5_context,
	krb5_auth_context,
	krb5_socket_t,
	int);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_generatelocalsubkey (
	krb5_context,
	krb5_auth_context,
	krb5_keyblock*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_getaddrs (
	krb5_context,
	krb5_auth_context,
	krb5_address**,
	krb5_address**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_getauthenticator (
	krb5_context,
	krb5_auth_context,
	krb5_authenticator*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_getcksumtype (
	krb5_context,
	krb5_auth_context,
	krb5_cksumtype*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_getflags (
	krb5_context,
	krb5_auth_context,
	int32_t*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_getkey (
	krb5_context,
	krb5_auth_context,
	krb5_keyblock**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_getkeytype (
	krb5_context,
	krb5_auth_context,
	krb5_keytype*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_getlocalseqnumber (
	krb5_context,
	krb5_auth_context,
	int32_t*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_getlocalsubkey (
	krb5_context,
	krb5_auth_context,
	krb5_keyblock**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_getrcache (
	krb5_context,
	krb5_auth_context,
	krb5_rcache*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_getrecvsubkey (
	krb5_context,
	krb5_auth_context,
	krb5_keyblock**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_getremoteseqnumber (
	krb5_context,
	krb5_auth_context,
	int32_t*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_getremotesubkey (
	krb5_context,
	krb5_auth_context,
	krb5_keyblock**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_getsendsubkey (
	krb5_context,
	krb5_auth_context,
	krb5_keyblock**);

/**
 * Allocate and initialize an autentication context.
 *
 * @param context      A kerberos context.
 * @param auth_context The authentication context to be initialized.
 *
 * Use krb5_auth_con_free() to release the memory when done using the context.
 *
 * @return An krb5 error code, see krb5_get_error_message().
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_init (
	krb5_context,
	krb5_auth_context*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_removeflags (
	krb5_context,
	krb5_auth_context,
	int32_t,
	int32_t*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_setaddrs (
	krb5_context,
	krb5_auth_context,
	krb5_address*,
	krb5_address*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_setaddrs_from_fd (
	krb5_context,
	krb5_auth_context,
	void*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_setcksumtype (
	krb5_context,
	krb5_auth_context,
	krb5_cksumtype);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_setflags (
	krb5_context,
	krb5_auth_context,
	int32_t);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_setkey (
	krb5_context,
	krb5_auth_context,
	krb5_keyblock*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_setkeytype (
	krb5_context,
	krb5_auth_context,
	krb5_keytype);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_setlocalseqnumber (
	krb5_context,
	krb5_auth_context,
	int32_t);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_setlocalsubkey (
	krb5_context,
	krb5_auth_context,
	krb5_keyblock*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_setrcache (
	krb5_context,
	krb5_auth_context,
	krb5_rcache);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_setrecvsubkey (
	krb5_context,
	krb5_auth_context,
	krb5_keyblock*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_setremoteseqnumber (
	krb5_context,
	krb5_auth_context,
	int32_t);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_setremotesubkey (
	krb5_context,
	krb5_auth_context,
	krb5_keyblock*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_setsendsubkey (
	krb5_context,
	krb5_auth_context,
	krb5_keyblock*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_con_setuserkey (
	krb5_context,
	krb5_auth_context,
	krb5_keyblock*);

/**
 * Deprecated: use krb5_auth_con_getremoteseqnumber()
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_auth_getremoteseqnumber (
	krb5_context,
	krb5_auth_context,
	int32_t*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_build_ap_req (
	krb5_context,
	krb5_enctype,
	krb5_creds*,
	krb5_flags,
	krb5_data,
	krb5_data*);

/**
 * Build a principal using vararg style building
 *
 * @param context A Kerberos context.
 * @param principal returned principal
 * @param rlen length of realm
 * @param realm realm name
 * @param ... a list of components ended with NULL.
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_build_principal (
	krb5_context,
	krb5_principal*,
	int,
	krb5_const_realm,
	...);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_build_principal_ext (
	krb5_context,
	krb5_principal*,
	int,
	krb5_const_realm,
	...);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_build_principal_va (
	krb5_context,
	krb5_principal*,
	int,
	krb5_const_realm,
	va_list);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_build_principal_va_ext (
	krb5_context,
	krb5_principal*,
	int,
	krb5_const_realm,
	va_list);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_c_block_size (
	krb5_context,
	krb5_enctype,
	size_t*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_c_checksum_length (
	krb5_context,
	krb5_cksumtype,
	size_t*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_c_decrypt (
	krb5_context,
	const krb5_keyblock,
	krb5_keyusage,
	const krb5_data*,
	krb5_enc_data*,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_c_encrypt (
	krb5_context,
	const krb5_keyblock*,
	krb5_keyusage,
	const krb5_data*,
	const krb5_data*,
	krb5_enc_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_c_encrypt_length (
	krb5_context,
	krb5_enctype,
	size_t,
	size_t*);

/**
 * Deprecated: keytypes doesn't exists, they are really enctypes.
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_c_enctype_compare (
	krb5_context,
	krb5_enctype,
	krb5_enctype,
	krb5_boolean*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_c_get_checksum (
	krb5_context,
	const krb5_checksum*,
	krb5_cksumtype*,
	krb5_data**);

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_c_is_coll_proof_cksum (krb5_cksumtype);

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_c_is_keyed_cksum (krb5_cksumtype);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_c_keylengths (
	krb5_context,
	krb5_enctype,
	size_t*,
	size_t*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_c_make_checksum (
	krb5_context,
	krb5_cksumtype,
	const krb5_keyblock*,
	krb5_keyusage,
	const krb5_data*,
	krb5_checksum*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_c_make_random_key (
	krb5_context,
	krb5_enctype,
	krb5_keyblock*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_c_prf (
	krb5_context,
	const krb5_keyblock*,
	const krb5_data*,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_c_prf_length (
	krb5_context,
	krb5_enctype,
	size_t*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_c_random_make_octets (
	krb5_context,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_c_set_checksum (
	krb5_context,
	krb5_checksum*,
	krb5_cksumtype,
	const krb5_data*);

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_c_valid_cksumtype (krb5_cksumtype);

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_c_valid_enctype (krb5_enctype);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_c_verify_checksum (
	krb5_context,
	const krb5_keyblock*,
	krb5_keyusage,
	const krb5_data*,
	const krb5_checksum*,
	krb5_boolean*);

/**
 * Destroy the cursor `cursor'.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_cache_end_seq_get (
	krb5_context,
	krb5_cc_cache_cursor);

/**
 * Start iterating over all caches of specified type. See also
 * krb5_cccol_cursor_new().

 * @param context A Kerberos 5 context
 * @param type optional type to iterate over, if NULL, the default cache is used.
 * @param cursor cursor should be freed with krb5_cc_cache_end_seq_get().
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_cache_get_first (
	krb5_context,
	const char*,
	krb5_cc_cache_cursor*);

/**
 * Search for a matching credential cache that have the
 * `principal' as the default principal. On success, `id' needs to be
 * freed with krb5_cc_close() or krb5_cc_destroy().
 *
 * @param context A Kerberos 5 context
 * @param client The principal to search for
 * @param id the returned credential cache
 *
 * @return On failure, error code is returned and `id' is set to NULL.
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_cache_match (
	krb5_context,
	krb5_principal,
	krb5_ccache*);

/**
 * Retrieve the next cache pointed to by (`cursor') in `id'
 * and advance `cursor'.
 *
 * @param context A Kerberos 5 context
 * @param cursor the iterator cursor, returned by krb5_cc_cache_get_first()
 * @param id next ccache
 *
 * @return Return 0 or an error code. Returns KRB5_CC_END when the end
 *         of caches is reached, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_cache_next (
	krb5_context,
	krb5_cc_cache_cursor,
	krb5_ccache*);

/**
 * Clear `mcreds' so it can be used with krb5_cc_retrieve_cred
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_cc_clear_mcred (krb5_creds*);

/**
 * Stop using the ccache `id' and free the related resources.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_close (
	krb5_context,
	krb5_ccache);

/**
 * Just like krb5_cc_copy_match_f(), but copy everything.
 *
 * @ingroup @krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_copy_cache (
	krb5_context,
	const krb5_ccache,
	krb5_ccache);

/**
 * MIT compat glue
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_copy_creds (
	krb5_context,
	const krb5_ccache,
	krb5_ccache);

/**
 * Copy the contents of `from' to `to' if the given match function
 * return true.
 *
 * @param context A Kerberos 5 context.
 * @param from the cache to copy data from.
 * @param to the cache to copy data to.
 * @param match a match function that should return TRUE if cred argument should be copied, if NULL, all credentials are copied.
 * @param matchctx context passed to match function.
 * @param matched set to true if there was a credential that matched, may be NULL.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_copy_match_f (
	krb5_context,
	const krb5_ccache,
	krb5_ccache,
	krb5_boolean (*)(krb5_context, void*, const krb5_creds*),
	void*,
	unsigned int*);

/**
 * Open the default ccache in `id'.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_default (
	krb5_context,
	krb5_ccache*);

/**
 * Return a pointer to a context static string containing the default
 * ccache name.
 *
 * @return String to the default credential cache name.
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_cc_default_name (krb5_context);

/**
 * Remove the ccache `id'.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_destroy (
	krb5_context,
	krb5_ccache);

/**
 * Destroy the cursor `cursor'.
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_end_seq_get (
	krb5_context,
	const krb5_ccache,
	krb5_cc_cursor*);

/**
 * Generate a new ccache of type `ops' in `id'.
 *
 * Deprecated: use krb5_cc_new_unique() instead.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_gen_new (
	krb5_context,
	const krb5_cc_ops*,
	krb5_ccache*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

/**
 * Get some configuration for the credential cache in the cache.
 *
 * @param context a Keberos context
 * @param id the credential cache to store the data for
 * @param principal configuration for a specific principal, if
 * NULL, global for the whole cache.
 * @param name name under which the configuraion is stored.
 * @param data data to fetched, free with krb5_data_free()
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_get_config (
	krb5_context,
	krb5_ccache,
	krb5_const_principal,
	const char*,
	krb5_data*);

/**
 * Get the flags of `id', store them in `flags'.
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_get_flags (
	krb5_context,
	krb5_ccache,
	krb5_flags*);

/**
 * Return a friendly name on credential cache. Free the result with krb5_xfree().
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_get_friendly_name (
	krb5_context,
	krb5_ccache,
	char**);

/**
 * Return the complete resolvable name the cache

 * @param context a Keberos context
 * @param id return pointer to a found credential cache
 * @param str the returned name of a credential cache, free with krb5_xfree()
 *
 * @return Returns 0 or an error (and then *str is set to NULL).
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_get_full_name (
	krb5_context,
	krb5_ccache,
	char**);

/**
 * Get the time offset betwen the client and the KDC
 *
 * If the backend doesn't support KDC offset, use the context global setting.
 *
 * @param context A Kerberos 5 context.
 * @param id a credential cache
 * @param offset the offset in seconds
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_get_kdc_offset (
	krb5_context,
	krb5_ccache,
	krb5_deltat*);

/**
 * Get the lifetime of the initial ticket in the cache
 *
 * Get the lifetime of the initial ticket in the cache, if the initial
 * ticket was not found, the error code KRB5_CC_END is returned.
 *
 * @param context A Kerberos 5 context.
 * @param id a credential cache
 * @param t the relative lifetime of the initial ticket
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_get_lifetime (
	krb5_context,
	krb5_ccache,
	time_t*);

/**
 * Return the name of the ccache `id'
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_cc_get_name (
	krb5_context,
	krb5_ccache);

/**
 * Return krb5_cc_ops of a the ccache `id'.
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION const krb5_cc_ops* KRB5_LIB_CALL
krb5_cc_get_ops (
	krb5_context,
	krb5_ccache);

/**
 * Get the cc ops that is registered in `context' to handle the
 * prefix. prefix can be a complete credential cache name or a
 * prefix, the function will only use part up to the first colon (:)
 * if there is one. If prefix the argument is NULL, the default ccache
 * implemtation is returned.
 *
 * @return Returns NULL if ops not found.
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION const krb5_cc_ops* KRB5_LIB_CALL
krb5_cc_get_prefix_ops (
	krb5_context,
	const char*);

/**
 * Return the principal of `id' in `principal'.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_get_principal (
	krb5_context,
	krb5_ccache,
	krb5_principal*);

/**
 * Return the type of the ccache `id'.
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_cc_get_type (
	krb5_context,
	krb5_ccache);

/**
 * Return the version of `id'.
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_get_version (
	krb5_context,
	const krb5_ccache);

/**
 * Create a new ccache in `id' for `primary_principal'.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_initialize (
	krb5_context,
	krb5_ccache,
	krb5_principal);

/**
 * Return the last time the credential cache was modified.
 *
 * @param context A Kerberos 5 context
 * @param id The credential cache to probe
 * @param mtime the last modification time, set to 0 on error.

 * @return Return 0 or and error. See krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_last_change_time (
	krb5_context,
	krb5_ccache,
	krb5_timestamp*);

/**
 * Move the content from one credential cache to another. The
 * operation is an atomic switch.
 *
 * @param context a Keberos context
 * @param from the credential cache to move the content from
 * @param to the credential cache to move the content to

 * @return On sucess, from is freed. On failure, error code is
 * returned and from and to are both still allocated, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_move (
	krb5_context,
	krb5_ccache,
	krb5_ccache);

/**
 * Generates a new unique ccache of `type` in `id'. If `type' is NULL,
 * the library chooses the default credential cache type. The supplied
 * `hint' (that can be NULL) is a string that the credential cache
 * type can use to base the name of the credential on, this is to make
 * it easier for the user to differentiate the credentials.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_new_unique (
	krb5_context,
	const char*,
	const char*,
	krb5_ccache*);

/**
 * Retrieve the next cred pointed to by (`id', `cursor') in `creds'
 * and advance `cursor'.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_next_cred (
	krb5_context,
	const krb5_ccache,
	krb5_cc_cursor*,
	krb5_creds*);

/**
 * Add a new ccache type with operations `ops', overwriting any
 * existing one if `override'.
 *
 * @param context a Keberos context
 * @param ops type of plugin symbol
 * @param override flag to select if the registration is to overide
 * an existing ops with the same name.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_register (
	krb5_context,
	const krb5_cc_ops*,
	krb5_boolean);

/**
 * Remove the credential identified by `cred', `which' from `id'.
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_remove_cred (
	krb5_context,
	krb5_ccache,
	krb5_flags,
	krb5_creds*);

/**
 * Find and allocate a ccache in `id' from the specification in `residual'.
 * If the ccache name doesn't contain any colon, interpret it as a file name.
 *
 * @param context a Keberos context.
 * @param name string name of a credential cache.
 * @param id return pointer to a found credential cache.
 *
 * @return Return 0 or an error code. In case of an error, id is set
 * to NULL, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_resolve (
	krb5_context,
	const char*,
	krb5_ccache*);

/**
 * Retrieve the credential identified by `mcreds' (and `whichfields')
 * from `id' in `creds'. 'creds' must be free by the caller using
 * krb5_free_cred_contents.
 *
 * @param context A Kerberos 5 context
 * @param id a Kerberos 5 credential cache
 * @param whichfields what fields to use for matching credentials, same
 *        flags as whichfields in krb5_compare_creds()
 * @param mcreds template credential to use for comparing
 * @param creds returned credential, free with krb5_free_cred_contents()
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_retrieve_cred (
	krb5_context,
	krb5_ccache,
	krb5_flags,
	const krb5_creds*,
	krb5_creds*);

/**
 * Store some configuration for the credential cache in the cache.
 * Existing configuration under the same name is over-written.
 *
 * @param context a Keberos context
 * @param id the credential cache to store the data for
 * @param principal configuration for a specific principal, if
 * NULL, global for the whole cache.
 * @param name name under which the configuraion is stored.
 * @param data data to store, if NULL, configure is removed.
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_set_config (
	krb5_context,
	krb5_ccache,
	krb5_const_principal,
	const char*,
	krb5_data*);

/**
 * Set the default cc name for `context' to `name'.
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_set_default_name (
	krb5_context,
	const char*);

/**
 * Set the flags of `id' to `flags'.
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_set_flags (
	krb5_context,
	krb5_ccache,
	krb5_flags);

/**
 * Set the friendly name on credential cache.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_set_friendly_name (
	krb5_context,
	krb5_ccache,
	const char*);

/**
 * Set the time offset betwen the client and the KDC
 *
 * If the backend doesn't support KDC offset, use the context global setting.
 *
 * @param context A Kerberos 5 context.
 * @param id a credential cache
 * @param offset the offset in seconds
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_set_kdc_offset (
	krb5_context,
	krb5_ccache,
	krb5_deltat);

/**
 * Start iterating over `id', `cursor' is initialized to the
 * beginning.  Caller must free the cursor with krb5_cc_end_seq_get().
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_start_seq_get (
	krb5_context,
	const krb5_ccache,
	krb5_cc_cursor*);

/**
 * Store `creds' in the ccache `id'.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_store_cred (
	krb5_context,
	krb5_ccache,
	krb5_creds*);

/**
 * Return true if the default credential cache support switch
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_cc_support_switch (
	krb5_context,
	const char*);

/**
 * Switch the default default credential cache for a specific
 * credcache type (and name for some implementations).
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cc_switch (
	krb5_context,
	krb5_ccache);

/**
 * End an iteration and free all resources, can be done before end is reached.
 *
 * @param context A Kerberos 5 context
 * @param cursor the iteration cursor to be freed.
 *
 * @return Return 0 or and error, KRB5_CC_END is returned at the end
 *        of iteration. See krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cccol_cursor_free (
	krb5_context,
	krb5_cccol_cursor*);

/**
 * Get a new cache interation cursor that will interate over all
 * credentials caches independent of type.
 *
 * @param context a Keberos context
 * @param cursor passed into krb5_cccol_cursor_next() and free with krb5_cccol_cursor_free().
 *
 * @return Returns 0 or and error code, see krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cccol_cursor_new (
	krb5_context,
	krb5_cccol_cursor*);

/**
 * Get next credential cache from the iteration.
 *
 * @param context A Kerberos 5 context
 * @param cursor the iteration cursor
 * @param cache the returned cursor, pointer is set to NULL on failure
 *        and a cache on success. The returned cache needs to be freed
 *        with krb5_cc_close() or destroyed with krb5_cc_destroy().
 *        MIT Kerberos behavies slightly diffrent and sets cache to NULL
 *        when all caches are iterated over and return 0.
 *
 * @return Return 0 or and error, KRB5_CC_END is returned at the end
 *        of iteration. See krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cccol_cursor_next (
	krb5_context,
	krb5_cccol_cursor,
	krb5_ccache*);

/**
 * Return the last modfication time for a cache collection. The query
 * can be limited to a specific cache type. If the function return 0
 * and mtime is 0, there was no credentials in the caches.
 *
 * @param context A Kerberos 5 context
 * @param type The credential cache to probe, if NULL, all type are traversed.
 * @param mtime the last modification time, set to 0 on error.

 * @return Return 0 or and error. See krb5_get_error_message().
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cccol_last_change_time (
	krb5_context,
	const char*,
	krb5_timestamp*);

/**
 * Deprecated: krb5_change_password() is deprecated, use krb5_set_password().
 *
 * @param context a Keberos context
 * @param creds
 * @param newpw
 * @param result_code
 * @param result_code_string
 * @param result_string
 *
 * @return On sucess password is changed.

 * @ingroup @krb5_deprecated
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_change_password (
	krb5_context,
	krb5_creds*,
	const char*,
	int*,
	krb5_data*,
	krb5_data*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_check_transited (
	krb5_context,
	krb5_const_realm,
	krb5_const_realm,
	krb5_realm*,
	unsigned int,
	int*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_check_transited_realms (
	krb5_context,
	const char*const*,
	unsigned int,
	int*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_checksum_disable (
	krb5_context,
	krb5_cksumtype);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_checksum_free (
	krb5_context,
	krb5_checksum*);

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_checksum_is_collision_proof (
	krb5_context,
	krb5_cksumtype);

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_checksum_is_keyed (
	krb5_context,
	krb5_cksumtype);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_checksumsize (
	krb5_context,
	krb5_cksumtype,
	size_t*);

/**
 * Return the coresponding encryption type for a checksum type.
 *
 * @param context Kerberos context
 * @param ctype The checksum type to get the result enctype for
 * @param etype The returned encryption, when the matching etype is
 * not found, etype is set to ETYPE_NULL.
 *
 * @return Return an error code for an failure or 0 on success.
 * @ingroup krb5_crypto
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cksumtype_to_enctype (
	krb5_context,
	krb5_cksumtype,
	krb5_enctype*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_cksumtype_valid (
	krb5_context,
	krb5_cksumtype);

/**
 * Clears the error message from the Kerberos 5 context.
 *
 * @param context The Kerberos 5 context to clear
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_clear_error_message (krb5_context);

/**
 * Clear the error message returned by krb5_get_error_string().
 *
 * Deprecated: use krb5_clear_error_message()
 *
 * @param context Kerberos context
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_clear_error_string (krb5_context)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_closelog (
	krb5_context,
	krb5_log_facility*);

/**
 * Return TRUE if `mcreds' and `creds' are equal (`whichfields'
 * determines what equal means).
 *
 *
 * The following flags, set in whichfields affects the comparison:
 * - KRB5_TC_MATCH_SRV_NAMEONLY Consider all realms equal when comparing the service principal.
 * - KRB5_TC_MATCH_KEYTYPE Compare enctypes.
 * - KRB5_TC_MATCH_FLAGS_EXACT Make sure that the ticket flags are identical.
 * - KRB5_TC_MATCH_FLAGS Make sure that all ticket flags set in mcreds are also present in creds .
 * - KRB5_TC_MATCH_TIMES_EXACT Compares the ticket times exactly.
 * - KRB5_TC_MATCH_TIMES Compares only the expiration times of the creds.
 * - KRB5_TC_MATCH_AUTHDATA Compares the authdata fields.
 * - KRB5_TC_MATCH_2ND_TKT Compares the second tickets (used by user-to-user authentication).
 * - KRB5_TC_MATCH_IS_SKEY Compares the existance of the second ticket.
 *
 * @param context Kerberos 5 context.
 * @param whichfields which fields to compare.
 * @param mcreds cred to compare with.
 * @param creds cred to compare with.
 *
 * @return return TRUE if mcred and creds are equal, FALSE if not.
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_compare_creds (
	krb5_context,
	krb5_flags,
	const krb5_creds*,
	const krb5_creds*);

/**
 * Free configuration file section, the result of
 * krb5_config_parse_file() and krb5_config_parse_file_multi().
 *
 * @param context A Kerberos 5 context
 * @param s the configuration section to free
 *
 * @return returns 0 on successes, otherwise an error code, see
 *          krb5_get_error_message()
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_config_file_free (
	krb5_context,
	krb5_config_section*);

/**
 * Free the resulting strings from krb5_config-get_strings() and
 * krb5_config_vget_strings().
 *
 * @param strings strings to free
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_config_free_strings (char**);

/**
 * Like krb5_config_get_bool() but with a va_list list of
 * configuration selection.
 *
 * Configuration value to a boolean value, where yes/true and any
 * non-zero number means TRUE and other value is FALSE.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param ... a list of names, terminated with NULL.
 *
 * @return TRUE or FALSE
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_config_get_bool (
	krb5_context,
	const krb5_config_section*,
	...);

/**
 * krb5_config_get_bool_default() will convert the configuration
 * option value to a boolean value, where yes/true and any non-zero
 * number means TRUE and other value is FALSE.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param def_value the default value to return if no configuration
 *        found in the database.
 * @param ... a list of names, terminated with NULL.
 *
 * @return TRUE or FALSE
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_config_get_bool_default (
	krb5_context,
	const krb5_config_section*,
	krb5_boolean,
	...);

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_config_get_int (
	krb5_context,
	const krb5_config_section*,
	...);

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_config_get_int_default (
	krb5_context,
	const krb5_config_section*,
	int,
	...);

/**
 * Get a list of configuration binding list for more processing
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param ... a list of names, terminated with NULL.
 *
 * @return NULL if configuration list is not found, a list otherwise
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION const krb5_config_binding* KRB5_LIB_CALL
krb5_config_get_list (
	krb5_context,
	const krb5_config_section*,
	...);

/**
 * Returns a "const char *" to a string in the configuration database.
 * The string may not be valid after a reload of the configuration
 * database so a caller should make a local copy if it needs to keep
 * the string.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param ... a list of names, terminated with NULL.
 *
 * @return NULL if configuration string not found, a string otherwise
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_config_get_string (
	krb5_context,
	const krb5_config_section*,
	...);

/**
 * Like krb5_config_get_string(), but instead of returning NULL,
 * instead return a default value.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param def_value the default value to return if no configuration
 *        found in the database.
 * @param ... a list of names, terminated with NULL.
 *
 * @return a configuration string
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_config_get_string_default (
	krb5_context,
	const krb5_config_section*,
	const char*,
	...);

/**
 * Get a list of configuration strings, free the result with
 * krb5_config_free_strings().
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param ... a list of names, terminated with NULL.
 *
 * @return TRUE or FALSE
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION char** KRB5_LIB_CALL
krb5_config_get_strings (
	krb5_context,
	const krb5_config_section*,
	...);

/**
 * Get the time from the configuration file using a relative time, for example: 1h30s
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param ... a list of names, terminated with NULL.
 *
 * @return parsed the time or -1 on error
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_config_get_time (
	krb5_context,
	const krb5_config_section*,
	...);

/**
 * Get the time from the configuration file using a relative time, for example: 1h30s
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param def_value the default value to return if no configuration
 *        found in the database.
 * @param ... a list of names, terminated with NULL.
 *
 * @return parsed the time (or def_value on parse error)
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_config_get_time_default (
	krb5_context,
	const krb5_config_section*,
	int,
	...);

/**
 * Parse configuration files in the given directory and add the result
 * into res.  Only files whose names consist only of alphanumeric
 * characters, hyphen, and underscore, will be parsed, though files
 * ending in ".conf" will also be parsed.
 *
 * This interface can be used to parse several configuration directories
 * into one resulting krb5_config_section by calling it repeatably.
 *
 * @param context a Kerberos 5 context.
 * @param dname a directory name to a Kerberos configuration file
 * @param res the returned result, must be free with krb5_free_config_files().
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_config_parse_dir_multi (
	krb5_context,
	const char*,
	krb5_config_section**);

/**
     * If the fname starts with "~/" parse configuration file in the
     * current users home directory. The behavior can be disabled and
     * enabled by calling krb5_set_home_dir_access().
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_config_parse_file (
	krb5_context,
	const char*,
	krb5_config_section**);

/**
 * Parse a configuration file and add the result into res. This
 * interface can be used to parse several configuration files into one
 * resulting krb5_config_section by calling it repeatably.
 *
 * @param context a Kerberos 5 context.
 * @param fname a file name to a Kerberos configuration file
 * @param res the returned result, must be free with krb5_free_config_files().
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_config_parse_file_multi (
	krb5_context,
	const char*,
	krb5_config_section**);

/**
 * Deprecated: configuration files are not strings
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_config_parse_string_multi (
	krb5_context,
	const char*,
	krb5_config_section**)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

/**
 * krb5_config_get_bool() will convert the configuration
 * option value to a boolean value, where yes/true and any non-zero
 * number means TRUE and other value is FALSE.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param args a va_list of arguments
 *
 * @return TRUE or FALSE
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_config_vget_bool (
	krb5_context,
	const krb5_config_section*,
	va_list);

/**
 * Like krb5_config_get_bool_default() but with a va_list list of
 * configuration selection.
 *
 * Configuration value to a boolean value, where yes/true and any
 * non-zero number means TRUE and other value is FALSE.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param def_value the default value to return if no configuration
 *        found in the database.
 * @param args a va_list of arguments
 *
 * @return TRUE or FALSE
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_config_vget_bool_default (
	krb5_context,
	const krb5_config_section*,
	krb5_boolean,
	va_list);

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_config_vget_int (
	krb5_context,
	const krb5_config_section*,
	va_list);

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_config_vget_int_default (
	krb5_context,
	const krb5_config_section*,
	int,
	va_list);

/**
 * Get a list of configuration binding list for more processing
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param args a va_list of arguments
 *
 * @return NULL if configuration list is not found, a list otherwise
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION const krb5_config_binding* KRB5_LIB_CALL
krb5_config_vget_list (
	krb5_context,
	const krb5_config_section*,
	va_list);

/**
 * Like krb5_config_get_string(), but uses a va_list instead of ...
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param args a va_list of arguments
 *
 * @return NULL if configuration string not found, a string otherwise
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_config_vget_string (
	krb5_context,
	const krb5_config_section*,
	va_list);

/**
 * Like krb5_config_vget_string(), but instead of returning NULL,
 * instead return a default value.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param def_value the default value to return if no configuration
 *        found in the database.
 * @param args a va_list of arguments
 *
 * @return a configuration string
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_config_vget_string_default (
	krb5_context,
	const krb5_config_section*,
	const char*,
	va_list);

/**
 * Get a list of configuration strings, free the result with
 * krb5_config_free_strings().
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param args a va_list of arguments
 *
 * @return TRUE or FALSE
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION char** KRB5_LIB_CALL
krb5_config_vget_strings (
	krb5_context,
	const krb5_config_section*,
	va_list);

/**
 * Get the time from the configuration file using a relative time, for example: 1h30s
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param args a va_list of arguments
 *
 * @return parsed the time or -1 on error
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_config_vget_time (
	krb5_context,
	const krb5_config_section*,
	va_list);

/**
 * Get the time from the configuration file using a relative time.
 *
 * Like krb5_config_get_time_default() but with a va_list list of
 * configuration selection.
 *
 * @param context A Kerberos 5 context.
 * @param c a configuration section, or NULL to use the section from context
 * @param def_value the default value to return if no configuration
 *        found in the database.
 * @param args a va_list of arguments
 *
 * @return parsed the time (or def_value on parse error)
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_config_vget_time_default (
	krb5_context,
	const krb5_config_section*,
	int,
	va_list);

/**
 * krb5_copy_address copies the content of address
 * inaddr to outaddr.
 *
 * @param context a Keberos context
 * @param inaddr pointer to source address
 * @param outaddr pointer to destination address
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_address
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_copy_address (
	krb5_context,
	const krb5_address*,
	krb5_address*);

/**
 * krb5_copy_addresses copies the content of addresses
 * inaddr to outaddr.
 *
 * @param context a Keberos context
 * @param inaddr pointer to source addresses
 * @param outaddr pointer to destination addresses
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_address
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_copy_addresses (
	krb5_context,
	const krb5_addresses*,
	krb5_addresses*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_copy_checksum (
	krb5_context,
	const krb5_checksum*,
	krb5_checksum**);

/**
 * Make a copy for the Kerberos 5 context, the new krb5_context shoud
 * be freed with krb5_free_context().
 *
 * @param context the Kerberos context to copy
 * @param out the copy of the Kerberos, set to NULL error.
 *
 * @return Returns 0 to indicate success.  Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_copy_context (
	krb5_context,
	krb5_context*);

/**
 * Copy krb5_creds.
 *
 * @param context Kerberos 5 context.
 * @param incred source credential
 * @param outcred destination credential, free with krb5_free_creds().
 *
 * @return Returns 0 to indicate success. Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_copy_creds (
	krb5_context,
	const krb5_creds*,
	krb5_creds**);

/**
 * Copy content of krb5_creds.
 *
 * @param context Kerberos 5 context.
 * @param incred source credential
 * @param c destination credential, free with krb5_free_cred_contents().
 *
 * @return Returns 0 to indicate success. Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_copy_creds_contents (
	krb5_context,
	const krb5_creds*,
	krb5_creds*);

/**
 * Copy the data into a newly allocated krb5_data.
 *
 * @param context Kerberos 5 context.
 * @param indata the krb5_data data to copy
 * @param outdata new krb5_date to copy too. Free with krb5_free_data().
 *
 * @return Returns 0 to indicate success. Otherwise an kerberos et
 * error code is returned.
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_copy_data (
	krb5_context,
	const krb5_data*,
	krb5_data**);

/**
 * Copy the list of realms from `from' to `to'.
 *
 * @param context Kerberos 5 context.
 * @param from list of realms to copy from.
 * @param to list of realms to copy to, free list of krb5_free_host_realm().
 *
 * @return Returns 0 to indicate success. Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_copy_host_realm (
	krb5_context,
	const krb5_realm*,
	krb5_realm**);

/**
 * Copy a keyblock, free the output keyblock with
 * krb5_free_keyblock().
 *
 * @param context a Kerberos 5 context
 * @param inblock the key to copy
 * @param to the output key.
 *
 * @return 0 on success or a Kerberos 5 error code
 *
 * @ingroup krb5_crypto
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_copy_keyblock (
	krb5_context,
	const krb5_keyblock*,
	krb5_keyblock**);

/**
 * Copy a keyblock, free the output keyblock with
 * krb5_free_keyblock_contents().
 *
 * @param context a Kerberos 5 context
 * @param inblock the key to copy
 * @param to the output key.
 *
 * @return 0 on success or a Kerberos 5 error code
 *
 * @ingroup krb5_crypto
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_copy_keyblock_contents (
	krb5_context,
	const krb5_keyblock*,
	krb5_keyblock*);

/**
 * Copy a principal
 *
 * @param context A Kerberos context.
 * @param inprinc principal to copy
 * @param outprinc copied principal, free with krb5_free_principal()
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_copy_principal (
	krb5_context,
	krb5_const_principal,
	krb5_principal*);

/**
 * Copy ticket and content
 *
 * @param context a Kerberos 5 context
 * @param from ticket to copy
 * @param to new copy of ticket, free with krb5_free_ticket()
 *
 * @return Returns 0 to indicate success.  Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_copy_ticket (
	krb5_context,
	const krb5_ticket*,
	krb5_ticket**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_create_checksum (
	krb5_context,
	krb5_crypto,
	krb5_key_usage,
	int,
	void*,
	size_t,
	Checksum*);

/**
 * Create a Kerberos message checksum.
 *
 * @param context Kerberos context
 * @param crypto Kerberos crypto context
 * @param usage Key usage for this buffer
 * @param data array of buffers to process
 * @param num_data length of array
 * @param type output data
 *
 * @return Return an error code or 0.
 * @ingroup krb5_crypto
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_create_checksum_iov (
	krb5_context,
	krb5_crypto,
	unsigned,
	krb5_crypto_iov*,
	unsigned int,
	krb5_cksumtype*);

/**
 * Returns the ticket flags for the credentials in creds.
 * See also krb5_ticket_get_flags().
 *
 * @param creds credential to get ticket flags from
 *
 * @return ticket flags
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION unsigned long KRB5_LIB_CALL
krb5_creds_get_ticket_flags (krb5_creds*);

/**
 * Free a crypto context created by krb5_crypto_init().
 *
 * @param context Kerberos context
 * @param crypto crypto context to free
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_crypto
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_crypto_destroy (
	krb5_context,
	krb5_crypto);

/**
 * The FX-CF2 key derivation function, used in FAST and preauth framework.
 *
 * @param context Kerberos 5 context
 * @param crypto1 first key to combine
 * @param crypto2 second key to combine
 * @param pepper1 factor to combine with first key to garante uniqueness
 * @param pepper2 factor to combine with second key to garante uniqueness
 * @param enctype the encryption type of the resulting key
 * @param res allocated key, free with krb5_free_keyblock_contents()
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_crypto
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_crypto_fx_cf2 (
	krb5_context,
	const krb5_crypto,
	const krb5_crypto,
	krb5_data*,
	krb5_data*,
	krb5_enctype,
	krb5_keyblock*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_crypto_get_checksum_type (
	krb5_context,
	krb5_crypto,
	krb5_cksumtype*);

/**
 * Return the blocksize used algorithm referenced by the crypto context
 *
 * @param context Kerberos context
 * @param crypto crypto context to query
 * @param blocksize the resulting blocksize
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_crypto
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_crypto_getblocksize (
	krb5_context,
	krb5_crypto,
	size_t*);

/**
 * Return the confounder size used by the crypto context
 *
 * @param context Kerberos context
 * @param crypto crypto context to query
 * @param confoundersize the returned confounder size
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_crypto
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_crypto_getconfoundersize (
	krb5_context,
	krb5_crypto,
	size_t*);

/**
 * Return the encryption type used by the crypto context
 *
 * @param context Kerberos context
 * @param crypto crypto context to query
 * @param enctype the resulting encryption type
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_crypto
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_crypto_getenctype (
	krb5_context,
	krb5_crypto,
	krb5_enctype*);

/**
 * Return the padding size used by the crypto context
 *
 * @param context Kerberos context
 * @param crypto crypto context to query
 * @param padsize the return padding size
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_crypto
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_crypto_getpadsize (
	krb5_context,
	krb5_crypto,
	size_t*);

/**
 * Create a crypto context used for all encryption and signature
 * operation. The encryption type to use is taken from the key, but
 * can be overridden with the enctype parameter.  This can be useful
 * for encryptions types which is compatiable (DES for example).
 *
 * To free the crypto context, use krb5_crypto_destroy().
 *
 * @param context Kerberos context
 * @param key the key block information with all key data
 * @param etype the encryption type
 * @param crypto the resulting crypto context
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_crypto
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_crypto_init (
	krb5_context,
	const krb5_keyblock*,
	krb5_enctype,
	krb5_crypto*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_crypto_length (
	krb5_context,
	krb5_crypto,
	int,
	size_t*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_crypto_length_iov (
	krb5_context,
	krb5_crypto,
	krb5_crypto_iov*,
	unsigned int);

KRB5_LIB_FUNCTION size_t KRB5_LIB_CALL
krb5_crypto_overhead (
	krb5_context,
	krb5_crypto);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_crypto_prf (
	krb5_context,
	const krb5_crypto,
	const krb5_data*,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_crypto_prf_length (
	krb5_context,
	krb5_enctype,
	size_t*);

/**
 * Allocate data of and krb5_data.
 *
 * @param p krb5_data to allocate.
 * @param len size to allocate.
 *
 * @return Returns 0 to indicate success. Otherwise an kerberos et
 * error code is returned.
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_data_alloc (
	krb5_data*,
	int);

/**
 * Compare to data.
 *
 * @param data1 krb5_data to compare
 * @param data2 krb5_data to compare
 *
 * @return return the same way as memcmp(), useful when sorting.
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_data_cmp (
	const krb5_data*,
	const krb5_data*);

/**
 * Copy the data of len into the krb5_data.
 *
 * @param p krb5_data to copy into.
 * @param data data to copy..
 * @param len new size.
 *
 * @return Returns 0 to indicate success. Otherwise an kerberos et
 * error code is returned.
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_data_copy (
	krb5_data*,
	const void*,
	size_t);

/**
 * Compare to data not exposing timing information from the checksum data
 *
 * @param data1 krb5_data to compare
 * @param data2 krb5_data to compare
 *
 * @return returns zero for same data, otherwise non zero.
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_data_ct_cmp (
	const krb5_data*,
	const krb5_data*);

/**
 * Free the content of krb5_data structure, its ok to free a zeroed
 * structure (with memset() or krb5_data_zero()). When done, the
 * structure will be zeroed. The same function is called
 * krb5_free_data_contents() in MIT Kerberos.
 *
 * @param p krb5_data to free.
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_data_free (krb5_data*);

/**
 * Grow (or shrink) the content of krb5_data to a new size.
 *
 * @param p krb5_data to free.
 * @param len new size.
 *
 * @return Returns 0 to indicate success. Otherwise an kerberos et
 * error code is returned.
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_data_realloc (
	krb5_data*,
	int);

/**
 * Reset the (potentially uninitalized) krb5_data structure.
 *
 * @param p krb5_data to reset.
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_data_zero (krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_decode_Authenticator (
	krb5_context,
	const void*,
	size_t,
	Authenticator*,
	size_t*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_decode_ETYPE_INFO (
	krb5_context,
	const void*,
	size_t,
	ETYPE_INFO*,
	size_t*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_decode_ETYPE_INFO2 (
	krb5_context,
	const void*,
	size_t,
	ETYPE_INFO2*,
	size_t*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_decode_EncAPRepPart (
	krb5_context,
	const void*,
	size_t,
	EncAPRepPart*,
	size_t*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_decode_EncASRepPart (
	krb5_context,
	const void*,
	size_t,
	EncASRepPart*,
	size_t*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_decode_EncKrbCredPart (
	krb5_context,
	const void*,
	size_t,
	EncKrbCredPart*,
	size_t*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_decode_EncTGSRepPart (
	krb5_context,
	const void*,
	size_t,
	EncTGSRepPart*,
	size_t*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_decode_EncTicketPart (
	krb5_context,
	const void*,
	size_t,
	EncTicketPart*,
	size_t*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_decode_ap_req (
	krb5_context,
	const krb5_data*,
	krb5_ap_req*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_decrypt (
	krb5_context,
	krb5_crypto,
	unsigned,
	void*,
	size_t,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_decrypt_EncryptedData (
	krb5_context,
	krb5_crypto,
	unsigned,
	const EncryptedData*,
	krb5_data*);

/**
 * Inline decrypt a Kerberos message.
 *
 * @param context Kerberos context
 * @param crypto Kerberos crypto context
 * @param usage Key usage for this buffer
 * @param data array of buffers to process
 * @param num_data length of array
 * @param ivec initial cbc/cts vector
 *
 * @return Return an error code or 0.
 * @ingroup krb5_crypto
 *
 * 1. KRB5_CRYPTO_TYPE_HEADER
 * 2. one KRB5_CRYPTO_TYPE_DATA and array [0,...] of KRB5_CRYPTO_TYPE_SIGN_ONLY in
 *  any order, however the receiver have to aware of the
 *  order. KRB5_CRYPTO_TYPE_SIGN_ONLY is commonly used unencrypoted
 *  protocol headers and trailers. The output data will be of same
 *  size as the input data or shorter.
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_decrypt_iov_ivec (
	krb5_context,
	krb5_crypto,
	unsigned,
	krb5_crypto_iov*,
	unsigned int,
	void*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_decrypt_ivec (
	krb5_context,
	krb5_crypto,
	unsigned,
	void*,
	size_t,
	krb5_data*,
	void*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_decrypt_ticket (
	krb5_context,
	Ticket*,
	krb5_keyblock*,
	EncTicketPart*,
	krb5_flags);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_derive_key (
	krb5_context,
	const krb5_keyblock*,
	krb5_enctype,
	const void*,
	size_t,
	krb5_keyblock**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_alloc (
	krb5_context,
	krb5_digest*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_digest_free (krb5_digest);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_get_client_binding (
	krb5_context,
	krb5_digest,
	char**,
	char**);

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_digest_get_identifier (
	krb5_context,
	krb5_digest);

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_digest_get_opaque (
	krb5_context,
	krb5_digest);

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_digest_get_rsp (
	krb5_context,
	krb5_digest);

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_digest_get_server_nonce (
	krb5_context,
	krb5_digest);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_get_session_key (
	krb5_context,
	krb5_digest,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_get_tickets (
	krb5_context,
	krb5_digest,
	Ticket**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_init_request (
	krb5_context,
	krb5_digest,
	krb5_realm,
	krb5_ccache);

/**
 * Get the supported/allowed mechanism for this principal.
 *
 * @param context A Keberos context.
 * @param realm The realm of the KDC.
 * @param ccache The credential cache to use when talking to the KDC.
 * @param flags The supported mechanism.
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_digest
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_probe (
	krb5_context,
	krb5_realm,
	krb5_ccache,
	unsigned*);

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_digest_rep_get_status (
	krb5_context,
	krb5_digest);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_request (
	krb5_context,
	krb5_digest,
	krb5_realm,
	krb5_ccache);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_set_authentication_user (
	krb5_context,
	krb5_digest,
	krb5_principal);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_set_authid (
	krb5_context,
	krb5_digest,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_set_client_nonce (
	krb5_context,
	krb5_digest,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_set_digest (
	krb5_context,
	krb5_digest,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_set_hostname (
	krb5_context,
	krb5_digest,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_set_identifier (
	krb5_context,
	krb5_digest,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_set_method (
	krb5_context,
	krb5_digest,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_set_nonceCount (
	krb5_context,
	krb5_digest,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_set_opaque (
	krb5_context,
	krb5_digest,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_set_qop (
	krb5_context,
	krb5_digest,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_set_realm (
	krb5_context,
	krb5_digest,
	const char*);

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_digest_set_responseData (
	krb5_context,
	krb5_digest,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_set_server_cb (
	krb5_context,
	krb5_digest,
	const char*,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_set_server_nonce (
	krb5_context,
	krb5_digest,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_set_type (
	krb5_context,
	krb5_digest,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_set_uri (
	krb5_context,
	krb5_digest,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_digest_set_username (
	krb5_context,
	krb5_digest,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_domain_x500_decode (
	krb5_context,
	krb5_data,
	char***,
	unsigned int*,
	const char*,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_domain_x500_encode (
	char**,
	unsigned int,
	krb5_data*);

/**
 * Convert the getaddrinfo() error code to a Kerberos et error code.
 *
 * @param eai_errno contains the error code from getaddrinfo().
 * @param system_error should have the value of errno after the failed getaddrinfo().
 *
 * @return Kerberos error code representing the EAI errors.
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_eai_to_heim_errno (
	int,
	int);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_encode_Authenticator (
	krb5_context,
	void*,
	size_t,
	Authenticator*,
	size_t*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_encode_ETYPE_INFO (
	krb5_context,
	void*,
	size_t,
	ETYPE_INFO*,
	size_t*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_encode_ETYPE_INFO2 (
	krb5_context,
	void*,
	size_t,
	ETYPE_INFO2*,
	size_t*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_encode_EncAPRepPart (
	krb5_context,
	void*,
	size_t,
	EncAPRepPart*,
	size_t*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_encode_EncASRepPart (
	krb5_context,
	void*,
	size_t,
	EncASRepPart*,
	size_t*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_encode_EncKrbCredPart (
	krb5_context,
	void*,
	size_t,
	EncKrbCredPart*,
	size_t*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_encode_EncTGSRepPart (
	krb5_context,
	void*,
	size_t,
	EncTGSRepPart*,
	size_t*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_encode_EncTicketPart (
	krb5_context,
	void*,
	size_t,
	EncTicketPart*,
	size_t*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_encrypt (
	krb5_context,
	krb5_crypto,
	unsigned,
	const void*,
	size_t,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_encrypt_EncryptedData (
	krb5_context,
	krb5_crypto,
	unsigned,
	void*,
	size_t,
	int,
	EncryptedData*);

/**
 * Inline encrypt a kerberos message
 *
 * @param context Kerberos context
 * @param crypto Kerberos crypto context
 * @param usage Key usage for this buffer
 * @param data array of buffers to process
 * @param num_data length of array
 * @param ivec initial cbc/cts vector
 *
 * @return Return an error code or 0.
 * @ingroup krb5_crypto
 *
 * Kerberos encrypted data look like this:
 *
 * 1. KRB5_CRYPTO_TYPE_HEADER
 * 2. array [1,...] KRB5_CRYPTO_TYPE_DATA and array [0,...]
 *    KRB5_CRYPTO_TYPE_SIGN_ONLY in any order, however the receiver
 *    have to aware of the order. KRB5_CRYPTO_TYPE_SIGN_ONLY is
 *    commonly used headers and trailers.
 * 3. KRB5_CRYPTO_TYPE_PADDING, at least on padsize long if padsize > 1
 * 4. KRB5_CRYPTO_TYPE_TRAILER
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_encrypt_iov_ivec (
	krb5_context,
	krb5_crypto,
	unsigned,
	krb5_crypto_iov*,
	int,
	void*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_encrypt_ivec (
	krb5_context,
	krb5_crypto,
	unsigned,
	const void*,
	size_t,
	krb5_data*,
	void*);

/**
 * Disable encryption type
 *
 * @param context Kerberos 5 context
 * @param enctype encryption type to disable
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_crypto
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_enctype_disable (
	krb5_context,
	krb5_enctype);

/**
 * Enable encryption type
 *
 * @param context Kerberos 5 context
 * @param enctype encryption type to enable
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_crypto
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_enctype_enable (
	krb5_context,
	krb5_enctype);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_enctype_keybits (
	krb5_context,
	krb5_enctype,
	size_t*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_enctype_keysize (
	krb5_context,
	krb5_enctype,
	size_t*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_enctype_to_keytype (
	krb5_context,
	krb5_enctype,
	krb5_keytype*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_enctype_to_string (
	krb5_context,
	krb5_enctype,
	char**);

/**
 * Check if a enctype is valid, return 0 if it is.
 *
 * @param context Kerberos context
 * @param etype enctype to check if its valid or not
 *
 * @return Return an error code for an failure or 0 on success (enctype valid).
 * @ingroup krb5_crypto
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_enctype_valid (
	krb5_context,
	krb5_enctype);

/**
 * Deprecated: keytypes doesn't exists, they are really enctypes.
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_enctypes_compatible_keys (
	krb5_context,
	krb5_enctype,
	krb5_enctype)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

krb5_error_code
krb5_enomem (krb5_context);

/**
 * Log a warning to the log, default stderr, include bthe error from
 * the last failure and then exit.
 *
 * @param context A Kerberos 5 context
 * @param eval the exit code to exit with
 * @param code error code of the last error
 * @param fmt message to print
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_err (
	krb5_context,
	int,
	krb5_error_code,
	const char*,
	...)
     __attribute__ ((__noreturn__, __format__ (__printf__, 4, 5)));

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_error_from_rd_error (
	krb5_context,
	const krb5_error*,
	const krb5_creds*);

/**
 * Log a warning to the log, default stderr, and then exit.
 *
 * @param context A Kerberos 5 context
 * @param eval the exit code to exit with
 * @param fmt message to print
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_errx (
	krb5_context,
	int,
	const char*,
	...)
     __attribute__ ((__noreturn__, __format__ (__printf__, 3, 4)));

/**
 * krb5_expand_hostname() tries to make orig_hostname into a more
 * canonical one in the newly allocated space returned in
 * new_hostname.

 * @param context a Keberos context
 * @param orig_hostname hostname to canonicalise.
 * @param new_hostname output hostname, caller must free hostname with
 *        krb5_xfree().
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_expand_hostname (
	krb5_context,
	const char*,
	char**);

/**
 * krb5_expand_hostname_realms() expands orig_hostname to a name we
 * believe to be a hostname in newly allocated space in new_hostname
 * and return the realms new_hostname is believed to belong to in
 * realms.
 *
 * @param context a Keberos context
 * @param orig_hostname hostname to canonicalise.
 * @param new_hostname output hostname, caller must free hostname with
 *        krb5_xfree().
 * @param realms output possible realms, is an array that is terminated
 *        with NULL. Caller must free with krb5_free_host_realm().
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_expand_hostname_realms (
	krb5_context,
	const char*,
	char**,
	char***);

KRB5_LIB_FUNCTION PA_DATA* KRB5_LIB_CALL
krb5_find_padata (
	PA_DATA*,
	unsigned,
	int,
	int*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_format_time (
	krb5_context,
	time_t,
	char*,
	size_t,
	krb5_boolean);

/**
 * krb5_free_address frees the data stored in the address that is
 * alloced with any of the krb5_address functions.
 *
 * @param context a Keberos context
 * @param address addresss to be freed.
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_address
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_free_address (
	krb5_context,
	krb5_address*);

/**
 * krb5_free_addresses frees the data stored in the address that is
 * alloced with any of the krb5_address functions.
 *
 * @param context a Keberos context
 * @param addresses addressses to be freed.
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_address
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_free_addresses (
	krb5_context,
	krb5_addresses*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_free_ap_rep_enc_part (
	krb5_context,
	krb5_ap_rep_enc_part*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_free_authenticator (
	krb5_context,
	krb5_authenticator*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_free_checksum (
	krb5_context,
	krb5_checksum*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_free_checksum_contents (
	krb5_context,
	krb5_checksum*);

/**
 * Free a list of configuration files.
 *
 * @param filenames list, terminated with a NULL pointer, to be
 * freed. NULL is an valid argument.
 *
 * @return Returns 0 to indicate success. Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_free_config_files (char**);

/**
 * Frees the krb5_context allocated by krb5_init_context().
 *
 * @param context context to be freed.
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_free_context (krb5_context);

/**
 * Free content of krb5_creds.
 *
 * @param context Kerberos 5 context.
 * @param c krb5_creds to free.
 *
 * @return Returns 0 to indicate success. Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_free_cred_contents (
	krb5_context,
	krb5_creds*);

/**
 * Free krb5_creds.
 *
 * @param context Kerberos 5 context.
 * @param c krb5_creds to free.
 *
 * @return Returns 0 to indicate success. Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_free_creds (
	krb5_context,
	krb5_creds*);

/**
 * Deprecated: use krb5_free_cred_contents()
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_free_creds_contents (
	krb5_context,
	krb5_creds*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

/**
 * Free krb5_data (and its content).
 *
 * @param context Kerberos 5 context.
 * @param p krb5_data to free.
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_free_data (
	krb5_context,
	krb5_data*);

/**
 * Same as krb5_data_free(). MIT compat.
 *
 * Deprecated: use krb5_data_free().
 *
 * @param context Kerberos 5 context.
 * @param data krb5_data to free.
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_free_data_contents (
	krb5_context,
	krb5_data*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_free_default_realm (
	krb5_context,
	krb5_realm);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_free_error (
	krb5_context,
	krb5_error*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_free_error_contents (
	krb5_context,
	krb5_error*);

/**
 * Free the error message returned by krb5_get_error_message().
 *
 * @param context Kerberos context
 * @param msg error message to free, returned byg
 *        krb5_get_error_message().
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_free_error_message (
	krb5_context,
	const char*);

/**
 * Free the error message returned by krb5_get_error_string().
 *
 * Deprecated: use krb5_free_error_message()
 *
 * @param context Kerberos context
 * @param str error message to free
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_free_error_string (
	krb5_context,
	char*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

/**
 * Free all memory allocated by `realmlist'
 *
 * @param context A Kerberos 5 context.
 * @param realmlist realmlist to free, NULL is ok
 *
 * @return a Kerberos error code, always 0.
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_free_host_realm (
	krb5_context,
	krb5_realm*);

/**
 * Variable containing the FILE based credential cache implemention.
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_free_kdc_rep (
	krb5_context,
	krb5_kdc_rep*);

/**
 * Free a keyblock, also zero out the content of the keyblock, uses
 * krb5_free_keyblock_contents() to free the content.
 *
 * @param context a Kerberos 5 context
 * @param keyblock keyblock to free, NULL is valid argument
 *
 * @ingroup krb5_crypto
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_free_keyblock (
	krb5_context,
	krb5_keyblock*);

/**
 * Free a keyblock's content, also zero out the content of the keyblock.
 *
 * @param context a Kerberos 5 context
 * @param keyblock keyblock content to free, NULL is valid argument
 *
 * @ingroup krb5_crypto
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_free_keyblock_contents (
	krb5_context,
	krb5_keyblock*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_free_krbhst (
	krb5_context,
	char**);

/**
 * Free a name canonicalization rule iterator.
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_free_name_canon_iterator (
	krb5_context,
	krb5_name_canon_iterator);

/**
 * Frees a Kerberos principal allocated by the library with
 * krb5_parse_name(), krb5_make_principal() or any other related
 * principal functions.
 *
 * @param context A Kerberos context.
 * @param p a principal to free.
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_free_principal (
	krb5_context,
	krb5_principal);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_free_salt (
	krb5_context,
	krb5_salt);

/**
 * Free ticket and content
 *
 * @param context a Kerberos 5 context
 * @param ticket ticket to free
 *
 * @return Returns 0 to indicate success.  Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_free_ticket (
	krb5_context,
	krb5_ticket*);

/**
 * Deprecated: use krb5_xfree().
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_free_unparsed_name (
	krb5_context,
	char*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

/**
 * Forward credentials for client to host hostname , making them
 * forwardable if forwardable, and returning the blob of data to sent
 * in out_data.  If hostname == NULL, pick it from server.
 *
 * @param context A kerberos 5 context.
 * @param auth_context the auth context with the key to encrypt the out_data.
 * @param hostname the host to forward the tickets too.
 * @param client the client to delegate from.
 * @param server the server to delegate the credential too.
 * @param ccache credential cache to use.
 * @param forwardable make the forwarded ticket forwabledable.
 * @param out_data the resulting credential.
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_credential
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_fwd_tgt_creds (
	krb5_context,
	krb5_auth_context,
	const char*,
	krb5_principal,
	krb5_principal,
	krb5_ccache,
	int,
	krb5_data*);

/**
 * Fill buffer buf with len bytes of PRNG randomness that is ok to use
 * for key generation, padding and public diclosing the randomness w/o
 * disclosing the randomness source.
 *
 * This function can fail, and callers must check the return value.
 *
 * @param buf a buffer to fill with randomness
 * @param len length of memory that buf points to.
 *
 * @return return 0 on success or HEIM_ERR_RANDOM_OFFLINE if the
 * funcation failed to initialize the randomness source.
 *
 * @ingroup krb5_crypto
 */

HEIMDAL_WARN_UNUSED_RESULT_ATTRIBUTE KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_generate_random (
	void*,
	size_t);

/**
 * Fill buffer buf with len bytes of PRNG randomness that is ok to use
 * for key generation, padding and public diclosing the randomness w/o
 * disclosing the randomness source.
 *
 * This function can NOT fail, instead it will abort() and program will crash.
 *
 * If this function is called after a successful krb5_init_context(),
 * the chance of it failing is low due to that krb5_init_context()
 * pulls out some random, and quite commonly the randomness sources
 * will not fail once it have started to produce good output,
 * /dev/urandom behavies that way.
 *
 * @param buf a buffer to fill with randomness
 * @param len length of memory that buf points to.
 *
 * @ingroup krb5_crypto
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_generate_random_block (
	void*,
	size_t);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_generate_random_keyblock (
	krb5_context,
	krb5_enctype,
	krb5_keyblock*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_generate_seq_number (
	krb5_context,
	const krb5_keyblock*,
	uint32_t*);

/**
 * Deprecated: use krb5_generate_subkey_extended()
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_generate_subkey (
	krb5_context,
	const krb5_keyblock*,
	krb5_keyblock**)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

/**
 * Generate subkey, from keyblock
 *
 * @param context kerberos context
 * @param key session key
 * @param etype encryption type of subkey, if ETYPE_NULL, use key's enctype
 * @param subkey returned new, free with krb5_free_keyblock().
 *
 * @return 0 on success or a Kerberos 5 error code
 *
* @ingroup krb5_crypto
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_generate_subkey_extended (
	krb5_context,
	const krb5_keyblock*,
	krb5_enctype,
	krb5_keyblock**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_all_client_addrs (
	krb5_context,
	krb5_addresses*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_all_server_addrs (
	krb5_context,
	krb5_addresses*);

/**
 * Deprecated: use krb5_get_credentials_with_flags().
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_cred_from_kdc (
	krb5_context,
	krb5_ccache,
	krb5_creds*,
	krb5_creds**,
	krb5_creds***)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

/**
 * Deprecated: use krb5_get_credentials_with_flags().
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_cred_from_kdc_opt (
	krb5_context,
	krb5_ccache,
	krb5_creds*,
	krb5_creds**,
	krb5_creds***,
	krb5_flags)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_credentials (
	krb5_context,
	krb5_flags,
	krb5_ccache,
	krb5_creds*,
	krb5_creds**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_credentials_with_flags (
	krb5_context,
	krb5_flags,
	krb5_kdc_flags,
	krb5_ccache,
	krb5_creds*,
	krb5_creds**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_creds (
	krb5_context,
	krb5_get_creds_opt,
	krb5_ccache,
	krb5_const_principal,
	krb5_creds**);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_get_creds_opt_add_options (
	krb5_context,
	krb5_get_creds_opt,
	krb5_flags);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_creds_opt_alloc (
	krb5_context,
	krb5_get_creds_opt*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_get_creds_opt_free (
	krb5_context,
	krb5_get_creds_opt);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_get_creds_opt_set_enctype (
	krb5_context,
	krb5_get_creds_opt,
	krb5_enctype);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_creds_opt_set_impersonate (
	krb5_context,
	krb5_get_creds_opt,
	krb5_const_principal);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_get_creds_opt_set_options (
	krb5_context,
	krb5_get_creds_opt,
	krb5_flags);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_creds_opt_set_ticket (
	krb5_context,
	krb5_get_creds_opt,
	const Ticket*);

/**
 * Get the global configuration list.
 *
 * @param pfilenames return array of filenames, should be freed with krb5_free_config_files().
 *
 * @return Returns 0 to indicate success.  Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_default_config_files (char***);

/**
 * Get the default encryption types that will be use in communcation
 * with the KDC, clients and servers.
 *
 * @param context Kerberos 5 context.
 * @param pdu_type request type (AS, TGS or none)
 * @param etypes Encryption types, array terminated with
 * ETYPE_NULL(0), caller should free array with krb5_xfree():
 *
 * @return Returns 0 to indicate success. Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_default_in_tkt_etypes (
	krb5_context,
	krb5_pdu,
	krb5_enctype**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_default_principal (
	krb5_context,
	krb5_principal*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_default_realm (
	krb5_context,
	krb5_realm*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_default_realms (
	krb5_context,
	krb5_realm**);

/**
 * Get if the library uses DNS to canonicalize hostnames.
 *
 * @param context Kerberos 5 context.
 *
 * @return return non zero if the library uses DNS to canonicalize hostnames.
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_get_dns_canonicalize_hostname (krb5_context);

/**
 * Return the error string for the error code. The caller must not
 * free the string.
 *
 * This function is deprecated since its not threadsafe.
 *
 * @param context Kerberos 5 context.
 * @param code Kerberos error code.
 *
 * @return the error message matching code
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_get_err_text (
	krb5_context,
	krb5_error_code)
     KRB5_DEPRECATED_FUNCTION("Use krb5_get_error_message instead");

/**
 * Return the error message for `code' in context. On memory
 * allocation error the function returns NULL.
 *
 * @param context Kerberos 5 context
 * @param code Error code related to the error
 *
 * @return an error string, needs to be freed with
 * krb5_free_error_message(). The functions return NULL on error.
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_get_error_message (
	krb5_context,
	krb5_error_code);

/**
 * Return the error message in context. On error or no error string,
 * the function returns NULL.
 *
 * @param context Kerberos 5 context
 *
 * @return an error string, needs to be freed with
 * krb5_free_error_message(). The functions return NULL on error.
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION char* KRB5_LIB_CALL
krb5_get_error_string (krb5_context)
     KRB5_DEPRECATED_FUNCTION("Use krb5_get_error_message instead");

/**
 * Get extra address to the address list that the library will add to
 * the client's address list when communicating with the KDC.
 *
 * @param context Kerberos 5 context.
 * @param addresses addreses to set
 *
 * @return Returns 0 to indicate success. Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_extra_addresses (
	krb5_context,
	krb5_addresses*);

/**
 * Get version of fcache that the library should use.
 *
 * @param context Kerberos 5 context.
 * @param version version number.
 *
 * @return Returns 0 to indicate success. Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_fcache_version (
	krb5_context,
	int*);

/**
 * Gets tickets forwarded to hostname. If the tickets that are
 * forwarded are address-less, the forwarded tickets will also be
 * address-less.
 *
 * If the ticket have any address, hostname will be used for figure
 * out the address to forward the ticket too. This since this might
 * use DNS, its insecure and also doesn't represent configured all
 * addresses of the host. For example, the host might have two
 * adresses, one IPv4 and one IPv6 address where the later is not
 * published in DNS. This IPv6 address might be used communications
 * and thus the resulting ticket useless.
 *
 * @param context A kerberos 5 context.
 * @param auth_context the auth context with the key to encrypt the out_data.
 * @param ccache credential cache to use
 * @param flags the flags to control the resulting ticket flags
 * @param hostname the host to forward the tickets too.
 * @param in_creds the in client and server ticket names.  The client
 * and server components forwarded to the remote host.
 * @param out_data the resulting credential.
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_credential
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_forwarded_creds (
	krb5_context,
	krb5_auth_context,
	krb5_ccache,
	krb5_flags,
	const char*,
	krb5_creds*,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_host_realm (
	krb5_context,
	const char*,
	krb5_realm**);

/**
 * Get extra addresses to ignore when fetching addresses from the
 * underlaying operating system.
 *
 * @param context Kerberos 5 context.
 * @param addresses list addreses ignored
 *
 * @return Returns 0 to indicate success. Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_ignore_addresses (
	krb5_context,
	krb5_addresses*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_in_cred (
	krb5_context,
	krb5_flags,
	const krb5_addresses*,
	const krb5_enctype*,
	const krb5_preauthtype*,
	const krb5_preauthdata*,
	krb5_key_proc,
	krb5_const_pointer,
	krb5_decrypt_proc,
	krb5_const_pointer,
	krb5_creds*,
	krb5_kdc_rep*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_in_tkt (
	krb5_context,
	krb5_flags,
	const krb5_addresses*,
	const krb5_enctype*,
	const krb5_preauthtype*,
	krb5_key_proc,
	krb5_const_pointer,
	krb5_decrypt_proc,
	krb5_const_pointer,
	krb5_creds*,
	krb5_ccache,
	krb5_kdc_rep*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

/**
 * Deprecated: use krb5_get_init_creds() and friends.
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_in_tkt_with_keytab (
	krb5_context,
	krb5_flags,
	krb5_addresses*,
	const krb5_enctype*,
	const krb5_preauthtype*,
	krb5_keytab,
	krb5_ccache,
	krb5_creds*,
	krb5_kdc_rep*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

/**
 * Deprecated: use krb5_get_init_creds() and friends.
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_in_tkt_with_password (
	krb5_context,
	krb5_flags,
	krb5_addresses*,
	const krb5_enctype*,
	const krb5_preauthtype*,
	const char*,
	krb5_ccache,
	krb5_creds*,
	krb5_kdc_rep*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

/**
 * Deprecated: use krb5_get_init_creds() and friends.
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_in_tkt_with_skey (
	krb5_context,
	krb5_flags,
	krb5_addresses*,
	const krb5_enctype*,
	const krb5_preauthtype*,
	const krb5_keyblock*,
	krb5_ccache,
	krb5_creds*,
	krb5_kdc_rep*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

/**
 * Get new credentials using keyblock.
 *
 * @ingroup krb5_credential
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_init_creds_keyblock (
	krb5_context,
	krb5_creds*,
	krb5_principal,
	krb5_keyblock*,
	krb5_deltat,
	const char*,
	krb5_get_init_creds_opt*);

/**
 * Get new credentials using keytab.
 *
 * @ingroup krb5_credential
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_init_creds_keytab (
	krb5_context,
	krb5_creds*,
	krb5_principal,
	krb5_keytab,
	krb5_deltat,
	const char*,
	krb5_get_init_creds_opt*);

/**
 * Allocate a new krb5_get_init_creds_opt structure, free with
 * krb5_get_init_creds_opt_free().
 *
 * @ingroup krb5_credential
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_init_creds_opt_alloc (
	krb5_context,
	krb5_get_init_creds_opt**);

/**
 * Free krb5_get_init_creds_opt structure.
 *
 * @ingroup krb5_credential
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_get_init_creds_opt_free (
	krb5_context,
	krb5_get_init_creds_opt*);

/**
 * Deprecated: use the new krb5_init_creds_init() and
 * krb5_init_creds_get_error().
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_init_creds_opt_get_error (
	krb5_context,
	krb5_get_init_creds_opt*,
	KRB_ERROR**)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

/**
 * Deprecated: use krb5_get_init_creds_opt_alloc().
 *
 * The reason krb5_get_init_creds_opt_init() is deprecated is that
 * krb5_get_init_creds_opt is a static structure and for ABI reason it
 * can't grow, ie can't add new functionality.
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_get_init_creds_opt_init (krb5_get_init_creds_opt*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_get_init_creds_opt_set_address_list (
	krb5_get_init_creds_opt*,
	krb5_addresses*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_init_creds_opt_set_addressless (
	krb5_context,
	krb5_get_init_creds_opt*,
	krb5_boolean);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_get_init_creds_opt_set_anonymous (
	krb5_get_init_creds_opt*,
	int);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_init_creds_opt_set_canonicalize (
	krb5_context,
	krb5_get_init_creds_opt*,
	krb5_boolean);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_get_init_creds_opt_set_change_password_prompt (
	krb5_get_init_creds_opt*,
	int);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_get_init_creds_opt_set_default_flags (
	krb5_context,
	const char*,
	krb5_const_realm,
	krb5_get_init_creds_opt*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_get_init_creds_opt_set_etype_list (
	krb5_get_init_creds_opt*,
	krb5_enctype*,
	int);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_get_init_creds_opt_set_forwardable (
	krb5_get_init_creds_opt*,
	int);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_init_creds_opt_set_pa_password (
	krb5_context,
	krb5_get_init_creds_opt*,
	const char*,
	krb5_s2k_proc);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_init_creds_opt_set_pac_request (
	krb5_context,
	krb5_get_init_creds_opt*,
	krb5_boolean);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_init_creds_opt_set_pkinit (
	krb5_context,
	krb5_get_init_creds_opt*,
	krb5_principal,
	const char*,
	const char*,
	char* const*,
	char* const*,
	int,
	krb5_prompter_fct,
	void*,
	char*);

krb5_error_code KRB5_LIB_FUNCTION
krb5_get_init_creds_opt_set_pkinit_user_certs (
	krb5_context,
	krb5_get_init_creds_opt*,
	struct hx509_certs_data*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_get_init_creds_opt_set_preauth_list (
	krb5_get_init_creds_opt*,
	krb5_preauthtype*,
	int);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_init_creds_opt_set_process_last_req (
	krb5_context,
	krb5_get_init_creds_opt*,
	krb5_gic_process_last_req,
	void*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_get_init_creds_opt_set_proxiable (
	krb5_get_init_creds_opt*,
	int);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_get_init_creds_opt_set_renew_life (
	krb5_get_init_creds_opt*,
	krb5_deltat);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_get_init_creds_opt_set_salt (
	krb5_get_init_creds_opt*,
	krb5_data*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_get_init_creds_opt_set_tkt_life (
	krb5_get_init_creds_opt*,
	krb5_deltat);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_init_creds_opt_set_win2k (
	krb5_context,
	krb5_get_init_creds_opt*,
	krb5_boolean);

/**
 * Get new credentials using password.
 *
 * @ingroup krb5_credential
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_init_creds_password (
	krb5_context,
	krb5_creds*,
	krb5_principal,
	const char*,
	krb5_prompter_fct,
	void*,
	krb5_deltat,
	const char*,
	krb5_get_init_creds_opt*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_kdc_cred (
	krb5_context,
	krb5_ccache,
	krb5_kdc_flags,
	krb5_addresses*,
	Ticket*,
	krb5_creds*,
	krb5_creds**out_creds );

/**
 * Get current offset in time to the KDC.
 *
 * @param context Kerberos 5 context.
 * @param sec seconds part of offset.
 * @param usec micro seconds part of offset.
 *
 * @return returns zero
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_kdc_sec_offset (
	krb5_context,
	int32_t*,
	int32_t*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_krb524hst (
	krb5_context,
	const krb5_realm*,
	char***);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_krb_admin_hst (
	krb5_context,
	const krb5_realm*,
	char***);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_krb_changepw_hst (
	krb5_context,
	const krb5_realm*,
	char***);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_krbhst (
	krb5_context,
	const krb5_realm*,
	char***);

/**
 * Get max time skew allowed.
 *
 * @param context Kerberos 5 context.
 *
 * @return timeskew in seconds.
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION time_t KRB5_LIB_CALL
krb5_get_max_time_skew (krb5_context);

/**
     * krb5_init_context() will get one random byte to make sure our
     * random is alive.  Assumption is that once the non blocking
     * source allows us to pull bytes, its all seeded and allows us to
     * pull more bytes.
     *
     * Most Kerberos users calls krb5_init_context(), so this is
     * useful point where we can do the checking.
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_permitted_enctypes (
	krb5_context,
	krb5_enctype**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_pw_salt (
	krb5_context,
	krb5_const_principal,
	krb5_salt*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_renewed_creds (
	krb5_context,
	krb5_creds*,
	krb5_const_principal,
	krb5_ccache,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_server_rcache (
	krb5_context,
	const krb5_data*,
	krb5_rcache*);

/**
 * Make the kerberos library default to the admin KDC.
 *
 * @param context Kerberos 5 context.
 *
 * @return boolean flag to telling the context will use admin KDC as the default KDC.
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_get_use_admin_kdc (krb5_context);

/**
 * Validate the newly fetch credential, see also krb5_verify_init_creds().
 *
 * @param context a Kerberos 5 context
 * @param creds the credentials to verify
 * @param client the client name to match up
 * @param ccache the credential cache to use
 * @param service a service name to use, used with
 *        krb5_sname_to_principal() to build a hostname to use to
 *        verify.
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_validated_creds (
	krb5_context,
	krb5_creds*,
	krb5_principal,
	krb5_ccache,
	char*);

/**
 * Get the default logging facility.
 *
 * @param context A Kerberos 5 context
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION krb5_log_facility* KRB5_LIB_CALL
krb5_get_warn_dest (krb5_context);

KRB5_LIB_FUNCTION size_t KRB5_LIB_CALL
krb5_get_wrapped_length (
	krb5_context,
	krb5_crypto,
	size_t);

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_getportbyname (
	krb5_context,
	const char*,
	const char*,
	int);

/**
 * krb5_h_addr2addr works like krb5_h_addr2sockaddr with the exception
 * that it operates on a krb5_address instead of a struct sockaddr.
 *
 * @param context a Keberos context
 * @param af address family
 * @param haddr host address from struct hostent.
 * @param addr returned krb5_address.
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_address
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_h_addr2addr (
	krb5_context,
	int,
	const char*,
	krb5_address*);

/**
 * krb5_h_addr2sockaddr initializes a "struct sockaddr sa" from af and
 * the "struct hostent" (see gethostbyname(3) ) h_addr_list
 * component. The argument sa_size should initially contain the size
 * of the sa, and after the call, it will contain the actual length of
 * the address.
 *
 * @param context a Keberos context
 * @param af addresses
 * @param addr address
 * @param sa returned struct sockaddr
 * @param sa_size size of sa
 * @param port port to set in sa.
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_address
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_h_addr2sockaddr (
	krb5_context,
	int,
	const char*,
	struct sockaddr*,
	krb5_socklen_t*,
	int);

/**
 * Convert the gethostname() error code (h_error) to a Kerberos et
 * error code.
 *
 * @param eai_errno contains the error code from gethostname().
 *
 * @return Kerberos error code representing the gethostname errors.
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_h_errno_to_heim_errno (int);

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_have_error_string (krb5_context)
     KRB5_DEPRECATED_FUNCTION("Use krb5_get_error_message instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_hmac (
	krb5_context,
	krb5_cksumtype,
	const void*,
	size_t,
	unsigned,
	krb5_keyblock*,
	Checksum*);

/**
 * Initializes the context structure and reads the configuration file
 * /etc/krb5.conf. The structure should be freed by calling
 * krb5_free_context() when it is no longer being used.
 *
 * @param context pointer to returned context
 *
 * @return Returns 0 to indicate success.  Otherwise an errno code is
 * returned.  Failure means either that something bad happened during
 * initialization (typically ENOMEM) or that Kerberos should not be
 * used ENXIO. If the function returns HEIM_ERR_RANDOM_OFFLINE, the
 * random source is not available and later Kerberos calls might fail.
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_init_context (krb5_context*);

/**
 * Free the krb5_init_creds_context allocated by krb5_init_creds_init().
 *
 * @param context A Kerberos 5 context.
 * @param ctx The krb5_init_creds_context to free.
 *
 * @ingroup krb5_credential
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_init_creds_free (
	krb5_context,
	krb5_init_creds_context);

/**
 * Get new credentials as setup by the krb5_init_creds_context.
 *
 * @param context A Kerberos 5 context.
 * @param ctx The krb5_init_creds_context to process.
 *
 * @ingroup krb5_credential
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_init_creds_get (
	krb5_context,
	krb5_init_creds_context);

/**
 * Extract the newly acquired credentials from krb5_init_creds_context
 * context.
 *
 * @param context A Kerberos 5 context.
 * @param ctx
 * @param cred credentials, free with krb5_free_cred_contents().
 *
 * @return 0 for sucess or An Kerberos error code, see krb5_get_error_message().
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_init_creds_get_creds (
	krb5_context,
	krb5_init_creds_context,
	krb5_creds*);

/**
 * Get the last error from the transaction.
 *
 * @return Returns 0 or an error code
 *
 * @ingroup krb5_credential
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_init_creds_get_error (
	krb5_context,
	krb5_init_creds_context,
	KRB_ERROR*);

/**
 * Start a new context to get a new initial credential.
 *
 * @param context A Kerberos 5 context.
 * @param client The Kerberos principal to get the credential for, if
 *     NULL is given, the default principal is used as determined by
 *     krb5_get_default_principal().
 * @param prompter
 * @param prompter_data
 * @param start_time the time the ticket should start to be valid or 0 for now.
 * @param options a options structure, can be NULL for default options.
 * @param rctx A new allocated free with krb5_init_creds_free().
 *
 * @return 0 for success or an Kerberos 5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_credential
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_init_creds_init (
	krb5_context,
	krb5_principal,
	krb5_prompter_fct,
	void*,
	krb5_deltat,
	krb5_get_init_creds_opt*,
	krb5_init_creds_context*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_init_creds_set_fast_ap_armor_service (
	krb5_context,
	krb5_init_creds_context,
	krb5_const_principal);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_init_creds_set_fast_ccache (
	krb5_context,
	krb5_init_creds_context,
	krb5_ccache);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_init_creds_set_keyblock (
	krb5_context,
	krb5_init_creds_context,
	krb5_keyblock*);

/**
 * Set the keytab to use for authentication.
 *
 * @param context a Kerberos 5 context.
 * @param ctx ctx krb5_init_creds_context context.
 * @param keytab the keytab to read the key from.
 *
 * @return 0 for success, or an Kerberos 5 error code, see krb5_get_error_message().
 * @ingroup krb5_credential
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_init_creds_set_keytab (
	krb5_context,
	krb5_init_creds_context,
	krb5_keytab);

/**
 * Sets the password that will use for the request.
 *
 * @param context a Kerberos 5 context.
 * @param ctx ctx krb5_init_creds_context context.
 * @param password the password to use.
 *
 * @return 0 for success, or an Kerberos 5 error code, see krb5_get_error_message().
 * @ingroup krb5_credential
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_init_creds_set_password (
	krb5_context,
	krb5_init_creds_context,
	const char*);

/**
 * Sets the service that the is requested. This call is only neede for
 * special initial tickets, by default the a krbtgt is fetched in the default realm.
 *
 * @param context a Kerberos 5 context.
 * @param ctx a krb5_init_creds_context context.
 * @param service the service given as a string, for example
 *        "kadmind/admin". If NULL, the default krbtgt in the clients
 *        realm is set.
 *
 * @return 0 for success, or an Kerberos 5 error code, see krb5_get_error_message().
 * @ingroup krb5_credential
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_init_creds_set_service (
	krb5_context,
	krb5_init_creds_context,
	const char*);

/**
 * The core loop if krb5_get_init_creds() function family. Create the
 * packets and have the caller send them off to the KDC.
 *
 * If the caller want all work been done for them, use
 * krb5_init_creds_get() instead.
 *
 * @param context a Kerberos 5 context.
 * @param ctx ctx krb5_init_creds_context context.
 * @param in input data from KDC, first round it should be reset by krb5_data_zer().
 * @param out reply to KDC.
 * @param hostinfo KDC address info, first round it can be NULL.
 * @param flags status of the round, if
 *        KRB5_INIT_CREDS_STEP_FLAG_CONTINUE is set, continue one more round.
 *
 * @return 0 for success, or an Kerberos 5 error code, see
 *     krb5_get_error_message().
 *
 * @ingroup krb5_credential
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_init_creds_step (
	krb5_context,
	krb5_init_creds_context,
	krb5_data*,
	krb5_data*,
	krb5_krbhst_info*,
	unsigned int*);

/**
 *
 * @ingroup krb5_credential
 */

krb5_error_code
krb5_init_creds_store (
	krb5_context,
	krb5_init_creds_context,
	krb5_ccache);

/**
 * Init the built-in ets in the Kerberos library.
 *
 * @param context kerberos context to add the ets too
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_init_ets (krb5_context);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_initlog (
	krb5_context,
	const char*,
	krb5_log_facility**);

/**
 * Return TRUE (non zero) if the principal is a configuration
 * principal (generated part of krb5_cc_set_config()). Returns FALSE
 * (zero) if not a configuration principal.
 *
 * @param context a Keberos context
 * @param principal principal to check if it a configuration principal
 *
 * @ingroup krb5_ccache
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_is_config_principal (
	krb5_context,
	krb5_const_principal);

/**
 * Returns is the encryption is strong or weak
 *
 * @param context Kerberos 5 context
 * @param enctype encryption type to probe
 *
 * @return Returns true if encryption type is weak or is not supported.
 *
 * @ingroup krb5_crypto
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_is_enctype_weak (
	krb5_context,
	krb5_enctype);

/**
 * Runtime check if the Kerberos library was complied with thread support.
 *
 * @return TRUE if the library was compiled with thread support, FALSE if not.
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_is_thread_safe (void);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_kcm_call (
	krb5_context,
	krb5_storage*,
	krb5_storage**,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_kcm_storage_request (
	krb5_context,
	uint16_t,
	krb5_storage**);

/**
 * Returns the list of Kerberos encryption types sorted in order of
 * most preferred to least preferred encryption type.  Note that some
 * encryption types might be disabled, so you need to check with
 * krb5_enctype_valid() before using the encryption type.
 *
 * @return list of enctypes, terminated with ETYPE_NULL. Its a static
 * array completed into the Kerberos library so the content doesn't
 * need to be freed.
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION const krb5_enctype* KRB5_LIB_CALL
krb5_kerberos_enctypes (krb5_context);

/**
 * Get encryption type of a keyblock.
 *
 * @ingroup krb5_crypto
 */

KRB5_LIB_FUNCTION krb5_enctype KRB5_LIB_CALL
krb5_keyblock_get_enctype (const krb5_keyblock*);

/**
 * Fill in `key' with key data of type `enctype' from `data' of length
 * `size'. Key should be freed using krb5_free_keyblock_contents().
 *
 * @return 0 on success or a Kerberos 5 error code
 *
 * @ingroup krb5_crypto
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_keyblock_init (
	krb5_context,
	krb5_enctype,
	const void*,
	size_t,
	krb5_keyblock*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_keyblock_key_proc (
	krb5_context,
	krb5_keytype,
	krb5_data*,
	krb5_const_pointer,
	krb5_keyblock**);

/**
 * Zero out a keyblock
 *
 * @param keyblock keyblock to zero out
 *
 * @ingroup krb5_crypto
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_keyblock_zero (krb5_keyblock*);

/**
 * Deprecated: use krb5_get_init_creds() and friends.
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_CALLCONV
krb5_keytab_key_proc (
	krb5_context,
	krb5_enctype,
	krb5_salt,
	krb5_const_pointer,
	krb5_keyblock**)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

/**
 * Deprecated: keytypes doesn't exists, they are really enctypes.
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_keytype_to_enctypes (
	krb5_context,
	krb5_keytype,
	unsigned*,
	krb5_enctype**)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

/**
 * Deprecated: keytypes doesn't exists, they are really enctypes.
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_keytype_to_enctypes_default (
	krb5_context,
	krb5_keytype,
	unsigned*,
	krb5_enctype**)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

/**
 * Deprecated: keytypes doesn't exists, they are really enctypes in
 * most cases, use krb5_enctype_to_string().
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_keytype_to_string (
	krb5_context,
	krb5_keytype,
	char**)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_krbhst_format_string (
	krb5_context,
	const krb5_krbhst_info*,
	char*,
	size_t);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_krbhst_free (
	krb5_context,
	krb5_krbhst_handle);

/**
 * Return an `struct addrinfo *' for a KDC host.
 *
 * Returns an the struct addrinfo in in that corresponds to the
 * information in `host'.  free:ing is handled by krb5_krbhst_free, so
 * the returned ai must not be released.
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_krbhst_get_addrinfo (
	krb5_context,
	krb5_krbhst_info*,
	struct addrinfo**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_krbhst_init (
	krb5_context,
	const char*,
	unsigned int,
	krb5_krbhst_handle*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_krbhst_init_flags (
	krb5_context,
	const char*,
	unsigned int,
	int,
	krb5_krbhst_handle*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_krbhst_next (
	krb5_context,
	krb5_krbhst_handle,
	krb5_krbhst_info**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_krbhst_next_as_string (
	krb5_context,
	krb5_krbhst_handle,
	char*,
	size_t);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_krbhst_reset (
	krb5_context,
	krb5_krbhst_handle);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_krbhst_set_hostname (
	krb5_context,
	krb5_krbhst_handle,
	const char*);

/**
 * Add the entry in `entry' to the keytab `id'.
 *
 * @param context a Keberos context.
 * @param id a keytab.
 * @param entry the entry to add
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_keytab
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_kt_add_entry (
	krb5_context,
	krb5_keytab,
	krb5_keytab_entry*);

/**
 * Finish using the keytab in `id'.  All resources will be released,
 * even on errors.
 *
 * @param context a Keberos context.
 * @param id keytab to close.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_keytab
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_kt_close (
	krb5_context,
	krb5_keytab);

/**
 * Compare `entry' against `principal, vno, enctype'.
 * Any of `principal, vno, enctype' might be 0 which acts as a wildcard.
 * Return TRUE if they compare the same, FALSE otherwise.
 *
 * @param context a Keberos context.
 * @param entry an entry to match with.
 * @param principal principal to match, NULL matches all principals.
 * @param vno key version to match, 0 matches all key version numbers.
 * @param enctype encryption type to match, 0 matches all encryption types.
 *
 * @return Return TRUE or match, FALSE if not matched.
 *
 * @ingroup krb5_keytab
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_kt_compare (
	krb5_context,
	krb5_keytab_entry*,
	krb5_const_principal,
	krb5_kvno,
	krb5_enctype);

/**
 * Copy the contents of `in' into `out'.
 *
 * @param context a Keberos context.
 * @param in the keytab entry to copy.
 * @param out the copy of the keytab entry, free with krb5_kt_free_entry().
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_keytab
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_kt_copy_entry_contents (
	krb5_context,
	const krb5_keytab_entry*,
	krb5_keytab_entry*);

/**
 * Set `id' to the default keytab.
 *
 * @param context a Keberos context.
 * @param id the new default keytab.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_keytab
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_kt_default (
	krb5_context,
	krb5_keytab*);

/**
 * Copy the name of the default modify keytab into `name'.
 *
 * @param context a Keberos context.
 * @param name buffer where the name will be written
 * @param namesize length of name
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_keytab
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_kt_default_modify_name (
	krb5_context,
	char*,
	size_t);

/**
 * copy the name of the default keytab into `name'.
 *
 * @param context a Keberos context.
 * @param name buffer where the name will be written
 * @param namesize length of name
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_keytab
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_kt_default_name (
	krb5_context,
	char*,
	size_t);

/**
 * Destroy (remove) the keytab in `id'.  All resources will be released,
 * even on errors, does the equvalment of krb5_kt_close() on the resources.
 *
 * @param context a Keberos context.
 * @param id keytab to destroy.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_keytab
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_kt_destroy (
	krb5_context,
	krb5_keytab);

/**
 * Release all resources associated with `cursor'.
 *
 * @param context a Keberos context.
 * @param id a keytab.
 * @param cursor the cursor to free.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_keytab
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_kt_end_seq_get (
	krb5_context,
	krb5_keytab,
	krb5_kt_cursor*);

/**
 * Free the contents of `entry'.
 *
 * @param context a Keberos context.
 * @param entry the entry to free
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_keytab
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_kt_free_entry (
	krb5_context,
	krb5_keytab_entry*);

/**
 * Retrieve the keytab entry for `principal, kvno, enctype' into `entry'
 * from the keytab `id'. Matching is done like krb5_kt_compare().
 *
 * @param context a Keberos context.
 * @param id a keytab.
 * @param principal principal to match, NULL matches all principals.
 * @param kvno key version to match, 0 matches all key version numbers.
 * @param enctype encryption type to match, 0 matches all encryption types.
 * @param entry the returned entry, free with krb5_kt_free_entry().
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_keytab
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_kt_get_entry (
	krb5_context,
	krb5_keytab,
	krb5_const_principal,
	krb5_kvno,
	krb5_enctype,
	krb5_keytab_entry*);

/**
 * Retrieve the full name of the keytab `keytab' and store the name in
 * `str'.
 *
 * @param context a Keberos context.
 * @param keytab keytab to get name for.
 * @param str the name of the keytab name, usee krb5_xfree() to free
 *        the string.  On error, *str is set to NULL.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_keytab
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_kt_get_full_name (
	krb5_context,
	krb5_keytab,
	char**);

/**
 * Retrieve the name of the keytab `keytab' into `name', `namesize'
 *
 * @param context a Keberos context.
 * @param keytab the keytab to get the name for.
 * @param name name buffer.
 * @param namesize size of name buffer.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_keytab
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_kt_get_name (
	krb5_context,
	krb5_keytab,
	char*,
	size_t);

/**
 * Return the type of the `keytab' in the string `prefix of length
 * `prefixsize'.
 *
 * @param context a Keberos context.
 * @param keytab the keytab to get the prefix for
 * @param prefix prefix buffer
 * @param prefixsize length of prefix buffer
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_keytab
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_kt_get_type (
	krb5_context,
	krb5_keytab,
	char*,
	size_t);

/**
 * Return true if the keytab exists and have entries
 *
 * @param context a Keberos context.
 * @param id a keytab.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_keytab
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_kt_have_content (
	krb5_context,
	krb5_keytab);

/**
 * Get the next entry from keytab, advance the cursor.  On last entry
 * the function will return KRB5_KT_END.
 *
 * @param context a Keberos context.
 * @param id a keytab.
 * @param entry the returned entry, free with krb5_kt_free_entry().
 * @param cursor the cursor of the iteration.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_keytab
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_kt_next_entry (
	krb5_context,
	krb5_keytab,
	krb5_keytab_entry*,
	krb5_kt_cursor*);

/**
 * Read the key identified by `(principal, vno, enctype)' from the
 * keytab in `keyprocarg' (the default if == NULL) into `*key'.
 *
 * @param context a Keberos context.
 * @param keyprocarg
 * @param principal
 * @param vno
 * @param enctype
 * @param key
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_keytab
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_kt_read_service_key (
	krb5_context,
	krb5_pointer,
	krb5_principal,
	krb5_kvno,
	krb5_enctype,
	krb5_keyblock**);

/**
 * Register a new keytab backend.
 *
 * @param context a Keberos context.
 * @param ops a backend to register.
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_keytab
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_kt_register (
	krb5_context,
	const krb5_kt_ops*);

/**
 * Remove an entry from the keytab, matching is done using
 * krb5_kt_compare().

 * @param context a Keberos context.
 * @param id a keytab.
 * @param entry the entry to remove
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_keytab
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_kt_remove_entry (
	krb5_context,
	krb5_keytab,
	krb5_keytab_entry*);

/**
 * Resolve the keytab name (of the form `type:residual') in `name'
 * into a keytab in `id'.
 *
 * @param context a Keberos context.
 * @param name name to resolve
 * @param id resulting keytab, free with krb5_kt_close().
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_keytab
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_kt_resolve (
	krb5_context,
	const char*,
	krb5_keytab*);

/**
 * Set `cursor' to point at the beginning of `id'.
 *
 * @param context a Keberos context.
 * @param id a keytab.
 * @param cursor a newly allocated cursor, free with krb5_kt_end_seq_get().
 *
 * @return Return an error code or 0, see krb5_get_error_message().
 *
 * @ingroup krb5_keytab
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_kt_start_seq_get (
	krb5_context,
	krb5_keytab,
	krb5_kt_cursor*);

/**
 * This function takes the name of a local user and checks if
 * principal is allowed to log in as that user.
 *
 * The user may have a ~/.k5login file listing principals that are
 * allowed to login as that user. If that file does not exist, all
 * principals with a only one component that is identical to the
 * username, and a realm considered local, are allowed access.
 *
 * The .k5login file must contain one principal per line, be owned by
 * user and not be writable by group or other (but must be readable by
 * anyone).
 *
 * Note that if the file exists, no implicit access rights are given
 * to user@@LOCALREALM.
 *
 * Optionally, a set of files may be put in ~/.k5login.d (a
 * directory), in which case they will all be checked in the same
 * manner as .k5login.  The files may be called anything, but files
 * starting with a hash (#) , or ending with a tilde (~) are
 * ignored. Subdirectories are not traversed. Note that this directory
 * may not be checked by other Kerberos implementations.
 *
 * If no configuration file exists, match user against local domains,
 * ie luser@@LOCAL-REALMS-IN-CONFIGURATION-FILES.
 *
 * @param context Kerberos 5 context.
 * @param principal principal to check if allowed to login
 * @param luser local user id
 *
 * @return returns TRUE if access should be granted, FALSE otherwise.
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_kuserok (
	krb5_context,
	krb5_principal,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_log (
	krb5_context,
	krb5_log_facility*,
	int,
	const char*,
	...)
     __attribute__ ((__format__ (__printf__, 4, 5)));

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_log_msg (
	krb5_context,
	krb5_log_facility*,
	int,
	char**,
	const char*,
	...)
     __attribute__ ((__format__ (__printf__, 5, 6)));

/**
 * Create an address of type KRB5_ADDRESS_ADDRPORT from (addr, port)
 *
 * @param context a Keberos context
 * @param res built address from addr/port
 * @param addr address to use
 * @param port port to use
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_address
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_make_addrport (
	krb5_context,
	krb5_address**,
	const krb5_address*,
	int16_t);

/**
 * Build a principal using vararg style building
 *
 * @param context A Kerberos context.
 * @param principal returned principal
 * @param realm realm name
 * @param ... a list of components ended with NULL.
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_make_principal (
	krb5_context,
	krb5_principal*,
	krb5_const_realm,
	...);

/**
 * krb5_max_sockaddr_size returns the max size of the .Li struct
 * sockaddr that the Kerberos library will return.
 *
 * @return Return an size_t of the maximum struct sockaddr.
 *
 * @ingroup krb5_address
 */

KRB5_LIB_FUNCTION size_t KRB5_LIB_CALL
krb5_max_sockaddr_size (void);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_mk_error (
	krb5_context,
	krb5_error_code,
	const char*,
	const krb5_data*,
	const krb5_principal,
	const krb5_principal,
	time_t*,
	int*,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_mk_error_ext (
	krb5_context,
	krb5_error_code,
	const char*,
	const krb5_data*,
	const krb5_principal,
	const PrincipalName*,
	const Realm*,
	time_t*,
	int*,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_mk_priv (
	krb5_context,
	krb5_auth_context,
	const krb5_data*,
	krb5_data*,
	krb5_replay_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_mk_rep (
	krb5_context,
	krb5_auth_context,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_mk_req (
	krb5_context,
	krb5_auth_context*,
	const krb5_flags,
	const char*,
	const char*,
	krb5_data*,
	krb5_ccache,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_mk_req_exact (
	krb5_context,
	krb5_auth_context*,
	const krb5_flags,
	const krb5_principal,
	krb5_data*,
	krb5_ccache,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_mk_req_extended (
	krb5_context,
	krb5_auth_context*,
	const krb5_flags,
	krb5_data*,
	krb5_creds*,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_mk_safe (
	krb5_context,
	krb5_auth_context,
	const krb5_data*,
	krb5_data*,
	krb5_replay_data*);

/**
 * Iteratively apply name canon rules, outputing a principal and rule
 * options each time.  Iteration completes when the @iter is NULL on
 * return or when an error is returned.  Callers must free the iterator
 * if they abandon it mid-way.
 *
 * @param context   Kerberos context
 * @param iter	    name canon rule iterator (input/output)
 * @param try_princ output principal name
 * @param rule_opts output rule options
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_name_canon_iterate (
	krb5_context,
	krb5_name_canon_iterator*,
	krb5_const_principal*,
	krb5_name_canon_rule_options*);

/**
 * Initialize name canonicalization iterator.
 *
 * @param context   Kerberos context
 * @param in_princ  principal name to be canonicalized OR
 * @param iter	    output iterator object
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_name_canon_iterator_start (
	krb5_context,
	krb5_const_principal,
	krb5_name_canon_iterator*);

/**
 * Read \a len bytes from socket \a p_fd into buffer \a buf.
 * Block until \a len bytes are read or until an error.
 *
 * @return If successful, the number of bytes read: \a len.
 *         On end-of-file, 0.
 *         On error, less than 0 (if single-threaded, the error can be found
 *         in the errno global variable).
 */

KRB5_LIB_FUNCTION krb5_ssize_t KRB5_LIB_CALL
krb5_net_read (
	krb5_context,
	void*,
	void*,
	size_t);

KRB5_LIB_FUNCTION krb5_ssize_t KRB5_LIB_CALL
krb5_net_write (
	krb5_context,
	void*,
	const void*,
	size_t);

KRB5_LIB_FUNCTION krb5_ssize_t KRB5_LIB_CALL
krb5_net_write_block (
	krb5_context,
	void*,
	const void*,
	size_t,
	time_t);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_alloc (
	krb5_context,
	krb5_ntlm*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_free (
	krb5_context,
	krb5_ntlm);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_init_get_challenge (
	krb5_context,
	krb5_ntlm,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_init_get_flags (
	krb5_context,
	krb5_ntlm,
	uint32_t*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_init_get_opaque (
	krb5_context,
	krb5_ntlm,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_init_get_targetinfo (
	krb5_context,
	krb5_ntlm,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_init_get_targetname (
	krb5_context,
	krb5_ntlm,
	char**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_init_request (
	krb5_context,
	krb5_ntlm,
	krb5_realm,
	krb5_ccache,
	uint32_t,
	const char*,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_rep_get_sessionkey (
	krb5_context,
	krb5_ntlm,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_ntlm_rep_get_status (
	krb5_context,
	krb5_ntlm);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_req_set_flags (
	krb5_context,
	krb5_ntlm,
	uint32_t);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_req_set_lm (
	krb5_context,
	krb5_ntlm,
	void*,
	size_t);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_req_set_ntlm (
	krb5_context,
	krb5_ntlm,
	void*,
	size_t);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_req_set_opaque (
	krb5_context,
	krb5_ntlm,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_req_set_session (
	krb5_context,
	krb5_ntlm,
	void*,
	size_t);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_req_set_targetname (
	krb5_context,
	krb5_ntlm,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_req_set_username (
	krb5_context,
	krb5_ntlm,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ntlm_request (
	krb5_context,
	krb5_ntlm,
	krb5_realm,
	krb5_ccache);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_openlog (
	krb5_context,
	const char*,
	krb5_log_facility**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_pac_add_buffer (
	krb5_context,
	krb5_pac,
	uint32_t,
	const krb5_data*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_pac_free (
	krb5_context,
	krb5_pac);

/**
 * Get the PAC buffer of specific type from the pac.
 *
 * @param context Kerberos 5 context.
 * @param p the pac structure returned by krb5_pac_parse().
 * @param type type of buffer to get
 * @param data return data, free with krb5_data_free().
 *
 * @return Returns 0 to indicate success. Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5_pac
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_pac_get_buffer (
	krb5_context,
	krb5_pac,
	uint32_t,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_pac_get_types (
	krb5_context,
	krb5_pac,
	size_t*,
	uint32_t**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_pac_init (
	krb5_context,
	krb5_pac*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_pac_parse (
	krb5_context,
	const void*,
	size_t,
	krb5_pac*);

/**
 * Verify the PAC.
 *
 * @param context Kerberos 5 context.
 * @param pac the pac structure returned by krb5_pac_parse().
 * @param authtime The time of the ticket the PAC belongs to.
 * @param principal the principal to verify.
 * @param server The service key, most always be given.
 * @param privsvr The KDC key, may be given.

 * @return Returns 0 to indicate success. Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5_pac
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_pac_verify (
	krb5_context,
	const krb5_pac,
	time_t,
	krb5_const_principal,
	const krb5_keyblock*,
	const krb5_keyblock*);

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_padata_add (
	krb5_context,
	METHOD_DATA*,
	int,
	void*,
	size_t);

/**
 * krb5_parse_address returns the resolved hostname in string to the
 * krb5_addresses addresses .
 *
 * @param context a Keberos context
 * @param string
 * @param addresses
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_address
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_parse_address (
	krb5_context,
	const char*,
	krb5_addresses*);

/**
 * Parse a name into a krb5_principal structure
 *
 * @param context Kerberos 5 context
 * @param name name to parse into a Kerberos principal
 * @param principal returned principal, free with krb5_free_principal().
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_parse_name (
	krb5_context,
	const char*,
	krb5_principal*);

/**
 * Parse a name into a krb5_principal structure, flags controls the behavior.
 *
 * @param context Kerberos 5 context
 * @param name name to parse into a Kerberos principal
 * @param flags flags to control the behavior
 * @param principal returned principal, free with krb5_free_principal().
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_parse_name_flags (
	krb5_context,
	const char*,
	int,
	krb5_principal*);

/**
 * Parse nametype string and return a nametype integer
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_parse_nametype (
	krb5_context,
	const char*,
	int32_t*);

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_passwd_result_to_string (
	krb5_context,
	int);

/**
 * Deprecated: use krb5_get_init_creds() and friends.
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_CALLCONV
krb5_password_key_proc (
	krb5_context,
	krb5_enctype,
	krb5_salt,
	krb5_const_pointer,
	krb5_keyblock**)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_pk_enterprise_cert (
	krb5_context,
	const char*,
	krb5_const_realm,
	krb5_principal*,
	struct hx509_certs_data**);

/**
 * Register a plugin symbol name of specific type.
 * @param context a Keberos context
 * @param type type of plugin symbol
 * @param name name of plugin symbol
 * @param symbol a pointer to the named symbol
 * @return In case of error a non zero error com_err error is returned
 * and the Kerberos error string is set.
 *
 * @ingroup krb5_support
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_plugin_register (
	krb5_context,
	enum krb5_plugin_type,
	const char*,
	void*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_prepend_config_files (
	const char*,
	char**,
	char***);

/**
 * Prepend the filename to the global configuration list.
 *
 * @param filelist a filename to add to the default list of filename
 * @param pfilenames return array of filenames, should be freed with krb5_free_config_files().
 *
 * @return Returns 0 to indicate success.  Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_prepend_config_files_default (
	const char*,
	char***);

/**
 * Prepend the context full error string for a specific error code.
 * The error that is stored should be internationalized.
 *
 * The if context is NULL, no error string is stored.
 *
 * @param context Kerberos 5 context
 * @param ret The error code
 * @param fmt Error string for the error code
 * @param ... printf(3) style parameters.
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_prepend_error_message (
	krb5_context,
	krb5_error_code,
	const char*,
	...)
     __attribute__ ((__format__ (__printf__, 3, 4)));

/**
 * Deprecated: use krb5_principal_get_realm()
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION krb5_realm* KRB5_LIB_CALL
krb5_princ_realm (
	krb5_context,
	krb5_principal)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

/**
 * Deprecated: use krb5_principal_set_realm()
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_princ_set_realm (
	krb5_context,
	krb5_principal,
	krb5_realm*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

/**
 * Compares the two principals, including realm of the principals and returns
 * TRUE if they are the same and FALSE if not.
 *
 * @param context Kerberos 5 context
 * @param princ1 first principal to compare
 * @param princ2 second principal to compare
 *
 * @ingroup krb5_principal
 * @see krb5_principal_compare_any_realm()
 * @see krb5_realm_compare()
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_principal_compare (
	krb5_context,
	krb5_const_principal,
	krb5_const_principal);

/**
 * Return TRUE iff princ1 == princ2 (without considering the realm)
 *
 * @param context Kerberos 5 context
 * @param princ1 first principal to compare
 * @param princ2 second principal to compare
 *
 * @return non zero if equal, 0 if not
 *
 * @ingroup krb5_principal
 * @see krb5_principal_compare()
 * @see krb5_realm_compare()
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_principal_compare_any_realm (
	krb5_context,
	krb5_const_principal,
	krb5_const_principal);

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_principal_get_comp_string (
	krb5_context,
	krb5_const_principal,
	unsigned int);

/**
 * Get number of component is principal.
 *
 * @param context Kerberos 5 context
 * @param principal principal to query
 *
 * @return number of components in string
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION unsigned int KRB5_LIB_CALL
krb5_principal_get_num_comp (
	krb5_context,
	krb5_const_principal);

/**
 * Get the realm of the principal
 *
 * @param context A Kerberos context.
 * @param principal principal to get the realm for
 *
 * @return realm of the principal, don't free or use after krb5_principal is freed
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_principal_get_realm (
	krb5_context,
	krb5_const_principal);

/**
 * Get the type of the principal
 *
 * @param context A Kerberos context.
 * @param principal principal to get the type for
 *
 * @return the type of principal
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_principal_get_type (
	krb5_context,
	krb5_const_principal);

/**
 * Returns true iff name is an WELLKNOWN:ORG.H5L.HOSTBASED-SERVICE
 *
 * @ingroup krb5_principal
 */

krb5_boolean KRB5_LIB_FUNCTION
krb5_principal_is_gss_hostbased_service (
	krb5_context,
	krb5_const_principal);

/**
 * Check if the cname part of the principal is a krbtgt principal
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_principal_is_krbtgt (
	krb5_context,
	krb5_const_principal);

/**
 * Returns true if name is Kerberos an LKDC realm
 *
 * @ingroup krb5_principal
 */

krb5_boolean KRB5_LIB_FUNCTION
krb5_principal_is_lkdc (
	krb5_context,
	krb5_const_principal);

/**
 * Returns true if name is Kerberos NULL name
 *
 * @ingroup krb5_principal
 */

krb5_boolean KRB5_LIB_FUNCTION
krb5_principal_is_null (
	krb5_context,
	krb5_const_principal);

/**
 * Returns true if name is Kerberos an LKDC realm
 *
 * @ingroup krb5_principal
 */

krb5_boolean KRB5_LIB_FUNCTION
krb5_principal_is_pku2u (
	krb5_context,
	krb5_const_principal);

/**
 * Check if the cname part of the principal is a initial or renewed krbtgt principal
 *
 * @ingroup krb5_principal
 */

krb5_boolean KRB5_LIB_FUNCTION
krb5_principal_is_root_krbtgt (
	krb5_context,
	krb5_const_principal);

/**
 * return TRUE iff princ matches pattern
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_principal_match (
	krb5_context,
	krb5_const_principal,
	krb5_const_principal);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_principal_set_comp_string (
	krb5_context,
	krb5_principal,
	unsigned int,
	const char*);

/**
 * Set a new realm for a principal, and as a side-effect free the
 * previous realm.
 *
 * @param context A Kerberos context.
 * @param principal principal set the realm for
 * @param realm the new realm to set
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_principal_set_realm (
	krb5_context,
	krb5_principal,
	krb5_const_realm);

/**
 * Set the type of the principal
 *
 * @param context A Kerberos context.
 * @param principal principal to set the type for
 * @param type the new type
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_principal_set_type (
	krb5_context,
	krb5_principal,
	int);

/**
 * krb5_print_address prints the address in addr to the string string
 * that have the length len. If ret_len is not NULL, it will be filled
 * with the length of the string if size were unlimited (not including
 * the final NUL) .
 *
 * @param addr address to be printed
 * @param str pointer string to print the address into
 * @param len length that will fit into area pointed to by "str".
 * @param ret_len return length the str.
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_address
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_print_address (
	const krb5_address*,
	char*,
	size_t,
	size_t*);

krb5_error_code
krb5_process_last_request (
	krb5_context,
	krb5_get_init_creds_opt*,
	krb5_init_creds_context);

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_program_setup (
	krb5_context*,
	int,
	char**,
	struct getargs*,
	int,
	void (KRB5_LIB_CALL*usage)(int, struct getargs*, int));

KRB5_LIB_FUNCTION int KRB5_CALLCONV
krb5_prompter_posix (
	krb5_context,
	void*,
	const char*,
	const char*,
	int,
	krb5_prompt prompts[]);

/**
 * Converts the random bytestring to a protocol key according to
 * Kerberos crypto frame work. It may be assumed that all the bits of
 * the input string are equally random, even though the entropy
 * present in the random source may be limited.
 *
 * @param context Kerberos 5 context
 * @param type the enctype resulting key will be of
 * @param data input random data to convert to a key
 * @param size size of input random data, at least krb5_enctype_keysize() long
 * @param key key, output key, free with krb5_free_keyblock_contents()
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_crypto
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_random_to_key (
	krb5_context,
	krb5_enctype,
	const void*,
	size_t,
	krb5_keyblock*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rc_close (
	krb5_context,
	krb5_rcache);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rc_default (
	krb5_context,
	krb5_rcache*);

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_rc_default_name (krb5_context);

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_rc_default_type (krb5_context);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rc_destroy (
	krb5_context,
	krb5_rcache);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rc_expunge (
	krb5_context,
	krb5_rcache);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rc_get_lifespan (
	krb5_context,
	krb5_rcache,
	krb5_deltat*);

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_rc_get_name (
	krb5_context,
	krb5_rcache);

KRB5_LIB_FUNCTION const char* KRB5_LIB_CALL
krb5_rc_get_type (
	krb5_context,
	krb5_rcache);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rc_initialize (
	krb5_context,
	krb5_rcache,
	krb5_deltat);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rc_recover (
	krb5_context,
	krb5_rcache);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rc_resolve (
	krb5_context,
	krb5_rcache,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rc_resolve_full (
	krb5_context,
	krb5_rcache*,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rc_resolve_type (
	krb5_context,
	krb5_rcache*,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rc_store (
	krb5_context,
	krb5_rcache,
	krb5_donot_replay*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rd_cred (
	krb5_context,
	krb5_auth_context,
	krb5_data*,
	krb5_creds***,
	krb5_replay_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rd_cred2 (
	krb5_context,
	krb5_auth_context,
	krb5_ccache,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rd_error (
	krb5_context,
	const krb5_data*,
	KRB_ERROR*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rd_priv (
	krb5_context,
	krb5_auth_context,
	const krb5_data*,
	krb5_data*,
	krb5_replay_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rd_rep (
	krb5_context,
	krb5_auth_context,
	const krb5_data*,
	krb5_ap_rep_enc_part**);

/**
 * Process an AP_REQ message.
 *
 * @param context        Kerberos 5 context.
 * @param auth_context   authentication context of the peer.
 * @param inbuf          the AP_REQ message, obtained for example with krb5_read_message().
 * @param server         server principal.
 * @param keytab         server keytab.
 * @param ap_req_options set to the AP_REQ options. See the AP_OPTS_* defines.
 * @param ticket         on success, set to the authenticated client credentials.
 *                       Must be deallocated with krb5_free_ticket(). If not
 *                       interested, pass a NULL value.
 *
 * @return 0 to indicate success. Otherwise a Kerberos error code is
 *         returned, see krb5_get_error_message().
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rd_req (
	krb5_context,
	krb5_auth_context*,
	const krb5_data*,
	krb5_const_principal,
	krb5_keytab,
	krb5_flags*,
	krb5_ticket**);

/**
 * The core server function that verify application authentication
 * requests from clients.
 *
 * @param context Keberos 5 context.
 * @param auth_context the authentication context, can be NULL, then
 *        default values for the authentication context will used.
 * @param inbuf the (AP-REQ) authentication buffer
 *
 * @param server the server to authenticate to. If NULL the function
 *        will try to find any available credential in the keytab
 *        that will verify the reply. The function will prefer the
 *        server specified in the AP-REQ, but if
 *        there is no mach, it will try all keytab entries for a
 *        match. This has serious performance issues for large keytabs.
 *
 * @param inctx control the behavior of the function, if NULL, the
 *        default behavior is used.
 * @param outctx the return outctx, free with krb5_rd_req_out_ctx_free().
 * @return Kerberos 5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_auth
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rd_req_ctx (
	krb5_context,
	krb5_auth_context*,
	const krb5_data*,
	krb5_const_principal,
	krb5_rd_req_in_ctx,
	krb5_rd_req_out_ctx*);

/**
 * Allocate a krb5_rd_req_in_ctx as an input parameter to
 * krb5_rd_req_ctx(). The caller should free the context with
 * krb5_rd_req_in_ctx_free() when done with the context.
 *
 * @param context Keberos 5 context.
 * @param ctx in ctx to krb5_rd_req_ctx().
 *
 * @return Kerberos 5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_auth
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rd_req_in_ctx_alloc (
	krb5_context,
	krb5_rd_req_in_ctx*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_rd_req_in_ctx_free (
	krb5_context,
	krb5_rd_req_in_ctx);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rd_req_in_set_keyblock (
	krb5_context,
	krb5_rd_req_in_ctx,
	krb5_keyblock*);

/**
 * Set the keytab that krb5_rd_req_ctx() will use.
 *
 * @param context Keberos 5 context.
 * @param in in ctx to krb5_rd_req_ctx().
 * @param keytab keytab that krb5_rd_req_ctx() will use, only copy the
 *        pointer, so the caller must free they keytab after
 *        krb5_rd_req_in_ctx_free() is called.
 *
 * @return Kerberos 5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_auth
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rd_req_in_set_keytab (
	krb5_context,
	krb5_rd_req_in_ctx,
	krb5_keytab);

/**
 * Set if krb5_rq_red() is going to check the Windows PAC or not
 *
 * @param context Keberos 5 context.
 * @param in krb5_rd_req_in_ctx to check the option on.
 * @param flag flag to select if to check the pac (TRUE) or not (FALSE).
 *
 * @return Kerberos 5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_auth
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rd_req_in_set_pac_check (
	krb5_context,
	krb5_rd_req_in_ctx,
	krb5_boolean);

/**
 * Free the krb5_rd_req_out_ctx.
 *
 * @param context Keberos 5 context.
 * @param ctx krb5_rd_req_out_ctx context to free.
 *
 * @ingroup krb5_auth
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_rd_req_out_ctx_free (
	krb5_context,
	krb5_rd_req_out_ctx);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rd_req_out_get_ap_req_options (
	krb5_context,
	krb5_rd_req_out_ctx,
	krb5_flags*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rd_req_out_get_keyblock (
	krb5_context,
	krb5_rd_req_out_ctx,
	krb5_keyblock**);

/**
 * Get the principal that was used in the request from the
 * client. Might not match whats in the ticket if krb5_rd_req_ctx()
 * searched in the keytab for a matching key.
 *
 * @param context a Kerberos 5 context.
 * @param out a krb5_rd_req_out_ctx from krb5_rd_req_ctx().
 * @param principal return principal, free with krb5_free_principal().
 *
 * @ingroup krb5_auth
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rd_req_out_get_server (
	krb5_context,
	krb5_rd_req_out_ctx,
	krb5_principal*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rd_req_out_get_ticket (
	krb5_context,
	krb5_rd_req_out_ctx,
	krb5_ticket**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rd_req_with_keyblock (
	krb5_context,
	krb5_auth_context*,
	const krb5_data*,
	krb5_const_principal,
	krb5_keyblock*,
	krb5_flags*,
	krb5_ticket**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_rd_safe (
	krb5_context,
	krb5_auth_context,
	const krb5_data*,
	krb5_data*,
	krb5_replay_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_read_message (
	krb5_context,
	krb5_pointer,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_read_priv_message (
	krb5_context,
	krb5_auth_context,
	krb5_pointer,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_read_safe_message (
	krb5_context,
	krb5_auth_context,
	krb5_pointer,
	krb5_data*);

/**
 * return TRUE iff realm(princ1) == realm(princ2)
 *
 * @param context Kerberos 5 context
 * @param princ1 first principal to compare
 * @param princ2 second principal to compare
 *
 * @ingroup krb5_principal
 * @see krb5_principal_compare_any_realm()
 * @see krb5_principal_compare()
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_realm_compare (
	krb5_context,
	krb5_const_principal,
	krb5_const_principal);

/**
 * Returns true if name is Kerberos an LKDC realm
 *
 * @ingroup krb5_principal
 */

krb5_boolean KRB5_LIB_FUNCTION
krb5_realm_is_lkdc (const char*);

/**
 * Perform the server side of the sendauth protocol.
 *
 * @param context       Kerberos 5 context.
 * @param auth_context  authentication context of the peer.
 * @param p_fd          socket associated to the connection.
 * @param appl_version  server-specific string.
 * @param server        server principal.
 * @param flags         if KRB5_RECVAUTH_IGNORE_VERSION is set, skip the sendauth version
 *                      part of the protocol.
 * @param keytab        server keytab.
 * @param ticket        on success, set to the authenticated client credentials.
 *                      Must be deallocated with krb5_free_ticket(). If not
 *                      interested, pass a NULL value.
 *
 * @return 0 to indicate success. Otherwise a Kerberos error code is
 *         returned, see krb5_get_error_message().
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_recvauth (
	krb5_context,
	krb5_auth_context*,
	krb5_pointer,
	const char*,
	krb5_principal,
	int32_t,
	krb5_keytab,
	krb5_ticket**);

/**
 * Perform the server side of the sendauth protocol like krb5_recvauth(), but support
 * a user-specified callback, \a match_appl_version, to perform the match of the application
 * version \a match_data.
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_recvauth_match_version (
	krb5_context,
	krb5_auth_context*,
	krb5_pointer,
	krb5_boolean (*)(const void*, const char*),
	const void*,
	krb5_principal,
	int32_t,
	krb5_keytab,
	krb5_ticket**);

/**
 * Read a address block from the storage.
 *
 * @param sp the storage buffer to write to
 * @param adr the address block read from storage
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_address (
	krb5_storage*,
	krb5_address*);

/**
 * Read a addresses block from the storage.
 *
 * @param sp the storage buffer to write to
 * @param adr the addresses block read from storage
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_addrs (
	krb5_storage*,
	krb5_addresses*);

/**
 * Read a auth data from the storage.
 *
 * @param sp the storage buffer to write to
 * @param auth the auth data block read from storage
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_authdata (
	krb5_storage*,
	krb5_authdata*);

/**
 * Read a credentials block from the storage.
 *
 * @param sp the storage buffer to write to
 * @param creds the credentials block read from storage
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_creds (
	krb5_storage*,
	krb5_creds*);

/**
 * Read a tagged credentials block from the storage.
 *
 * @param sp the storage buffer to write to
 * @param creds the credentials block read from storage
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_creds_tag (
	krb5_storage*,
	krb5_creds*);

/**
 * Parse a data from the storage.
 *
 * @param sp the storage buffer to read from
 * @param data the parsed data
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_data (
	krb5_storage*,
	krb5_data*);

/**
 * Read a int16 from storage, byte order is controlled by the settings
 * on the storage, see krb5_storage_set_byteorder().
 *
 * @param sp the storage to write too
 * @param value the value read from the buffer
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_int16 (
	krb5_storage*,
	int16_t*);

/**
 * Read a int32 from storage, byte order is controlled by the settings
 * on the storage, see krb5_storage_set_byteorder().
 *
 * @param sp the storage to write too
 * @param value the value read from the buffer
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_int32 (
	krb5_storage*,
	int32_t*);

/**
 * Read a int64 from storage, byte order is controlled by the settings
 * on the storage, see krb5_storage_set_byteorder().
 *
 * @param sp the storage to write too
 * @param value the value read from the buffer
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_int64 (
	krb5_storage*,
	int64_t*);

/**
 * Read a int8 from storage
 *
 * @param sp the storage to write too
 * @param value the value read from the buffer
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_int8 (
	krb5_storage*,
	int8_t*);

/**
 * Read a keyblock from the storage.
 *
 * @param sp the storage buffer to write to
 * @param p the keyblock read from storage, free using krb5_free_keyblock()
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_keyblock (
	krb5_storage*,
	krb5_keyblock*);

/**
 * Parse principal from the storage.
 *
 * @param sp the storage buffer to read from
 * @param princ the parsed principal
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_principal (
	krb5_storage*,
	krb5_principal*);

/**
 * Parse a string from the storage.
 *
 * @param sp the storage buffer to read from
 * @param string the parsed string
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_string (
	krb5_storage*,
	char**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_stringnl (
	krb5_storage*,
	char**);

/**
 * Parse zero terminated string from the storage.
 *
 * @param sp the storage buffer to read from
 * @param string the parsed string
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_stringz (
	krb5_storage*,
	char**);

/**
 * Read a times block from the storage.
 *
 * @param sp the storage buffer to write to
 * @param times the times block read from storage
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_times (
	krb5_storage*,
	krb5_times*);

/**
 * Read a int16 from storage, byte order is controlled by the settings
 * on the storage, see krb5_storage_set_byteorder().
 *
 * @param sp the storage to write too
 * @param value the value read from the buffer
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_uint16 (
	krb5_storage*,
	uint16_t*);

/**
 * Read a uint32 from storage, byte order is controlled by the settings
 * on the storage, see krb5_storage_set_byteorder().
 *
 * @param sp the storage to write too
 * @param value the value read from the buffer
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_uint32 (
	krb5_storage*,
	uint32_t*);

/**
 * Read a uint64 from storage, byte order is controlled by the settings
 * on the storage, see krb5_storage_set_byteorder().
 *
 * @param sp the storage to write too
 * @param value the value read from the buffer
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_uint64 (
	krb5_storage*,
	uint64_t*);

/**
 * Read a uint8 from storage
 *
 * @param sp the storage to write too
 * @param value the value read from the buffer
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ret_uint8 (
	krb5_storage*,
	uint8_t*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_salttype_to_string (
	krb5_context,
	krb5_enctype,
	krb5_salttype,
	char**);

/**
 * Perform the client side of the sendauth protocol.
 *
 * @param context        Kerberos 5 context.
 * @param auth_context   Authentication context of the peer.
 * @param p_fd           Socket associated to the connection.
 * @param appl_version   Server-specific string.
 * @param client         Client principal. If NULL, use the credentials in \a ccache.
 * @param server         Server principal.
 * @param ap_req_options Options for the AP_REQ message. See the AP_OPTS_* defines in krb5.h.
 * @param in_data        FIXME
 * @param in_creds       FIXME
 * @param ccache         Credentials cache. If NULL, use the default credentials cache.
 * @param ret_error      If not NULL, will be set to the error reported by server, if any.
 *                       Must be deallocated with krb5_free_error_contents().
 * @param rep_result     If not NULL, will be set to the EncApRepPart of the AP_REP message.
 *                       Must be deallocated with krb5_free_ap_rep_enc_part().
 * @param out_creds      FIXME If not NULL, will be set to FIXME. Must be deallocated with
 *                       krb5_free_creds().
 *
 * @return 0 to indicate success. Otherwise a Kerberos error code is
 *         returned, see krb5_get_error_message().
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_sendauth (
	krb5_context,
	krb5_auth_context*,
	krb5_pointer,
	const char*,
	krb5_principal,
	krb5_principal,
	krb5_flags,
	krb5_data*,
	krb5_creds*,
	krb5_ccache,
	krb5_error**,
	krb5_ap_rep_enc_part**,
	krb5_creds**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_sendto (
	krb5_context,
	const krb5_data*,
	krb5_krbhst_handle,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_sendto_context (
	krb5_context,
	krb5_sendto_ctx,
	const krb5_data*,
	krb5_const_realm,
	krb5_data*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_sendto_ctx_add_flags (
	krb5_sendto_ctx,
	int);

/**
 * @section send_to_kdc Locating and sending packets to the KDC
 *
 * The send to kdc code is responsible to request the list of KDC from
 * the locate-kdc subsystem and then send requests to each of them.
 *
 * - Each second a new hostname is tried.
 * - If the hostname have several addresses, the first will be tried
 *   directly then in turn the other will be tried every 3 seconds
 *   (host_timeout).
 * - UDP requests are tried 3 times, and it tried with a individual timeout of kdc_timeout / 3.
 * - TCP and HTTP requests are tried 1 time.
 *
 *  Total wait time shorter then (number of addresses * 3) + kdc_timeout seconds.
 *
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_sendto_ctx_alloc (
	krb5_context,
	krb5_sendto_ctx*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_sendto_ctx_free (
	krb5_context,
	krb5_sendto_ctx);

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_sendto_ctx_get_flags (krb5_sendto_ctx);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_sendto_ctx_set_func (
	krb5_sendto_ctx,
	krb5_sendto_ctx_func,
	void*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_sendto_ctx_set_type (
	krb5_sendto_ctx,
	int);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_sendto_kdc (
	krb5_context,
	const krb5_data*,
	const krb5_realm*,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_sendto_kdc_flags (
	krb5_context,
	const krb5_data*,
	const krb5_realm*,
	krb5_data*,
	int);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_sendto_set_hostname (
	krb5_context,
	krb5_sendto_ctx,
	const char*);

/**
 * Reinit the context from a new set of filenames.
 *
 * @param context context to add configuration too.
 * @param filenames array of filenames, end of list is indicated with a NULL filename.
 *
 * @return Returns 0 to indicate success.  Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_set_config_files (
	krb5_context,
	char**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_set_debug_dest (
	krb5_context,
	const char*,
	const char*);

/**
 * Set the default encryption types that will be use in communcation
 * with the KDC, clients and servers.
 *
 * @param context Kerberos 5 context.
 * @param etypes Encryption types, array terminated with ETYPE_NULL (0).
 * A value of NULL resets the encryption types to the defaults set in the
 * configuration file.
 *
 * @return Returns 0 to indicate success. Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_set_default_in_tkt_etypes (
	krb5_context,
	const krb5_enctype*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_set_default_realm (
	krb5_context,
	const char*);

/**
 * Set if the library should use DNS to canonicalize hostnames.
 *
 * @param context Kerberos 5 context.
 * @param flag if its dns canonicalizion is used or not.
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_set_dns_canonicalize_hostname (
	krb5_context,
	krb5_boolean);

/**
 * Set the context full error string for a specific error code.
 * The error that is stored should be internationalized.
 *
 * The if context is NULL, no error string is stored.
 *
 * @param context Kerberos 5 context
 * @param ret The error code
 * @param fmt Error string for the error code
 * @param ... printf(3) style parameters.
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_set_error_message (
	krb5_context,
	krb5_error_code,
	const char*,
	...)
     __attribute__ ((__format__ (__printf__, 3, 4)));

/**
 * Set the error message returned by krb5_get_error_string().
 *
 * Deprecated: use krb5_get_error_message()
 *
 * @param context Kerberos context
 * @param fmt error message to free
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_set_error_string (
	krb5_context,
	const char*,
	...)
     __attribute__ ((__format__ (__printf__, 2, 3))) KRB5_DEPRECATED_FUNCTION("Use X instead");

/**
 * Set extra address to the address list that the library will add to
 * the client's address list when communicating with the KDC.
 *
 * @param context Kerberos 5 context.
 * @param addresses addreses to set
 *
 * @return Returns 0 to indicate success. Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_set_extra_addresses (
	krb5_context,
	const krb5_addresses*);

/**
 * Set version of fcache that the library should use.
 *
 * @param context Kerberos 5 context.
 * @param version version number.
 *
 * @return Returns 0 to indicate success. Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_set_fcache_version (
	krb5_context,
	int);

/**
 * Enable and disable home directory access on either the global state
 * or the krb5_context state. By calling krb5_set_home_dir_access()
 * with context set to NULL, the global state is configured otherwise
 * the state for the krb5_context is modified.
 *
 * For home directory access to be allowed, both the global state and
 * the krb5_context state have to be allowed.
 *
 * @param context a Kerberos 5 context or NULL
 * @param allow allow if TRUE home directory
 * @return the old value
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_set_home_dir_access (
	krb5_context,
	krb5_boolean);

/**
 * Set extra addresses to ignore when fetching addresses from the
 * underlaying operating system.
 *
 * @param context Kerberos 5 context.
 * @param addresses addreses to ignore
 *
 * @return Returns 0 to indicate success. Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_set_ignore_addresses (
	krb5_context,
	const krb5_addresses*);

/**
 * Set current offset in time to the KDC.
 *
 * @param context Kerberos 5 context.
 * @param sec seconds part of offset.
 * @param usec micro seconds part of offset.
 *
 * @return returns zero
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_set_kdc_sec_offset (
	krb5_context,
	int32_t,
	int32_t);

/**
 * Set max time skew allowed.
 *
 * @param context Kerberos 5 context.
 * @param t timeskew in seconds.
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_set_max_time_skew (
	krb5_context,
	time_t);

/**
 * Change password using creds.
 *
 * @param context a Keberos context
 * @param creds The initial kadmin/passwd for the principal or an admin principal
 * @param newpw The new password to set
 * @param targprinc if unset, the client principal from creds is used
 * @param result_code Result code, KRB5_KPASSWD_SUCCESS is when password is changed.
 * @param result_code_string binary message from the server, contains
 * at least the result_code.
 * @param result_string A message from the kpasswd service or the
 * library in human printable form. The string is NUL terminated.
 *
 * @return On sucess and *result_code is KRB5_KPASSWD_SUCCESS, the password is changed.

 * @ingroup @krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_set_password (
	krb5_context,
	krb5_creds*,
	const char*,
	krb5_principal,
	int*,
	krb5_data*,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_set_password_using_ccache (
	krb5_context,
	krb5_ccache,
	const char*,
	krb5_principal,
	int*,
	krb5_data*,
	krb5_data*);

/**
 * Set the absolute time that the caller knows the kdc has so the
 * kerberos library can calculate the relative diffrence beteen the
 * KDC time and local system time.
 *
 * @param context Keberos 5 context.
 * @param sec The applications new of "now" in seconds
 * @param usec The applications new of "now" in micro seconds

 * @return Kerberos 5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_set_real_time (
	krb5_context,
	krb5_timestamp,
	int32_t);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_set_send_to_kdc_func (
	krb5_context,
	krb5_send_to_kdc_func,
	void*);

/**
 * Make the kerberos library default to the admin KDC.
 *
 * @param context Kerberos 5 context.
 * @param flag boolean flag to select if the use the admin KDC or not.
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_set_use_admin_kdc (
	krb5_context,
	krb5_boolean);

/**
 * Set the default logging facility.
 *
 * @param context A Kerberos 5 context
 * @param fac Facility to use for logging.
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_set_warn_dest (
	krb5_context,
	krb5_log_facility*);

/**
 * Create a principal for the given service running on the given
 * hostname. If KRB5_NT_SRV_HST is used, the hostname is canonicalized
 * according the configured name canonicalization rules, with
 * canonicalization delayed in some cases.  One rule involves DNS, which
 * is insecure unless DNSSEC is used, but we don't use DNSSEC-capable
 * resolver APIs here, so that if DNSSEC is used we wouldn't know it.
 *
 * Canonicalization is immediate (not delayed) only when there is only
 * one canonicalization rule and that rule indicates that we should do a
 * host lookup by name (i.e., DNS).
 *
 * @param context A Kerberos context.
 * @param hostname hostname to use
 * @param sname Service name to use
 * @param type name type of principal, use KRB5_NT_SRV_HST or KRB5_NT_UNKNOWN.
 * @param ret_princ return principal, free with krb5_free_principal().
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_sname_to_principal (
	krb5_context,
	const char*,
	const char*,
	int32_t,
	krb5_principal*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_sock_to_principal (
	krb5_context,
	int,
	const char*,
	int32_t,
	krb5_principal*);

/**
 * krb5_sockaddr2address stores a address a "struct sockaddr" sa in
 * the krb5_address addr.
 *
 * @param context a Keberos context
 * @param sa a struct sockaddr to extract the address from
 * @param addr an Kerberos 5 address to store the address in.
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_address
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_sockaddr2address (
	krb5_context,
	const struct sockaddr*,
	krb5_address*);

/**
 * krb5_sockaddr2port extracts a port (if possible) from a "struct
 * sockaddr.
 *
 * @param context a Keberos context
 * @param sa a struct sockaddr to extract the port from
 * @param port a pointer to an int16_t store the port in.
 *
 * @return Return an error code or 0. Will return
 * KRB5_PROG_ATYPE_NOSUPP in case address type is not supported.
 *
 * @ingroup krb5_address
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_sockaddr2port (
	krb5_context,
	const struct sockaddr*,
	int16_t*);

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_sockaddr_is_loopback (const struct sockaddr*);

/**
 * krb5_sockaddr_uninteresting returns TRUE for all .Fa sa that the
 * kerberos library thinks are uninteresting.  One example are link
 * local addresses.
 *
 * @param sa pointer to struct sockaddr that might be interesting.
 *
 * @return Return a non zero for uninteresting addresses.
 *
 * @ingroup krb5_address
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_sockaddr_uninteresting (const struct sockaddr*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_std_usage (
	int,
	struct getargs*,
	int);

/**
 * Clear the flags on a storage buffer
 *
 * @param sp the storage buffer to clear the flags on
 * @param flags the flags to clear
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_storage_clear_flags (
	krb5_storage*,
	krb5_flags);

/**
 * Create a elastic (allocating) memory storage backend. Memory is
 * allocated on demand. Free returned krb5_storage with
 * krb5_storage_free().
 *
 * @return A krb5_storage on success, or NULL on out of memory error.
 *
 * @ingroup krb5_storage
 *
 * @sa krb5_storage_from_mem()
 * @sa krb5_storage_from_readonly_mem()
 * @sa krb5_storage_from_fd()
 * @sa krb5_storage_from_data()
 * @sa krb5_storage_from_socket()
 */

KRB5_LIB_FUNCTION krb5_storage* KRB5_LIB_CALL
krb5_storage_emem (void);

/**
 * Free a krb5 storage.
 *
 * @param sp the storage to free.
 *
 * @return An Kerberos 5 error code.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_storage_free (krb5_storage*);

/**
 * Create a fixed size memory storage block
 *
 * @return A krb5_storage on success, or NULL on out of memory error.
 *
 * @ingroup krb5_storage
 *
 * @sa krb5_storage_mem()
 * @sa krb5_storage_from_mem()
 * @sa krb5_storage_from_readonly_mem()
 * @sa krb5_storage_from_fd()
 */

KRB5_LIB_FUNCTION krb5_storage* KRB5_LIB_CALL
krb5_storage_from_data (krb5_data*);

/**
 *
 *
 * @return A krb5_storage on success, or NULL on out of memory error.
 *
 * @ingroup krb5_storage
 *
 * @sa krb5_storage_emem()
 * @sa krb5_storage_from_mem()
 * @sa krb5_storage_from_readonly_mem()
 * @sa krb5_storage_from_data()
 * @sa krb5_storage_from_socket()
 */

KRB5_LIB_FUNCTION krb5_storage* KRB5_LIB_CALL
krb5_storage_from_fd (int);

/**
 * Create a fixed size memory storage block
 *
 * @return A krb5_storage on success, or NULL on out of memory error.
 *
 * @ingroup krb5_storage
 *
 * @sa krb5_storage_mem()
 * @sa krb5_storage_from_readonly_mem()
 * @sa krb5_storage_from_data()
 * @sa krb5_storage_from_fd()
 * @sa krb5_storage_from_socket()
 */

KRB5_LIB_FUNCTION krb5_storage* KRB5_LIB_CALL
krb5_storage_from_mem (
	void*,
	size_t);

/**
 * Create a fixed size memory storage block that is read only
 *
 * @return A krb5_storage on success, or NULL on out of memory error.
 *
 * @ingroup krb5_storage
 *
 * @sa krb5_storage_mem()
 * @sa krb5_storage_from_mem()
 * @sa krb5_storage_from_data()
 * @sa krb5_storage_from_fd()
 */

KRB5_LIB_FUNCTION krb5_storage* KRB5_LIB_CALL
krb5_storage_from_readonly_mem (
	const void*,
	size_t);

/**
 *
 *
 * @return A krb5_storage on success, or NULL on out of memory error.
 *
 * @ingroup krb5_storage
 *
 * @sa krb5_storage_emem()
 * @sa krb5_storage_from_mem()
 * @sa krb5_storage_from_readonly_mem()
 * @sa krb5_storage_from_data()
 * @sa krb5_storage_from_fd()
 */

KRB5_LIB_FUNCTION krb5_storage* KRB5_LIB_CALL
krb5_storage_from_socket (krb5_socket_t);

/**
 * Sync the storage buffer to its backing store.  If there is no
 * backing store this function will return success.
 *
 * @param sp the storage buffer to sync
 *
 * @return A Kerberos 5 error code
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_storage_fsync (krb5_storage*);

/**
 * Return the current byteorder for the buffer. See krb5_storage_set_byteorder() for the list or byte order contants.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_flags KRB5_LIB_CALL
krb5_storage_get_byteorder (krb5_storage*);

/**
 * Get the return code that will be used when end of storage is reached.
 *
 * @param sp the storage
 *
 * @return storage error code
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_storage_get_eof_code (krb5_storage*);

/**
 * Return true or false depending on if the storage flags is set or
 * not. NB testing for the flag 0 always return true.
 *
 * @param sp the storage buffer to check flags on
 * @param flags The flags to test for
 *
 * @return true if all the flags are set, false if not.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_boolean KRB5_LIB_CALL
krb5_storage_is_flags (
	krb5_storage*,
	krb5_flags);

/**
 * Read to the storage buffer.
 *
 * @param sp the storage buffer to read from
 * @param buf the buffer to store the data in
 * @param len the length to read
 *
 * @return The length of data read (can be shorter then len), or negative on error.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_ssize_t KRB5_LIB_CALL
krb5_storage_read (
	krb5_storage*,
	void*,
	size_t);

/**
 * Seek to a new offset.
 *
 * @param sp the storage buffer to seek in.
 * @param offset the offset to seek
 * @param whence relateive searching, SEEK_CUR from the current
 * position, SEEK_END from the end, SEEK_SET absolute from the start.
 *
 * @return The new current offset
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION off_t KRB5_LIB_CALL
krb5_storage_seek (
	krb5_storage*,
	off_t,
	int);

/**
 * Set the new byte order of the storage buffer.
 *
 * @param sp the storage buffer to set the byte order for.
 * @param byteorder the new byte order.
 *
 * The byte order are: KRB5_STORAGE_BYTEORDER_BE,
 * KRB5_STORAGE_BYTEORDER_LE and KRB5_STORAGE_BYTEORDER_HOST.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_storage_set_byteorder (
	krb5_storage*,
	krb5_flags);

/**
 * Set the return code that will be used when end of storage is reached.
 *
 * @param sp the storage
 * @param code the error code to return on end of storage
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_storage_set_eof_code (
	krb5_storage*,
	int);

/**
 * Add the flags on a storage buffer by or-ing in the flags to the buffer.
 *
 * @param sp the storage buffer to set the flags on
 * @param flags the flags to set
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_storage_set_flags (
	krb5_storage*,
	krb5_flags);

/**
 * Set the max alloc value
 *
 * @param sp the storage buffer set the max allow for
 * @param size maximum size to allocate, use 0 to remove limit
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_storage_set_max_alloc (
	krb5_storage*,
	size_t);

/**
 * Open a krb5_storage using stdio for buffering.
 *
 * @return A krb5_storage on success, or NULL on out of memory error.
 *
 * @ingroup krb5_storage
 *
 * @sa krb5_storage_emem()
 * @sa krb5_storage_from_fd()
 * @sa krb5_storage_from_mem()
 * @sa krb5_storage_from_readonly_mem()
 * @sa krb5_storage_from_data()
 * @sa krb5_storage_from_socket()
 */

KRB5_LIB_FUNCTION krb5_storage* KRB5_LIB_CALL
krb5_storage_stdio_from_fd (
	int,
	const char*);

/**
 * Copy the contnent of storage
 *
 * @param sp the storage to copy to a data
 * @param data the copied data, free with krb5_data_free()
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_storage_to_data (
	krb5_storage*,
	krb5_data*);

/**
 * Truncate the storage buffer in sp to offset.
 *
 * @param sp the storage buffer to truncate.
 * @param offset the offset to truncate too.
 *
 * @return An Kerberos 5 error code.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_storage_truncate (
	krb5_storage*,
	off_t);

/**
 * Write to the storage buffer.
 *
 * @param sp the storage buffer to write to
 * @param buf the buffer to write to the storage buffer
 * @param len the length to write
 *
 * @return The length of data written (can be shorter then len), or negative on error.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_ssize_t KRB5_LIB_CALL
krb5_storage_write (
	krb5_storage*,
	const void*,
	size_t);

/**
 * Write a address block to storage.
 *
 * @param sp the storage buffer to write to
 * @param p the address block to write.
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_address (
	krb5_storage*,
	krb5_address);

/**
 * Write a addresses block to storage.
 *
 * @param sp the storage buffer to write to
 * @param p the addresses block to write.
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_addrs (
	krb5_storage*,
	krb5_addresses);

/**
 * Write a auth data block to storage.
 *
 * @param sp the storage buffer to write to
 * @param auth the auth data block to write.
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_authdata (
	krb5_storage*,
	krb5_authdata);

/**
 * Write a credentials block to storage.
 *
 * @param sp the storage buffer to write to
 * @param creds the creds block to write.
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_creds (
	krb5_storage*,
	krb5_creds*);

/**
 * Write a tagged credentials block to storage.
 *
 * @param sp the storage buffer to write to
 * @param creds the creds block to write.
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_creds_tag (
	krb5_storage*,
	krb5_creds*);

/**
 * Store a data to the storage. The data is stored with an int32 as
 * lenght plus the data (not padded).
 *
 * @param sp the storage buffer to write to
 * @param data the buffer to store.
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_data (
	krb5_storage*,
	krb5_data);

/**
 * Store a int16 to storage, byte order is controlled by the settings
 * on the storage, see krb5_storage_set_byteorder().
 *
 * @param sp the storage to write too
 * @param value the value to store
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_int16 (
	krb5_storage*,
	int16_t);

/**
 * Store a int32 to storage, byte order is controlled by the settings
 * on the storage, see krb5_storage_set_byteorder().
 *
 * @param sp the storage to write too
 * @param value the value to store
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_int32 (
	krb5_storage*,
	int32_t);

/**
 * Store a int64 to storage, byte order is controlled by the settings
 * on the storage, see krb5_storage_set_byteorder().
 *
 * @param sp the storage to write too
 * @param value the value to store
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_int64 (
	krb5_storage*,
	int64_t);

/**
 * Store a int8 to storage.
 *
 * @param sp the storage to write too
 * @param value the value to store
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_int8 (
	krb5_storage*,
	int8_t);

/**
 * Store a keyblock to the storage.
 *
 * @param sp the storage buffer to write to
 * @param p the keyblock to write
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_keyblock (
	krb5_storage*,
	krb5_keyblock);

/**
 * Write a principal block to storage.
 *
 * @param sp the storage buffer to write to
 * @param p the principal block to write.
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_principal (
	krb5_storage*,
	krb5_const_principal);

/**
 * Store a string to the buffer. The data is formated as an len:uint32
 * plus the string itself (not padded).
 *
 * @param sp the storage buffer to write to
 * @param s the string to store.
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_string (
	krb5_storage*,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_stringnl (
	krb5_storage*,
	const char*);

/**
 * Store a zero terminated string to the buffer. The data is stored
 * one character at a time until a NUL is stored.
 *
 * @param sp the storage buffer to write to
 * @param s the string to store.
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_stringz (
	krb5_storage*,
	const char*);

/**
 * Write a times block to storage.
 *
 * @param sp the storage buffer to write to
 * @param times the times block to write.
 *
 * @return 0 on success, a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_times (
	krb5_storage*,
	krb5_times);

/**
 * Store a uint16 to storage, byte order is controlled by the settings
 * on the storage, see krb5_storage_set_byteorder().
 *
 * @param sp the storage to write too
 * @param value the value to store
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_uint16 (
	krb5_storage*,
	uint16_t);

/**
 * Store a uint32 to storage, byte order is controlled by the settings
 * on the storage, see krb5_storage_set_byteorder().
 *
 * @param sp the storage to write too
 * @param value the value to store
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_uint32 (
	krb5_storage*,
	uint32_t);

/**
 * Store a uint64 to storage, byte order is controlled by the settings
 * on the storage, see krb5_storage_set_byteorder().
 *
 * @param sp the storage to write too
 * @param value the value to store
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_uint64 (
	krb5_storage*,
	uint64_t);

/**
 * Store a uint8 to storage.
 *
 * @param sp the storage to write too
 * @param value the value to store
 *
 * @return 0 for success, or a Kerberos 5 error code on failure.
 *
 * @ingroup krb5_storage
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_store_uint8 (
	krb5_storage*,
	uint8_t);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_string_to_deltat (
	const char*,
	krb5_deltat*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_string_to_enctype (
	krb5_context,
	const char*,
	krb5_enctype*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_string_to_key (
	krb5_context,
	krb5_enctype,
	const char*,
	krb5_principal,
	krb5_keyblock*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_string_to_key_data (
	krb5_context,
	krb5_enctype,
	krb5_data,
	krb5_principal,
	krb5_keyblock*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_string_to_key_data_salt (
	krb5_context,
	krb5_enctype,
	krb5_data,
	krb5_salt,
	krb5_keyblock*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_string_to_key_data_salt_opaque (
	krb5_context,
	krb5_enctype,
	krb5_data,
	krb5_salt,
	krb5_data,
	krb5_keyblock*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_string_to_key_derived (
	krb5_context,
	const void*,
	size_t,
	krb5_enctype,
	krb5_keyblock*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_string_to_key_salt (
	krb5_context,
	krb5_enctype,
	const char*,
	krb5_salt,
	krb5_keyblock*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_string_to_key_salt_opaque (
	krb5_context,
	krb5_enctype,
	const char*,
	krb5_salt,
	krb5_data,
	krb5_keyblock*);

/**
 * Deprecated: keytypes doesn't exists, they are really enctypes in
 * most cases, use krb5_string_to_enctype().
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_string_to_keytype (
	krb5_context,
	const char*,
	krb5_keytype*)
     KRB5_DEPRECATED_FUNCTION("Use X instead");

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_string_to_salttype (
	krb5_context,
	krb5_enctype,
	const char*,
	krb5_salttype*);

/**
 * Extract the authorization data type of type from the ticket. Store
 * the field in data. This function is to use for kerberos
 * applications.
 *
 * @param context a Kerberos 5 context
 * @param ticket Kerberos ticket
 * @param type type to fetch
 * @param data returned data, free with krb5_data_free()
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ticket_get_authorization_data_type (
	krb5_context,
	krb5_ticket*,
	int,
	krb5_data*);

/**
 * Return client principal in ticket
 *
 * @param context a Kerberos 5 context
 * @param ticket ticket to copy
 * @param client client principal, free with krb5_free_principal()
 *
 * @return Returns 0 to indicate success.  Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ticket_get_client (
	krb5_context,
	const krb5_ticket*,
	krb5_principal*);

/**
 * Return end time of ticket
 *
 * @param context a Kerberos 5 context
 * @param ticket ticket to copy
 *
 * @return end time of ticket
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION time_t KRB5_LIB_CALL
krb5_ticket_get_endtime (
	krb5_context,
	const krb5_ticket*);

/**
 * Get the flags from the Kerberos ticket
 *
 * @param context Kerberos context
 * @param ticket Kerberos ticket
 *
 * @return ticket flags
 *
 * @ingroup krb5_ticket
 */

KRB5_LIB_FUNCTION unsigned long KRB5_LIB_CALL
krb5_ticket_get_flags (
	krb5_context,
	const krb5_ticket*);

/**
 * Return server principal in ticket
 *
 * @param context a Kerberos 5 context
 * @param ticket ticket to copy
 * @param server server principal, free with krb5_free_principal()
 *
 * @return Returns 0 to indicate success.  Otherwise an kerberos et
 * error code is returned, see krb5_get_error_message().
 *
 * @ingroup krb5
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_ticket_get_server (
	krb5_context,
	const krb5_ticket*,
	krb5_principal*);

/**
     * If the caller passes in a negative usec, its assumed to be
     * unknown and the function will use the current time usec.
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_timeofday (
	krb5_context,
	krb5_timestamp*);

/**
 * Unparse the Kerberos name into a string
 *
 * @param context Kerberos 5 context
 * @param principal principal to query
 * @param name resulting string, free with krb5_xfree()
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_unparse_name (
	krb5_context,
	krb5_const_principal,
	char**);

/**
 * Unparse the principal name to a fixed buffer
 *
 * @param context A Kerberos context.
 * @param principal principal to unparse
 * @param name buffer to write name to
 * @param len length of buffer
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_unparse_name_fixed (
	krb5_context,
	krb5_const_principal,
	char*,
	size_t);

/**
 * Unparse the principal name with unparse flags to a fixed buffer.
 *
 * @param context A Kerberos context.
 * @param principal principal to unparse
 * @param flags unparse flags
 * @param name buffer to write name to
 * @param len length of buffer
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_unparse_name_fixed_flags (
	krb5_context,
	krb5_const_principal,
	int,
	char*,
	size_t);

/**
 * Unparse the principal name to a fixed buffer. The realm is skipped
 * if its a default realm.
 *
 * @param context A Kerberos context.
 * @param principal principal to unparse
 * @param name buffer to write name to
 * @param len length of buffer
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_unparse_name_fixed_short (
	krb5_context,
	krb5_const_principal,
	char*,
	size_t);

/**
 * Unparse the Kerberos name into a string
 *
 * @param context Kerberos 5 context
 * @param principal principal to query
 * @param flags flag to determine the behavior
 * @param name resulting string, free with krb5_xfree()
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_unparse_name_flags (
	krb5_context,
	krb5_const_principal,
	int,
	char**);

/**
 * Unparse the principal name to a allocated buffer. The realm is
 * skipped if its a default realm.
 *
 * @param context A Kerberos context.
 * @param principal principal to unparse
 * @param name returned buffer, free with krb5_xfree()
 *
 * @return An krb5 error code, see krb5_get_error_message().
 *
 * @ingroup krb5_principal
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_unparse_name_short (
	krb5_context,
	krb5_const_principal,
	char**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_us_timeofday (
	krb5_context,
	krb5_timestamp*,
	int32_t*);

/**
 * Log a warning to the log, default stderr, include bthe error from
 * the last failure and then abort.
 *
 * @param context A Kerberos 5 context
 * @param code error code of the last error
 * @param fmt message to print
 * @param ap arguments
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_vabort (
	krb5_context,
	krb5_error_code,
	const char*,
	va_list)
     __attribute__ ((__noreturn__, __format__ (__printf__, 3, 0)));

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_vabortx (
	krb5_context,
	const char*,
	va_list)
     __attribute__ ((__noreturn__, __format__ (__printf__, 2, 0)));

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_verify_ap_req (
	krb5_context,
	krb5_auth_context*,
	krb5_ap_req*,
	krb5_const_principal,
	krb5_keyblock*,
	krb5_flags,
	krb5_flags*,
	krb5_ticket**);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_verify_ap_req2 (
	krb5_context,
	krb5_auth_context*,
	krb5_ap_req*,
	krb5_const_principal,
	krb5_keyblock*,
	krb5_flags,
	krb5_flags*,
	krb5_ticket**,
	krb5_key_usage);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_verify_authenticator_checksum (
	krb5_context,
	krb5_auth_context,
	void*,
	size_t);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_verify_checksum (
	krb5_context,
	krb5_crypto,
	krb5_key_usage,
	void*,
	size_t,
	Checksum*);

/**
 * Verify a Kerberos message checksum.
 *
 * @param context Kerberos context
 * @param crypto Kerberos crypto context
 * @param usage Key usage for this buffer
 * @param data array of buffers to process
 * @param num_data length of array
 * @param type return checksum type if not NULL
 *
 * @return Return an error code or 0.
 * @ingroup krb5_crypto
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_verify_checksum_iov (
	krb5_context,
	krb5_crypto,
	unsigned,
	krb5_crypto_iov*,
	unsigned int,
	krb5_cksumtype*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_verify_init_creds (
	krb5_context,
	krb5_creds*,
	krb5_principal,
	krb5_keytab,
	krb5_ccache*,
	krb5_verify_init_creds_opt*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_verify_init_creds_opt_init (krb5_verify_init_creds_opt*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_verify_init_creds_opt_set_ap_req_nofail (
	krb5_verify_init_creds_opt*,
	int);

KRB5_LIB_FUNCTION int KRB5_LIB_CALL
krb5_verify_opt_alloc (
	krb5_context,
	krb5_verify_opt**);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_verify_opt_free (krb5_verify_opt*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_verify_opt_init (krb5_verify_opt*);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_verify_opt_set_ccache (
	krb5_verify_opt*,
	krb5_ccache);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_verify_opt_set_flags (
	krb5_verify_opt*,
	unsigned int);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_verify_opt_set_keytab (
	krb5_verify_opt*,
	krb5_keytab);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_verify_opt_set_secure (
	krb5_verify_opt*,
	krb5_boolean);

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_verify_opt_set_service (
	krb5_verify_opt*,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_verify_user (
	krb5_context,
	krb5_principal,
	krb5_ccache,
	const char*,
	krb5_boolean,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_verify_user_lrealm (
	krb5_context,
	krb5_principal,
	krb5_ccache,
	const char*,
	krb5_boolean,
	const char*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_verify_user_opt (
	krb5_context,
	krb5_principal,
	const char*,
	krb5_verify_opt*);

/**
 * Log a warning to the log, default stderr, include bthe error from
 * the last failure and then exit.
 *
 * @param context A Kerberos 5 context
 * @param eval the exit code to exit with
 * @param code error code of the last error
 * @param fmt message to print
 * @param ap arguments
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_verr (
	krb5_context,
	int,
	krb5_error_code,
	const char*,
	va_list)
     __attribute__ ((__noreturn__, __format__ (__printf__, 4, 0)));

/**
 * Log a warning to the log, default stderr, and then exit.
 *
 * @param context A Kerberos 5 context
 * @param eval the exit code to exit with
 * @param fmt message to print
 * @param ap arguments
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_verrx (
	krb5_context,
	int,
	const char*,
	va_list)
     __attribute__ ((__noreturn__, __format__ (__printf__, 3, 0)));

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_vlog (
	krb5_context,
	krb5_log_facility*,
	int,
	const char*,
	va_list)
     __attribute__ ((__format__ (__printf__, 4, 0)));

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_vlog_msg (
	krb5_context,
	krb5_log_facility*,
	char**,
	int,
	const char*,
	va_list)
     __attribute__ ((__format__ (__printf__, 5, 0)));

/**
 * Prepend the contexts's full error string for a specific error code.
 *
 * The if context is NULL, no error string is stored.
 *
 * @param context Kerberos 5 context
 * @param ret The error code
 * @param fmt Error string for the error code
 * @param args printf(3) style parameters.
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_vprepend_error_message (
	krb5_context,
	krb5_error_code,
	const char*,
	va_list)
     __attribute__ ((__format__ (__printf__, 3, 0)));

/**
 * Set the context full error string for a specific error code.
 *
 * The if context is NULL, no error string is stored.
 *
 * @param context Kerberos 5 context
 * @param ret The error code
 * @param fmt Error string for the error code
 * @param args printf(3) style parameters.
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_vset_error_message (
	krb5_context,
	krb5_error_code,
	const char*,
	va_list)
     __attribute__ ((__format__ (__printf__, 3, 0)));

/**
 * Set the error message returned by krb5_get_error_string(),
 * deprecated, use krb5_set_error_message().
 *
 * Deprecated: use krb5_vset_error_message()
 *
 * @param context Kerberos context
 * @param fmt error message to free
 * @param args variable argument list vector
 *
 * @return Return an error code or 0.
 *
 * @ingroup krb5_deprecated
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_vset_error_string (
	krb5_context,
	const char*,
	va_list)
     __attribute__ ((__format__ (__printf__, 2, 0))) KRB5_DEPRECATED_FUNCTION("Use X instead");

/**
 * Log a warning to the log, default stderr, include the error from
 * the last failure.
 *
 * @param context A Kerberos 5 context.
 * @param code error code of the last error
 * @param fmt message to print
 * @param ap arguments
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_vwarn (
	krb5_context,
	krb5_error_code,
	const char*,
	va_list)
     __attribute__ ((__format__ (__printf__, 3, 0)));

/**
 * Log a warning to the log, default stderr.
 *
 * @param context A Kerberos 5 context.
 * @param fmt message to print
 * @param ap arguments
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_vwarnx (
	krb5_context,
	const char*,
	va_list)
     __attribute__ ((__format__ (__printf__, 2, 0)));

/**
 * Log a warning to the log, default stderr, include the error from
 * the last failure.
 *
 * @param context A Kerberos 5 context.
 * @param code error code of the last error
 * @param fmt message to print
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_warn (
	krb5_context,
	krb5_error_code,
	const char*,
	...)
     __attribute__ ((__format__ (__printf__, 3, 4)));

/**
 * Log a warning to the log, default stderr.
 *
 * @param context A Kerberos 5 context.
 * @param fmt message to print
 *
 * @ingroup krb5_error
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_warnx (
	krb5_context,
	const char*,
	...)
     __attribute__ ((__format__ (__printf__, 2, 3)));

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_write_message (
	krb5_context,
	krb5_pointer,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_write_priv_message (
	krb5_context,
	krb5_auth_context,
	krb5_pointer,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_write_safe_message (
	krb5_context,
	krb5_auth_context,
	krb5_pointer,
	krb5_data*);

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_xfree (void*);

#ifdef __cplusplus
}
#endif

#undef KRB5_DEPRECATED_FUNCTION

#endif /* DOXY */
#endif /* __krb5_protos_h__ */
