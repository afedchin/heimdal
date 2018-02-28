/* This is a generated file */
#ifndef __der_protos_h__
#define __der_protos_h__
#ifndef DOXY

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

int
copy_heim_any (
	const heim_any*,
	heim_any*);

int
copy_heim_any_set (
	const heim_any_set*,
	heim_any_set*);

int
decode_heim_any (
	const unsigned char*,
	size_t,
	heim_any*,
	size_t*);

int
decode_heim_any_set (
	const unsigned char*,
	size_t,
	heim_any_set*,
	size_t*);

int
der_copy_bit_string (
	const heim_bit_string*,
	heim_bit_string*);

int
der_copy_bmp_string (
	const heim_bmp_string*,
	heim_bmp_string*);

int
der_copy_general_string (
	const heim_general_string*,
	heim_general_string*);

int
der_copy_generalized_time (
	const time_t*,
	time_t*);

int
der_copy_heim_integer (
	const heim_integer*,
	heim_integer*);

int
der_copy_ia5_string (
	const heim_ia5_string*,
	heim_ia5_string*);

int
der_copy_integer (
	const int*,
	int*);

int
der_copy_integer64 (
	const int64_t*,
	int64_t*);

int
der_copy_octet_string (
	const heim_octet_string*,
	heim_octet_string*);

int
der_copy_oid (
	const heim_oid*,
	heim_oid*);

int
der_copy_printable_string (
	const heim_printable_string*,
	heim_printable_string*);

int
der_copy_universal_string (
	const heim_universal_string*,
	heim_universal_string*);

int
der_copy_unsigned (
	const unsigned*,
	unsigned*);

int
der_copy_unsigned64 (
	const uint64_t*,
	uint64_t*);

int
der_copy_utctime (
	const time_t*,
	time_t*);

int
der_copy_utf8string (
	const heim_utf8_string*,
	heim_utf8_string*);

int
der_copy_visible_string (
	const heim_visible_string*,
	heim_visible_string*);

void
der_free_bit_string (heim_bit_string*);

void
der_free_bmp_string (heim_bmp_string*);

void
der_free_general_string (heim_general_string*);

void
der_free_generalized_time (time_t*);

void
der_free_heim_integer (heim_integer*);

void
der_free_ia5_string (heim_ia5_string*);

void
der_free_integer (int*);

void
der_free_integer64 (int64_t*);

void
der_free_octet_string (heim_octet_string*);

void
der_free_oid (heim_oid*);

void
der_free_printable_string (heim_printable_string*);

void
der_free_universal_string (heim_universal_string*);

void
der_free_unsigned (unsigned*);

void
der_free_unsigned64 (uint64_t*);

void
der_free_utctime (time_t*);

void
der_free_utf8string (heim_utf8_string*);

void
der_free_visible_string (heim_visible_string*);

int
der_get_bit_string (
	const unsigned char*,
	size_t,
	heim_bit_string*,
	size_t*);

int
der_get_bmp_string (
	const unsigned char*,
	size_t,
	heim_bmp_string*,
	size_t*);

int
der_get_boolean (
	const unsigned char*,
	size_t,
	int*,
	size_t*);

const char*
der_get_class_name (unsigned);

int
der_get_class_num (const char*);

int
der_get_general_string (
	const unsigned char*,
	size_t,
	heim_general_string*,
	size_t*);

int
der_get_generalized_time (
	const unsigned char*,
	size_t,
	time_t*,
	size_t*);

int
der_get_heim_integer (
	const unsigned char*,
	size_t,
	heim_integer*,
	size_t*);

int
der_get_ia5_string (
	const unsigned char*,
	size_t,
	heim_ia5_string*,
	size_t*);

int
der_get_integer (
	const unsigned char*,
	size_t,
	int*,
	size_t*);

int
der_get_integer64 (
	const unsigned char*,
	size_t,
	int64_t*,
	size_t*);

int
der_get_length (
	const unsigned char*,
	size_t,
	size_t*,
	size_t*);

int
der_get_octet_string (
	const unsigned char*,
	size_t,
	heim_octet_string*,
	size_t*);

int
der_get_octet_string_ber (
	const unsigned char*,
	size_t,
	heim_octet_string*,
	size_t*);

int
der_get_oid (
	const unsigned char*,
	size_t,
	heim_oid*,
	size_t*);

int
der_get_printable_string (
	const unsigned char*,
	size_t,
	heim_printable_string*,
	size_t*);

int
der_get_tag (
	const unsigned char*,
	size_t,
	Der_class*,
	Der_type*,
	unsigned int*,
	size_t*);

const char*
der_get_tag_name (unsigned);

int
der_get_tag_num (const char*);

const char*
der_get_type_name (unsigned);

int
der_get_type_num (const char*);

int
der_get_universal_string (
	const unsigned char*,
	size_t,
	heim_universal_string*,
	size_t*);

int
der_get_unsigned (
	const unsigned char*,
	size_t,
	unsigned*,
	size_t*);

int
der_get_unsigned64 (
	const unsigned char*,
	size_t,
	uint64_t*,
	size_t*);

int
der_get_utctime (
	const unsigned char*,
	size_t,
	time_t*,
	size_t*);

int
der_get_utf8string (
	const unsigned char*,
	size_t,
	heim_utf8_string*,
	size_t*);

int
der_get_visible_string (
	const unsigned char*,
	size_t,
	heim_visible_string*,
	size_t*);

int
der_heim_bit_string_cmp (
	const heim_bit_string*,
	const heim_bit_string*);

int
der_heim_bmp_string_cmp (
	const heim_bmp_string*,
	const heim_bmp_string*);

int
der_heim_integer_cmp (
	const heim_integer*,
	const heim_integer*);

int
der_heim_octet_string_cmp (
	const heim_octet_string*,
	const heim_octet_string*);

int
der_heim_oid_cmp (
	const heim_oid*,
	const heim_oid*);

int
der_heim_universal_string_cmp (
	const heim_universal_string*,
	const heim_universal_string*);

int
der_ia5_string_cmp (
	const heim_ia5_string*,
	const heim_ia5_string*);

size_t
der_length_bit_string (const heim_bit_string*);

size_t
der_length_bmp_string (const heim_bmp_string*);

size_t
der_length_boolean (const int*);

size_t
der_length_enumerated (const unsigned*);

size_t
der_length_general_string (const heim_general_string*);

size_t
der_length_generalized_time (const time_t*);

size_t
der_length_heim_integer (const heim_integer*);

size_t
der_length_ia5_string (const heim_ia5_string*);

size_t
der_length_integer (const int*);

size_t
der_length_integer64 (const int64_t*);

size_t
der_length_len (size_t);

size_t
der_length_octet_string (const heim_octet_string*);

size_t
der_length_oid (const heim_oid*);

size_t
der_length_printable_string (const heim_printable_string*);

size_t
der_length_tag (unsigned int);

size_t
der_length_universal_string (const heim_universal_string*);

size_t
der_length_unsigned (const unsigned*);

size_t
der_length_unsigned64 (const uint64_t*);

size_t
der_length_utctime (const time_t*);

size_t
der_length_utf8string (const heim_utf8_string*);

size_t
der_length_visible_string (const heim_visible_string*);

int
der_match_tag (
	const unsigned char*,
	size_t,
	Der_class,
	Der_type,
	unsigned int,
	size_t*);

int
der_match_tag2 (
	const unsigned char*,
	size_t,
	Der_class,
	Der_type*,
	unsigned int,
	size_t*);

int
der_match_tag_and_length (
	const unsigned char*,
	size_t,
	Der_class,
	Der_type*,
	unsigned int,
	size_t*,
	size_t*);

int
der_parse_heim_oid (
	const char*,
	const char*,
	heim_oid*);

int
der_parse_hex_heim_integer (
	const char*,
	heim_integer*);

int
der_print_heim_oid (
	const heim_oid*,
	char,
	char**);

int
der_print_hex_heim_integer (
	const heim_integer*,
	char**);

int
der_printable_string_cmp (
	const heim_printable_string*,
	const heim_printable_string*);

int
der_put_bit_string (
	unsigned char*,
	size_t,
	const heim_bit_string*,
	size_t*);

int
der_put_bmp_string (
	unsigned char*,
	size_t,
	const heim_bmp_string*,
	size_t*);

int
der_put_boolean (
	unsigned char*,
	size_t,
	const int*,
	size_t*);

int
der_put_general_string (
	unsigned char*,
	size_t,
	const heim_general_string*,
	size_t*);

int
der_put_generalized_time (
	unsigned char*,
	size_t,
	const time_t*,
	size_t*);

int
der_put_heim_integer (
	unsigned char*,
	size_t,
	const heim_integer*,
	size_t*);

int
der_put_ia5_string (
	unsigned char*,
	size_t,
	const heim_ia5_string*,
	size_t*);

int
der_put_integer (
	unsigned char*,
	size_t,
	const int*,
	size_t*);

int
der_put_integer64 (
	unsigned char*,
	size_t,
	const int64_t*,
	size_t*);

int
der_put_length (
	unsigned char*,
	size_t,
	size_t,
	size_t*);

int
der_put_length_and_tag (
	unsigned char*,
	size_t,
	size_t,
	Der_class,
	Der_type,
	unsigned int,
	size_t*);

int
der_put_octet_string (
	unsigned char*,
	size_t,
	const heim_octet_string*,
	size_t*);

int
der_put_oid (
	unsigned char*,
	size_t,
	const heim_oid*,
	size_t*);

int
der_put_printable_string (
	unsigned char*,
	size_t,
	const heim_printable_string*,
	size_t*);

int
der_put_tag (
	unsigned char*,
	size_t,
	Der_class,
	Der_type,
	unsigned int,
	size_t*);

int
der_put_universal_string (
	unsigned char*,
	size_t,
	const heim_universal_string*,
	size_t*);

int
der_put_unsigned (
	unsigned char*,
	size_t,
	const unsigned*,
	size_t*);

int
der_put_unsigned64 (
	unsigned char*,
	size_t,
	const uint64_t*,
	size_t*);

int
der_put_utctime (
	unsigned char*,
	size_t,
	const time_t*,
	size_t*);

int
der_put_utf8string (
	unsigned char*,
	size_t,
	const heim_utf8_string*,
	size_t*);

int
der_put_visible_string (
	unsigned char*,
	size_t,
	const heim_visible_string*,
	size_t*);

int
encode_heim_any (
	unsigned char*,
	size_t,
	const heim_any*,
	size_t*);

int
encode_heim_any_set (
	unsigned char*,
	size_t,
	const heim_any_set*,
	size_t*);

void
free_heim_any (heim_any*);

void
free_heim_any_set (heim_any_set*);

int
heim_any_cmp (
	const heim_any_set*,
	const heim_any_set*);

size_t
length_heim_any (const heim_any*);

size_t
length_heim_any_set (const heim_any*);

#ifdef __cplusplus
}
#endif

#endif /* DOXY */
#endif /* __der_protos_h__ */
