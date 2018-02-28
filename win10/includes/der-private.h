/* This is a generated file */
#ifndef __der_private_h__
#define __der_private_h__

#include <stdarg.h>

struct tm*
_der_gmtime (
	time_t,
	struct tm*);

int
_heim_der_set_sort (
	const void*,
	const void*);

int
_heim_fix_dce (
	size_t,
	size_t*);

size_t
_heim_len_int (int);

size_t
_heim_len_int64 (int64_t);

size_t
_heim_len_unsigned (unsigned);

size_t
_heim_len_unsigned64 (uint64_t);

int
_heim_time2generalizedtime (
	time_t,
	heim_octet_string*,
	int);

#endif /* __der_private_h__ */
