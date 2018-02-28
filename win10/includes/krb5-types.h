#ifndef __D__Work_Custom_kodi_addons_heimdal_include____out_dest_AMD64_inc_krb5_types_h__
#define __D__Work_Custom_kodi_addons_heimdal_include____out_dest_AMD64_inc_krb5_types_h__

#include <sys/types.h>
#include <winsock2.h>
#include <ws2tcpip.h>

/* For compatibility with various type definitions */
#ifndef __BIT_TYPES_DEFINED__
#define __BIT_TYPES_DEFINED__

typedef signed char int8_t;		/*  8 bits */
typedef short int16_t;			/* 16 bits */
typedef int int32_t;			/* 32 bits */
typedef long long int64_t;		/* 64 bits */
typedef unsigned char uint8_t;		/*  8 bits */
typedef unsigned short uint16_t;	/* 16 bits */
typedef unsigned int uint32_t;		/* 32 bits */
typedef unsigned long long uint64_t;	/* 64 bits */
typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef uint64_t u_int64_t;

#endif /* __BIT_TYPES_DEFINED__ */


typedef socklen_t krb5_socklen_t;
typedef int krb5_ssize_t;

typedef SOCKET krb5_socket_t;

#if !defined(__has_extension)
#define __has_extension(x) 0
#endif

#ifndef KRB5TYPES_REQUIRE_GNUC
#define KRB5TYPES_REQUIRE_GNUC(m,n,p) \
    (((__GNUC__ * 10000) + (__GNUC_MINOR__ * 100) + __GNUC_PATCHLEVEL__) >= \
     (((m) * 10000) + ((n) * 100) + (p)))
#endif

#ifndef HEIMDAL_DEPRECATED
#if __has_extension(deprecated) || KRB5TYPES_REQUIRE_GNUC(3,1,0)
#define HEIMDAL_DEPRECATED __attribute__ ((__deprecated__))
#elif defined(_MSC_VER) && (_MSC_VER>1200)
#define HEIMDAL_DEPRECATED __declspec(deprecated)
#else
#define HEIMDAL_DEPRECATED
#endif
#endif

#ifndef HEIMDAL_PRINTF_ATTRIBUTE
#if __has_extension(format) || KRB5TYPES_REQUIRE_GNUC(3,1,0)
#define HEIMDAL_PRINTF_ATTRIBUTE(x) __attribute__ ((__format__ x))
#else
#define HEIMDAL_PRINTF_ATTRIBUTE(x)
#endif
#endif

#ifndef HEIMDAL_NORETURN_ATTRIBUTE
#if __has_extension(noreturn) || KRB5TYPES_REQUIRE_GNUC(3,1,0)
#define HEIMDAL_NORETURN_ATTRIBUTE __attribute__ ((__noreturn__))
#else
#define HEIMDAL_NORETURN_ATTRIBUTE
#endif
#endif

#ifndef HEIMDAL_UNUSED_ATTRIBUTE
#if __has_extension(unused) || KRB5TYPES_REQUIRE_GNUC(3,1,0)
#define HEIMDAL_UNUSED_ATTRIBUTE __attribute__ ((__unused__))
#else
#define HEIMDAL_UNUSED_ATTRIBUTE
#endif
#endif

#ifndef HEIMDAL_WARN_UNUSED_RESULT_ATTRIBUTE
#if __has_extension(warn_unused_result) || KRB5TYPES_REQUIRE_GNUC(3,3,0)
#define HEIMDAL_WARN_UNUSED_RESULT_ATTRIBUTE __attribute__ ((__warn_unused_result__))
#else
#define HEIMDAL_WARN_UNUSED_RESULT_ATTRIBUTE
#endif
#endif

#endif /* __D__Work_Custom_kodi_addons_heimdal_include____out_dest_AMD64_inc_krb5_types_h__ */
