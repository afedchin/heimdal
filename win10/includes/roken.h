/* This is an OS dependent, generated file */


#ifndef __ROKEN_H__
#define __ROKEN_H__

/* -*- C -*- */
/*
 * Copyright (c) 1995-2017 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* _CRT_RAND_S must be defined before including stdlib.h */
# define _CRT_RAND_S
# define HAVE_WIN32_RAND_S 1

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <signal.h>


#  define ROKEN_LIB_CALL     __cdecl
#  ifdef ROKEN_LIB_DYNAMIC
#    define ROKEN_LIB_FUNCTION __declspec(dllimport)
#    define ROKEN_LIB_VARIABLE __declspec(dllimport)
#  else
#    define ROKEN_LIB_FUNCTION
#    define ROKEN_LIB_VARIABLE
#  endif

/* Declarations for Microsoft Windows */

#include <winsock2.h>
#include <ws2tcpip.h>

/*
 * error codes for inet_ntop/inet_pton
 */
typedef SOCKET rk_socket_t;

#define rk_closesocket(x) closesocket(x)
#define rk_INVALID_SOCKET INVALID_SOCKET
#define rk_IS_BAD_SOCKET(s) ((s) == INVALID_SOCKET)
#define rk_IS_SOCKET_ERROR(rv) ((rv) == SOCKET_ERROR)
#define rk_SOCK_ERRNO WSAGetLastError()

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL rk_SOCK_IOCTL(SOCKET s, long cmd, int * argp);

#define rk_SOCK_INIT() rk_WSAStartup()
#define rk_SOCK_EXIT() rk_WSACleanup()

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL rk_WSAStartup(void);
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL rk_WSACleanup(void);


#define IN_LOOPBACKNET 127

#include <intsafe.h>

/* Declarations for Microsoft Visual C runtime on Windows */

#include<process.h>

#include<io.h>

#define __BIT_TYPES_DEFINED__

typedef __int8             int8_t;
typedef __int16            int16_t;
typedef __int32            int32_t;
typedef __int64            int64_t;
typedef unsigned __int8    uint8_t;
typedef unsigned __int16   uint16_t;
typedef unsigned __int32   uint32_t;
typedef unsigned __int64   uint64_t;
typedef uint8_t            u_int8_t;
typedef uint16_t           u_int16_t;
typedef uint32_t           u_int32_t;
typedef uint64_t           u_int64_t;


#define UNREACHABLE(x) x
#define UNUSED_ARGUMENT(x) ((void) x)

#define RETSIGTYPE void

#define VOID_RETSIGTYPE 1

#define SIGRETURN(x) return (RETSIGTYPE)(x)


typedef int pid_t;

typedef unsigned int gid_t;

typedef unsigned int uid_t;

typedef unsigned short mode_t;


#define inline __inline


#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>
#include <time.h>


#include <dirent.h>
#include <direct.h>


#define rk_PATH_DELIM '\\'

typedef __int64 ssize_t;
#define SSIZE_T_DEFINED

#include <roken-common.h>

ROKEN_CPP_START

#define rk_UNCONST(x) ((void *)(uintptr_t)(const void *)(x))


/* Additional macros for Visual C/C++ runtime */

#define close	_close

#define getpid	GetCurrentProcessId

#define open	_open

#define chdir   _chdir

#define fsync   _commit

/* The MSVC implementation of snprintf is not C99 compliant.  */
#define snprintf    rk_snprintf
#define vsnprintf   rk_vsnprintf
#define vasnprintf  rk_vasnprintf
#define vasprintf   rk_vasprintf
#define asnprintf   rk_asnprintf
#define asprintf    rk_asprintf

#define _PIPE_BUFFER_SZ 8192
#define pipe(fds) _pipe((fds), _PIPE_BUFFER_SZ, O_BINARY);

#define ftruncate(fd, sz) _chsize((fd), (sz))

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_snprintf (char *str, size_t sz, const char *format, ...);

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_asprintf (char **ret, const char *format, ...);

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_asnprintf (char **ret, size_t max_sz, const char *format, ...);

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_vasprintf (char **ret, const char *format, va_list args);

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_vasnprintf (char **ret, size_t max_sz, const char *format, va_list args);

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_vsnprintf (char *str, size_t sz, const char *format, va_list args);

/* missing stat.h predicates */

#define S_ISREG(m) (((m) & _S_IFREG) == _S_IFREG)

#define S_ISDIR(m) (((m) & _S_IFDIR) == _S_IFDIR)

#define S_ISCHR(m) (((m) & _S_IFCHR) == _S_IFCHR)

#define S_ISFIFO(m) (((m) & _S_IFIFO) == _S_IFIFO)

/* The following are not implemented:

 S_ISLNK(m)
 S_ISSOCK(m)
 S_ISBLK(m)
*/

/* The following symbolic constants are provided for rk_mkdir mode */

#define S_IRWXU 00700 /* user (file owner) has read, write and execute permission */
#define S_IRUSR 00400 /* user has read permission */
#define S_IWUSR 00200 /* user has write permission */
#define S_IXUSR 00100 /* user has execute permission */
#define S_IRWXG 00070 /* group has read, write and execute permission */
#define S_IRGRP 00040 /* group has read permission */
#define S_IWGRP 00020 /* group has write permission */
#define S_IXGRP 00010 /* group has execute permission */
#define S_IRWXO 00007 /* others have read, write and execute permission */
#define S_IROTH 00004 /* others have read permission */
#define S_IWOTH 00002 /* others have write permission */
#define S_IXOTH 00001 /* others have execute permission */

/* Ensure that a common memory allocator is used by all */
#define calloc  rk_calloc
#define free    rk_free
#define malloc  rk_malloc
#define realloc rk_realloc
#define strdup  rk_strdup
#define wcsdup  rk_wcsdup

ROKEN_LIB_FUNCTION void * ROKEN_LIB_CALL
rk_calloc(size_t, size_t);

ROKEN_LIB_FUNCTION void ROKEN_LIB_CALL
rk_free(void *);

ROKEN_LIB_FUNCTION void * ROKEN_LIB_CALL
rk_malloc(size_t);

ROKEN_LIB_FUNCTION void * ROKEN_LIB_CALL
rk_realloc(void *, size_t);

ROKEN_LIB_FUNCTION char * ROKEN_LIB_CALL
rk_strdup(const char *);

ROKEN_LIB_FUNCTION unsigned short * ROKEN_LIB_CALL
rk_wcsdup(const unsigned short *);



/* While we are at it, define WinSock specific scatter gather socket
   I/O. */

#define iovec    _WSABUF
#define iov_base buf
#define iov_len  len

struct msghdr {
    void           *msg_name;
    socklen_t       msg_namelen;
    struct iovec   *msg_iov;
    size_t          msg_iovlen;
    void           *msg_control;
    socklen_t       msg_controllen;
    int             msg_flags;
};

#define sendmsg sendmsg_w32

ROKEN_LIB_FUNCTION ssize_t ROKEN_LIB_CALL
sendmsg_w32(rk_socket_t s, const struct msghdr * msg, int flags);



ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL setenv(const char *, const char *, int);

#define unsetenv rk_unsetenv
ROKEN_LIB_FUNCTION void ROKEN_LIB_CALL unsetenv(const char *);

#define getusershell rk_getusershell
#define endusershell rk_endusershell
ROKEN_LIB_FUNCTION char * ROKEN_LIB_CALL getusershell(void);
ROKEN_LIB_FUNCTION void ROKEN_LIB_CALL endusershell(void);

#define snprintf rk_snprintf
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
     rk_snprintf (char *, size_t, const char *, ...)
     __attribute__ ((__format__ (__printf__, 3, 4)));

#define vsnprintf rk_vsnprintf
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
     rk_vsnprintf (char *, size_t, const char *, va_list)
     __attribute__ ((__format__ (__printf__, 3, 0)));

#define asprintf rk_asprintf
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
     rk_asprintf (char **, const char *, ...)
     __attribute__ ((__format__ (__printf__, 2, 3)));

#define vasprintf rk_vasprintf
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
    rk_vasprintf (char **, const char *, va_list)
     __attribute__ ((__format__ (__printf__, 2, 0)));

#define asnprintf rk_asnprintf
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
    rk_asnprintf (char **, size_t, const char *, ...)
     __attribute__ ((__format__ (__printf__, 3, 4)));

#define vasnprintf rk_vasnprintf
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
    vasnprintf (char **, size_t, const char *, va_list)
     __attribute__ ((__format__ (__printf__, 3, 0)));


#define strndup rk_strndup
ROKEN_LIB_FUNCTION char * ROKEN_LIB_CALL strndup(const char *, size_t);



#define strsep rk_strsep
ROKEN_LIB_FUNCTION char * ROKEN_LIB_CALL strsep(char**, const char*);

#define strsep_copy rk_strsep_copy
ROKEN_LIB_FUNCTION ssize_t ROKEN_LIB_CALL strsep_copy(const char**, const char*, char*, size_t);



ROKEN_LIB_FUNCTION char * ROKEN_LIB_CALL strtok_r(char *, const char *, char **);


#define strlcpy rk_strlcpy
ROKEN_LIB_FUNCTION size_t ROKEN_LIB_CALL strlcpy (char *, const char *, size_t);

#define strlcat rk_strlcat
ROKEN_LIB_FUNCTION size_t ROKEN_LIB_CALL strlcat (char *, const char *, size_t);

#define getdtablesize rk_getdtablesize
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL getdtablesize(void);


int ROKEN_LIB_FUNCTION rk_strerror_r(int, char *, size_t);

#define hstrerror rk_hstrerror
/* This causes a fatal error under Psoriasis */
ROKEN_LIB_FUNCTION const char * ROKEN_LIB_CALL hstrerror(int);


#define inet_aton rk_inet_aton
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL inet_aton(const char *, struct in_addr *);





ROKEN_LIB_FUNCTION const char * ROKEN_LIB_CALL get_default_username (void);

#define seteuid rk_seteuid
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL seteuid(uid_t);

#define setegid rk_setegid
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL setegid(gid_t);

#define lstat rk_lstat
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL lstat(const char *, struct stat *);

#define mkstemp rk_mkstemp
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL mkstemp(char *);

#define cgetent rk_cgetent
#define cgetstr rk_cgetstr
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL cgetent(char **, char **, const char *);
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL cgetstr(char *, const char *, char **);

#define initgroups rk_initgroups
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL initgroups(const char *, gid_t);

#define fchown rk_fchown
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL fchown(int, uid_t, gid_t);

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL rk_rename(const char *, const char *);

#define rk_mkdir(__rk_rn_name, __rk_rn_mode) mkdir(__rk_rn_name)


#define daemon rk_daemon
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL daemon(int, int);


#define rcmd rk_rcmd
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
    rcmd(char **, unsigned short, const char *,
	 const char *, const char *, int *);

#define innetgr rk_innetgr
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL innetgr(const char*, const char*,
    const char*, const char*);

#define iruserok rk_iruserok
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL iruserok(unsigned, int,
    const char *, const char *);


#define writev rk_writev
ROKEN_LIB_FUNCTION ssize_t ROKEN_LIB_CALL
writev(int, const struct iovec *, int);

#define readv rk_readv
ROKEN_LIB_FUNCTION ssize_t ROKEN_LIB_CALL
readv(int, const struct iovec *, int);

#define rk_pidfile(x) ((void) 0)

#define bswap64 rk_bswap64
ROKEN_LIB_FUNCTION uint64_t ROKEN_LIB_CALL bswap64(uint64_t);

#define bswap32 rk_bswap32
ROKEN_LIB_FUNCTION unsigned int ROKEN_LIB_CALL bswap32(unsigned int);

#define bswap16 rk_bswap16
ROKEN_LIB_FUNCTION unsigned short ROKEN_LIB_CALL bswap16(unsigned short);

#define LOCK_SH   1		/* Shared lock */
#define LOCK_EX   2		/* Exclusive lock */
#define LOCK_NB   4		/* Don't block when locking */
#define LOCK_UN   8		/* Unlock */

#define flock(_x,_y) rk_flock(_x,_y)
int rk_flock(int fd, int operation);


ROKEN_LIB_FUNCTION time_t ROKEN_LIB_CALL tm2time (struct tm, int);

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL unix_verify_user(char *, char *);

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL roken_concat (char *, size_t, ...);

ROKEN_LIB_FUNCTION size_t ROKEN_LIB_CALL roken_mconcat (char **, size_t, ...);

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL roken_vconcat (char *, size_t, va_list);

ROKEN_LIB_FUNCTION size_t ROKEN_LIB_CALL
    roken_vmconcat (char **, size_t, va_list);

ROKEN_LIB_FUNCTION void ROKEN_LIB_CALL roken_detach_prep(int, char **, char *);
ROKEN_LIB_FUNCTION void ROKEN_LIB_CALL roken_detach_finish(const char *, int);

ROKEN_LIB_FUNCTION ssize_t ROKEN_LIB_CALL
    net_write (rk_socket_t, const void *, size_t);

ROKEN_LIB_FUNCTION ssize_t ROKEN_LIB_CALL
    net_read (rk_socket_t, void *, size_t);

ROKEN_LIB_FUNCTION unsigned long ROKEN_LIB_CALL
    rk_getauxval(unsigned long);

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
    issuid(void);

ROKEN_LIB_FUNCTION char * ROKEN_LIB_CALL
    rk_secure_getenv(const char *);

#undef secure_getenv
#define secure_getenv(e) rk_secure_getenv(e)

struct winsize {
	unsigned short ws_row, ws_col;
	unsigned short ws_xpixel, ws_ypixel;
};

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL get_window_size(int fd, int *, int *);


#define getopt rk_getopt
#define optarg rk_optarg
#define optind rk_optind
#define opterr rk_opterr
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
getopt(int nargc, char * const *nargv, const char *ostr);

ROKEN_LIB_VARIABLE extern char *optarg;
ROKEN_LIB_VARIABLE extern int optind;
ROKEN_LIB_VARIABLE extern int opterr;

#define getipnodebyname rk_getipnodebyname
ROKEN_LIB_FUNCTION struct hostent * ROKEN_LIB_CALL
getipnodebyname (const char *, int, int, int *);

#define getipnodebyaddr rk_getipnodebyaddr
ROKEN_LIB_FUNCTION struct hostent * ROKEN_LIB_CALL
getipnodebyaddr (const void *, size_t, int, int *);

#define freehostent rk_freehostent
ROKEN_LIB_FUNCTION void ROKEN_LIB_CALL
freehostent (struct hostent *);

#define copyhostent rk_copyhostent
ROKEN_LIB_FUNCTION struct hostent * ROKEN_LIB_CALL
copyhostent (const struct hostent *);









ROKEN_LIB_FUNCTION unsigned int ROKEN_LIB_CALL
sleep(unsigned int seconds);

ROKEN_LIB_FUNCTION unsigned int ROKEN_LIB_CALL
usleep(unsigned int useconds);


ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
getnameinfo_verified(const struct sockaddr *, socklen_t,
		     char *, size_t,
		     char *, size_t,
		     int);

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
roken_getaddrinfo_hostspec(const char *, int, struct addrinfo **);
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
roken_getaddrinfo_hostspec2(const char *, int, int, struct addrinfo **);


#define strptime rk_strptime
ROKEN_LIB_FUNCTION char * ROKEN_LIB_CALL
strptime (const char *, const char *, struct tm *);

#define gettimeofday rk_gettimeofday
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
gettimeofday (struct timeval *, void *);

#define emalloc rk_emalloc
ROKEN_LIB_FUNCTION void * ROKEN_LIB_CALL emalloc (size_t);
#define ecalloc rk_ecalloc
ROKEN_LIB_FUNCTION void * ROKEN_LIB_CALL ecalloc(size_t, size_t);
#define erealloc rk_erealloc
ROKEN_LIB_FUNCTION void * ROKEN_LIB_CALL erealloc (void *, size_t);
#define estrdup rk_estrdup
ROKEN_LIB_FUNCTION char * ROKEN_LIB_CALL estrdup (const char *);

/*
 * kludges and such
 */

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
roken_gethostby_setup(const char*, const char*);
ROKEN_LIB_FUNCTION struct hostent* ROKEN_LIB_CALL
roken_gethostbyname(const char*);
ROKEN_LIB_FUNCTION struct hostent* ROKEN_LIB_CALL
roken_gethostbyaddr(const void*, size_t, int);

#define roken_getservbyname(x,y) getservbyname(x,y)

#define roken_openlog(a,b,c) openlog(a,b,c)

#define roken_getsockname(a,b,c) getsockname(a, b, (void*)c)

#define setprogname rk_setprogname
ROKEN_LIB_FUNCTION void ROKEN_LIB_CALL setprogname(const char *);

#define getprogname rk_getprogname
ROKEN_LIB_FUNCTION const char * ROKEN_LIB_CALL getprogname(void);

extern const char *__progname;

ROKEN_LIB_FUNCTION void ROKEN_LIB_CALL
mini_inetd_addrinfo (struct addrinfo*, rk_socket_t *);

ROKEN_LIB_FUNCTION void ROKEN_LIB_CALL
mini_inetd (int, rk_socket_t *);

#define localtime_r rk_localtime_r
ROKEN_LIB_FUNCTION struct tm * ROKEN_LIB_CALL
localtime_r(const time_t *, struct tm *);

#define strtoll rk_strtoll
ROKEN_LIB_FUNCTION long long ROKEN_LIB_CALL
strtoll(const char * nptr, char ** endptr, int base);

#define strtoull rk_strtoull
ROKEN_LIB_FUNCTION unsigned long long ROKEN_LIB_CALL
strtoull(const char * nptr, char ** endptr, int base);

#define strsvis rk_strsvis
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
strsvis(char *, const char *, int, const char *);

#define strsvisx rk_strsvisx
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
strsvisx(char *, const char *, size_t, int, const char *);

#define strunvis rk_strunvis
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
strunvis(char *, const char *);

#define strvis rk_strvis
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
strvis(char *, const char *, int);

#define strvisx rk_strvisx
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
strvisx(char *, const char *, size_t, int);

#define svis rk_svis
ROKEN_LIB_FUNCTION char * ROKEN_LIB_CALL
svis(char *, int, int, int, const char *);

#define unvis rk_unvis
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
unvis(char *, int, int *, int);

#define vis rk_vis
ROKEN_LIB_FUNCTION char * ROKEN_LIB_CALL
vis(char *, int, int, int);

#define closefrom rk_closefrom
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
closefrom(int);

#define timegm rk_timegm
ROKEN_LIB_FUNCTION time_t ROKEN_LIB_CALL
rk_timegm(struct tm *tm);


#define memset_s rk_memset_s
ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL memset_s(void *s, size_t smax,
					int c, size_t n);

# ifdef HAVE_WIN32_RAND_S
ROKEN_LIB_FUNCTION unsigned int ROKEN_LIB_CALL
rk_random(void);
# else
#  define rk_random() rand()
# endif

#define tdelete(a,b,c) rk_tdelete(a,b,c)
#define tfind(a,b,c) rk_tfind(a,b,c)
#define tsearch(a,b,c) rk_tsearch(a,b,c)
#define twalk(a,b) rk_twalk(a,b)


/* Microsoft VC 2010 POSIX definitions */



ROKEN_CPP_END

#endif /* __ROKEN_H__ */
