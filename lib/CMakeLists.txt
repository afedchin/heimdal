cmake_minimum_required(VERSION 3.9)

project(heimdal C CXX)

add_definitions(-D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_DEPRECATE -D_WINSOCK_DEPRECATED_NO_WARNINGS -D_COM_ERR_STATIC)
# Disable warnings:
#
# C4996: 'function' was declared deprecated
# C4127: Conditional expression is constant
# C4244: Conversion from 'type1' to 'type2', possible loss of data
# C4100: 'identifier': unreferenced formal parameter
# C4706: Assignment within conditional expression
# C4214: Nonstandard extension used
# C4267: '': Conversion from 'type1' to 'type2', possible loss of data
# C4018: '': Signed/unsigned mismatch
# C4204: Nonstandard extension used: non-constant aggregate initializer
# C4221: Nonstandard extension used: 'v1': cannot be initialized using address of automatic variable 'v2'
# C4295: '': Array is too small to include a terminating null character
# C4146: Unary minus operator applied to unsigned type, result still unsigned.
# C4101: unreferenced local variable
add_compile_options(-wd4146 -wd4996 -wd4127 -wd4244 -wd4100 -wd4706 -wd4214 -wd4267 -wd4018 -wd4389 -wd4204 -wd4221 -wd4295 -wd4101)

set(WIN10DIR ${CMAKE_SOURCE_DIR}/../win10)
include_directories(${CMAKE_SOURCE_DIR}/../win10/includes)

set(libroken_SOURCES
 	roken/base64.c
	roken/bswap.c
	roken/concat.c
	roken/cloexec.c
	roken/ct.c	
	roken/detach.c
	roken/dirent.c
	roken/dlfcn_w32.c
	roken/dumpdata.c
	roken/ecalloc.c
	roken/emalloc.c
	roken/environment.c
	roken/eread.c
	roken/erealloc.c
	roken/err.c	
	roken/errx.c	
	roken/esetenv.c
	roken/estrdup.c
	roken/ewrite.c
	roken/flock.c
	roken/fnmatch.c
	roken/fseeko.c
	roken/ftello.c
	roken/getauxval.c
	roken/getaddrinfo_hostspec.c
	roken/get_default_username.c
	roken/get_window_size.c
	roken/getarg.c
	roken/getifaddrs_w32.c
	roken/getnameinfo_verified.c
	roken/getopt.c
	roken/getprogname.c
	roken/gettimeofday.c
	roken/hex.c	
	roken/hostent_find_fqdn.c
	roken/inet_aton.c
	roken/issuid.c
	roken/localtime_r.c
	roken/lstat.c
	roken/memset_s.c 
	roken/mkdir.c
	roken/mini_inetd.c
	roken/mkstemp.c
	roken/net_read.c
	roken/net_write.c
	roken/parse_bytes.c
	roken/parse_time.c
	roken/parse_units.c
	roken/realloc.c
	roken/rename.c
	roken/resolve.c
	roken/rand.c	
	roken/roken_gethostby.c
	roken/rtbl.c	
	roken/secure_getenv.c
	roken/sendmsg.c
	roken/setenv.c
	roken/setprogname.c
	roken/simple_exec_w32.c
	roken/sleep.c
	roken/snprintf.c
	roken/socket.c
	roken/sockstartup_w32.c
	roken/strcollect.c
	roken/strerror_r.c
	roken/strlcat.c
	roken/strlcpy.c
	roken/strndup.c
	roken/strpool.c
	roken/strptime.c
	roken/strsep.c
	roken/strsep_copy.c
	roken/strtok_r.c
	roken/strtoll.c
	roken/strtoull.c
	roken/syslogc.c
	roken/timegm.c
	roken/timeval.c
	roken/tm2time.c
	roken/tsearch.c
	roken/unvis.c
	roken/verr.c	
	roken/verrx.c
	roken/vis.c	
	roken/vwarn.c
	roken/vwarnx.c
	roken/warn.c	
	roken/warnerr.c
	roken/warnx.c
	roken/win32_alloc.c
	roken/writev.c
	roken/xfree.c
)
add_library(libroken OBJECT ${libroken_SOURCES})

set(libheimbase_SOURCES
	base/array.c
	base/bool.c
	base/bsearch.c
	base/data.c
	base/db.c
	base/dict.c
	base/dll.c
	base/error.c
	base/heimbase.c
	base/json.c
	base/null.c
	base/number.c
	base/string.c)
add_library(libheimbase OBJECT ${libheimbase_SOURCES})
#target_link_libraries(libheimbase libroken)

set(com_err_SOURCES 
	com_err/error.c 
	com_err/com_err.c)

add_library(com_err OBJECT ${com_err_SOURCES})
target_compile_definitions(com_err PRIVATE -DBUILD_KRB5_LIB)
#target_link_libraries(com_err libroken)

set(libwind_SOURCES 
	wind/bidi.c
	wind/combining.c
	wind/errorlist.c
	wind/map.c
	wind/ldap.c
	wind/normalize.c
	wind/punycode.c
	wind/stringprep.c
	wind/utf8.c
	${WIN10DIR}/wind/bidi_table.c
	${WIN10DIR}/wind/combining_table.c
	${WIN10DIR}/wind/errorlist_table.c
	${WIN10DIR}/wind/map_table.c
	${WIN10DIR}/wind/normalize_table.c
	${WIN10DIR}/wind/wind_err.c
	)
add_library(libwind OBJECT ${libwind_SOURCES})
target_include_directories(libwind PRIVATE ${CMAKE_SOURCE_DIR}/wind ${WIN10DIR}/wind)

set(libasn1_SOURCES 
	asn1/der.c
	asn1/der_get.c
	asn1/der_put.c
	asn1/der_free.c
	asn1/der_length.c
	asn1/der_copy.c
	asn1/der_cmp.c
	asn1/der_format.c
	asn1/extra.c
	asn1/timegm.c
	${WIN10DIR}/asn1/asn1_err.c
	${WIN10DIR}/asn1/asn1_rfc2459_asn1.c
	${WIN10DIR}/asn1/asn1_cms_asn1.c
	${WIN10DIR}/asn1/asn1_krb5_asn1.c
	${WIN10DIR}/asn1/asn1_pkinit_asn1.c
	${WIN10DIR}/asn1/asn1_pkcs8_asn1.c
	${WIN10DIR}/asn1/asn1_pkcs9_asn1.c
	${WIN10DIR}/asn1/asn1_pkcs12_asn1.c
	${WIN10DIR}/asn1/asn1_digest_asn1.c
	${WIN10DIR}/asn1/asn1_kx509_asn1.c
	)

add_library(libasn1 OBJECT ${libasn1_SOURCES})
target_include_directories(libasn1 PRIVATE ${CMAKE_SOURCE_DIR}/asn1 ${WIN10DIR}/asn1)
#target_link_libraries(libasn1 libroken)

set(sqlite3_SOURCES 
	sqlite/sqlite3.c
	sqlite/sqlite3.h
	sqlite/sqlite3ext.h
	)

add_library(sqlite3 OBJECT ${sqlite3_SOURCES})
target_include_directories(sqlite3 PRIVATE ${CMAKE_SOURCE_DIR}/sqlite)
target_compile_definitions(sqlite3 PRIVATE -DSQLITE_OS_WINRT)

set(libltm_SOURCES	
	hcrypto/libtommath/bncore.c
	hcrypto/libtommath/bn_mp_init.c
	hcrypto/libtommath/bn_mp_clear.c
	hcrypto/libtommath/bn_mp_exch.c
	hcrypto/libtommath/bn_mp_grow.c
	hcrypto/libtommath/bn_mp_shrink.c
	hcrypto/libtommath/bn_mp_clamp.c
	hcrypto/libtommath/bn_mp_zero.c
	hcrypto/libtommath/bn_mp_zero_multi.c
	hcrypto/libtommath/bn_mp_set.c
	hcrypto/libtommath/bn_mp_set_int.c
	hcrypto/libtommath/bn_mp_init_size.c
	hcrypto/libtommath/bn_mp_copy.c
	hcrypto/libtommath/bn_mp_init_copy.c
	hcrypto/libtommath/bn_mp_abs.c
	hcrypto/libtommath/bn_mp_neg.c
	hcrypto/libtommath/bn_mp_cmp_mag.c
	hcrypto/libtommath/bn_mp_cmp.c
	hcrypto/libtommath/bn_mp_cmp_d.c
	hcrypto/libtommath/bn_mp_rshd.c
	hcrypto/libtommath/bn_mp_lshd.c
	hcrypto/libtommath/bn_mp_mod_2d.c
	hcrypto/libtommath/bn_mp_div_2d.c
	hcrypto/libtommath/bn_mp_mul_2d.c
	hcrypto/libtommath/bn_mp_div_2.c
	hcrypto/libtommath/bn_mp_mul_2.c
	hcrypto/libtommath/bn_s_mp_add.c
	hcrypto/libtommath/bn_s_mp_sub.c
	hcrypto/libtommath/bn_fast_s_mp_mul_digs.c
	hcrypto/libtommath/bn_s_mp_mul_digs.c
	hcrypto/libtommath/bn_fast_s_mp_mul_high_digs.c
	hcrypto/libtommath/bn_s_mp_mul_high_digs.c
	hcrypto/libtommath/bn_fast_s_mp_sqr.c
	hcrypto/libtommath/bn_s_mp_sqr.c
	hcrypto/libtommath/bn_mp_add.c
	hcrypto/libtommath/bn_mp_sub.c
	hcrypto/libtommath/bn_mp_karatsuba_mul.c
	hcrypto/libtommath/bn_mp_mul.c
	hcrypto/libtommath/bn_mp_karatsuba_sqr.c
	hcrypto/libtommath/bn_mp_sqr.c
	hcrypto/libtommath/bn_mp_div.c
	hcrypto/libtommath/bn_mp_mod.c
	hcrypto/libtommath/bn_mp_add_d.c
	hcrypto/libtommath/bn_mp_sub_d.c
	hcrypto/libtommath/bn_mp_mul_d.c
	hcrypto/libtommath/bn_mp_div_d.c
	hcrypto/libtommath/bn_mp_mod_d.c
	hcrypto/libtommath/bn_mp_expt_d.c
	hcrypto/libtommath/bn_mp_addmod.c
	hcrypto/libtommath/bn_mp_submod.c
	hcrypto/libtommath/bn_mp_mulmod.c
	hcrypto/libtommath/bn_mp_sqrmod.c
	hcrypto/libtommath/bn_mp_gcd.c
	hcrypto/libtommath/bn_mp_lcm.c
	hcrypto/libtommath/bn_fast_mp_invmod.c
	hcrypto/libtommath/bn_mp_invmod.c
	hcrypto/libtommath/bn_mp_reduce.c
	hcrypto/libtommath/bn_mp_montgomery_setup.c
	hcrypto/libtommath/bn_fast_mp_montgomery_reduce.c
	hcrypto/libtommath/bn_mp_montgomery_reduce.c
	hcrypto/libtommath/bn_mp_exptmod_fast.c
	hcrypto/libtommath/bn_mp_exptmod.c
	hcrypto/libtommath/bn_mp_2expt.c
	hcrypto/libtommath/bn_mp_n_root.c
	hcrypto/libtommath/bn_mp_jacobi.c
	hcrypto/libtommath/bn_reverse.c
	hcrypto/libtommath/bn_mp_count_bits.c
	hcrypto/libtommath/bn_mp_read_unsigned_bin.c
	hcrypto/libtommath/bn_mp_read_signed_bin.c
	hcrypto/libtommath/bn_mp_to_unsigned_bin.c
	hcrypto/libtommath/bn_mp_to_signed_bin.c
	hcrypto/libtommath/bn_mp_unsigned_bin_size.c
	hcrypto/libtommath/bn_mp_signed_bin_size.c
	hcrypto/libtommath/bn_mp_xor.c
	hcrypto/libtommath/bn_mp_and.c
	hcrypto/libtommath/bn_mp_or.c
	hcrypto/libtommath/bn_mp_rand.c
	hcrypto/libtommath/bn_mp_montgomery_calc_normalization.c
	hcrypto/libtommath/bn_mp_prime_is_divisible.c
	hcrypto/libtommath/bn_prime_tab.c
	hcrypto/libtommath/bn_mp_prime_fermat.c
	hcrypto/libtommath/bn_mp_prime_miller_rabin.c
	hcrypto/libtommath/bn_mp_prime_is_prime.c
	hcrypto/libtommath/bn_mp_prime_next_prime.c
	hcrypto/libtommath/bn_mp_find_prime.c
	hcrypto/libtommath/bn_mp_dr_reduce.c
	hcrypto/libtommath/bn_mp_dr_is_modulus.c
	hcrypto/libtommath/bn_mp_dr_setup.c
	hcrypto/libtommath/bn_mp_reduce_setup.c
	hcrypto/libtommath/bn_mp_toom_mul.c
	hcrypto/libtommath/bn_mp_toom_sqr.c
	hcrypto/libtommath/bn_mp_div_3.c
	hcrypto/libtommath/bn_s_mp_exptmod.c
	hcrypto/libtommath/bn_mp_reduce_2k.c
	hcrypto/libtommath/bn_mp_reduce_is_2k.c
	hcrypto/libtommath/bn_mp_reduce_2k_setup.c
	hcrypto/libtommath/bn_mp_reduce_2k_l.c
	hcrypto/libtommath/bn_mp_reduce_is_2k_l.c
	hcrypto/libtommath/bn_mp_reduce_2k_setup_l.c
	hcrypto/libtommath/bn_mp_radix_smap.c
	hcrypto/libtommath/bn_mp_read_radix.c
	hcrypto/libtommath/bn_mp_toradix.c
	hcrypto/libtommath/bn_mp_radix_size.c
	hcrypto/libtommath/bn_mp_fread.c
	hcrypto/libtommath/bn_mp_fwrite.c
	hcrypto/libtommath/bn_mp_cnt_lsb.c
	hcrypto/libtommath/bn_error.c
	hcrypto/libtommath/bn_mp_init_multi.c
	hcrypto/libtommath/bn_mp_clear_multi.c
	hcrypto/libtommath/bn_mp_exteuclid.c
	hcrypto/libtommath/bn_mp_toradix_n.c
	hcrypto/libtommath/bn_mp_prime_random_ex.c
	hcrypto/libtommath/bn_mp_get_int.c
	hcrypto/libtommath/bn_mp_sqrt.c
	hcrypto/libtommath/bn_mp_is_square.c
	hcrypto/libtommath/bn_mp_init_set.c
	hcrypto/libtommath/bn_mp_init_set_int.c
	hcrypto/libtommath/bn_mp_invmod_slow.c
	hcrypto/libtommath/bn_mp_prime_rabin_miller_trials.c
	hcrypto/libtommath/bn_mp_to_signed_bin_n.c
	hcrypto/libtommath/bn_mp_to_unsigned_bin_n.c
)
add_library(libltm OBJECT ${libltm_SOURCES})
target_include_directories(libltm PRIVATE ${CMAKE_SOURCE_DIR}/hcrypto/libtommath)

set(libhcrypto_SOURCES 
	hcrypto/aes.c
	hcrypto/bn.c
	hcrypto/camellia.c
	hcrypto/camellia-ntt.c
	hcrypto/common.c
	hcrypto/des.c
	hcrypto/dh.c
	hcrypto/dh-ltm.c
	hcrypto/dh-tfm.c
	hcrypto/dsa.c
	hcrypto/evp.c
	hcrypto/evp-hcrypto.c
	hcrypto/evp-cc.c
	hcrypto/evp-openssl.c
	hcrypto/evp-pkcs11.c
	hcrypto/evp-wincng.c
	hcrypto/evp-w32.c
	hcrypto/engine.c
	hcrypto/hmac.c
	hcrypto/md2.c
	hcrypto/md4.c
	hcrypto/md5.c
	hcrypto/pkcs5.c
	hcrypto/pkcs12.c
	hcrypto/rand-w32.c
	hcrypto/rand.c
	hcrypto/rc2.c
	hcrypto/rc4.c
	hcrypto/rijndael-alg-fst.c
	hcrypto/rnd_keys.c
	hcrypto/rsa.c
	hcrypto/rsa-gmp.c
	hcrypto/rsa-ltm.c
	hcrypto/rsa-tfm.c
	hcrypto/sha.c
	hcrypto/sha256.c
	hcrypto/sha512.c
	hcrypto/ui.c
	hcrypto/validate.c
	)

add_library(libhcrypto OBJECT ${libhcrypto_SOURCES})
target_include_directories(libhcrypto PRIVATE ${CMAKE_SOURCE_DIR}/hcrypto ${CMAKE_SOURCE_DIR}/hx509 ${WIN10DIR}/includes/hcrypto)
target_compile_definitions(libhcrypto PRIVATE -DKRB5 -DASN1_LIB -DUSE_HCRYPTO_LTM=1 -DHAVE_CONFIG_H)
#target_link_libraries(libhcrypto libltm)

set(libhx509_SOURCES 
	hx509/ca.c
	hx509/cert.c
	hx509/cms.c
	hx509/collector.c
	hx509/crypto.c
	hx509/crypto-ec.c
	hx509/error.c
	hx509/env.c
	hx509/file.c
	hx509/sel.c
	hx509/keyset.c
	hx509/ks_dir.c
	hx509/ks_file.c
	hx509/ks_mem.c
	hx509/ks_null.c
	hx509/ks_p11.c
	hx509/ks_p12.c
	hx509/ks_keychain.c
	hx509/lock.c
	hx509/name.c
	hx509/peer.c
	hx509/print.c
	hx509/softp11.c
	hx509/req.c
	hx509/revoke.c
	${WIN10DIR}/hx509/asn1_ocsp_asn1.c
	${WIN10DIR}/hx509/asn1_pkcs10_asn1.c
	${WIN10DIR}/hx509/hx509_err.c
	${WIN10DIR}/hx509/sel-gram.c
	${WIN10DIR}/hx509/sel-lex.c
)
add_library(libhx509 OBJECT ${libhx509_SOURCES})
target_include_directories(libhx509 PRIVATE ${WIN10DIR}/includes ${CMAKE_SOURCE_DIR}/hx509)
target_compile_definitions(libhx509 PRIVATE -DASN1_LIB)
#target_link_libraries(libhx509 libasn1)

set(libkrb5_SOURCES
	krb5/acache.c
	krb5/acl.c
	krb5/add_et_list.c
	krb5/addr_families.c
	krb5/aname_to_localname.c
	krb5/appdefault.c
	krb5/asn1_glue.c
	krb5/auth_context.c
	krb5/build_ap_req.c
	krb5/build_auth.c
	krb5/cache.c
	krb5/changepw.c
	krb5/codec.c
	krb5/config_file.c
#	krb5/config_reg.c
	krb5/constants.c
	krb5/context.c
    krb5/convert_creds.c
	krb5/copy_host_realm.c
	krb5/crc.c
	krb5/creds.c
	krb5/crypto.c
	krb5/crypto-aes-sha1.c
	krb5/crypto-aes-sha2.c
	krb5/crypto-algs.c
	krb5/crypto-arcfour.c
	krb5/crypto-des-common.c
	krb5/crypto-des.c
	krb5/crypto-des3.c
	krb5/crypto-evp.c
	krb5/crypto-null.c
	krb5/crypto-pk.c
	krb5/crypto-rand.c
	krb5/data.c
	krb5/dcache.c
	krb5/db_plugin.c
	krb5/deprecated.c
	krb5/digest.c
	krb5/dll.c
	krb5/eai_to_heim_errno.c
    krb5/enomem.c
	krb5/error_string.c
	krb5/expand_hostname.c
	krb5/expand_path.c
	krb5/fast.c
	krb5/fcache.c
	krb5/free.c
	krb5/free_host_realm.c
	krb5/generate_seq_number.c
	krb5/generate_subkey.c
	krb5/get_addrs.c
	krb5/get_cred.c
	krb5/get_default_principal.c
	krb5/get_default_realm.c
	krb5/get_for_creds.c
	krb5/get_host_realm.c
	krb5/get_in_tkt.c
	krb5/get_port.c
	krb5/init_creds.c
	krb5/init_creds_pw.c
	krb5/kcm.c
	krb5/keyblock.c
	krb5/keytab.c
	krb5/keytab_any.c
	krb5/keytab_file.c
	krb5/keytab_keyfile.c
	krb5/keytab_memory.c
	krb5/krbhst.c
	krb5/kuserok.c
	krb5/log.c
	krb5/mcache.c
	krb5/misc.c
	krb5/mit_glue.c
	krb5/mk_error.c
	krb5/mk_priv.c
	krb5/mk_rep.c
	krb5/mk_req.c
	krb5/mk_req_ext.c
	krb5/mk_safe.c
	krb5/net_read.c
	krb5/net_write.c
	krb5/n-fold.c
	krb5/pac.c
	krb5/padata.c
	krb5/pcache.c
	krb5/pkinit.c
	krb5/pkinit-ec.c
	krb5/plugin.c
	krb5/principal.c
	krb5/prog_setup.c
	krb5/prompter_posix.c
	krb5/rd_cred.c
	krb5/rd_error.c
	krb5/rd_priv.c
	krb5/rd_rep.c
	krb5/rd_req.c
	krb5/rd_safe.c
	krb5/read_message.c
	krb5/recvauth.c
	krb5/replay.c
	krb5/salt-aes-sha1.c
	krb5/salt-aes-sha2.c
	krb5/salt-arcfour.c
	krb5/salt-des.c
	krb5/salt-des3.c
	krb5/salt.c
	krb5/scache.c
	krb5/send_to_kdc.c
	krb5/sendauth.c
	krb5/set_default_realm.c
	krb5/sock_principal.c
	krb5/sp800-108-kdf.c
	krb5/store.c
	krb5/store-int.c
	krb5/store_emem.c
	krb5/store_fd.c
	krb5/store_mem.c
	krb5/store_sock.c
	krb5/store_stdio.c
	krb5/ticket.c
	krb5/time.c
	krb5/transited.c
	krb5/verify_init.c
	krb5/verify_user.c
	krb5/version.c
	krb5/warn.c
	krb5/write_message.c

	${WIN10DIR}/krb5/krb5_err.c
	${WIN10DIR}/krb5/krb_err.c
	${WIN10DIR}/krb5/heim_err.c
	${WIN10DIR}/krb5/k524_err.c
	${WIN10DIR}/uwpapi.cpp
)
add_library(libkrb5 OBJECT ${libkrb5_SOURCES})
target_include_directories(libkrb5 PRIVATE ${WIN10DIR}/includes ${WIN10DIR}/krb5)
target_compile_definitions(libkrb5 PRIVATE -DBUILD_KRB5_LIB -DASN1_LIB)
set_source_files_properties(${WIN10DIR}/uwpapi.cpp PROPERTIES COMPILE_FLAGS "/TP /ZW")

add_library(${PROJECT_NAME} SHARED $<TARGET_OBJECTS:libasn1>
                                   $<TARGET_OBJECTS:com_err>
                                   $<TARGET_OBJECTS:libhcrypto>
                                   $<TARGET_OBJECTS:libhx509>
                                   $<TARGET_OBJECTS:libkrb5>
                                   $<TARGET_OBJECTS:libroken>
                                   $<TARGET_OBJECTS:sqlite3>
                                   $<TARGET_OBJECTS:libwind>
                                   $<TARGET_OBJECTS:libltm>
                                   $<TARGET_OBJECTS:libheimbase>)
target_link_libraries(${PROJECT_NAME} ws2_32.lib bcrypt.lib)
set_target_properties(${PROJECT_NAME} 
	PROPERTIES 
		WINDOWS_EXPORT_ALL_SYMBOLS 1
		LINK_FLAGS_DEBUG "/defaultlib:vccorlibd.lib /defaultlib:msvcrtd.lib"
		LINK_FLAGS_RELEASE "/defaultlib:vccorlib.lib /defaultlib:msvcrt.lib"
		LINK_FLAGS_RELWITHDEBINFO "/defaultlib:vccorlib.lib /defaultlib:msvcrt.lib"
)

set(heimntlm_SOURCES
	ntlm/ntlm.c
	ntlm/heimntlm.h
	${WIN10DIR}/ntlm/heimntlm-protos.h
	${WIN10DIR}/ntlm/ntlm_err.c
	${WIN10DIR}/ntlm/ntlm_err.h
)
add_library(heimntlm SHARED ${heimntlm_SOURCES})
target_include_directories(heimntlm PRIVATE ${WIN10DIR}/includes ${CMAKE_SOURCE_DIR}/ntlm)
target_link_libraries(heimntlm heimdal)
set_target_properties(heimntlm PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS 1)

set(gssapi_SOURCES
	gssapi/krb5/8003.c	
	gssapi/krb5/accept_sec_context.c
	gssapi/krb5/acquire_cred.c
	gssapi/krb5/add_cred.c
	gssapi/krb5/address_to_krb5addr.c
	gssapi/krb5/aeap.c
	gssapi/krb5/arcfour.c
	gssapi/krb5/authorize_localname.c
	gssapi/krb5/canonicalize_name.c
	gssapi/krb5/creds.c
	gssapi/krb5/ccache_name.c
	gssapi/krb5/cfx.c
	gssapi/krb5/cfx.h
	gssapi/krb5/compare_name.c
	gssapi/krb5/compat.c
	gssapi/krb5/context_time.c
	gssapi/krb5/copy_ccache.c
	gssapi/krb5/decapsulate.c
	gssapi/krb5/delete_sec_context.c
	gssapi/krb5/display_name.c
	gssapi/krb5/display_status.c
	gssapi/krb5/duplicate_name.c
	gssapi/krb5/encapsulate.c
	gssapi/krb5/export_name.c
	gssapi/krb5/export_sec_context.c
	gssapi/krb5/external.c
	gssapi/krb5/get_mic.c
	gssapi/krb5/gsskrb5_locl.h
	gssapi/krb5/import_name.c
	gssapi/krb5/import_sec_context.c
	gssapi/krb5/indicate_mechs.c
	gssapi/krb5/init.c
	gssapi/krb5/init_sec_context.c
	gssapi/krb5/inquire_context.c
	gssapi/krb5/inquire_cred.c
	gssapi/krb5/inquire_cred_by_mech.c
	gssapi/krb5/inquire_cred_by_oid.c
	gssapi/krb5/inquire_mechs_for_name.c
	gssapi/krb5/inquire_names_for_mech.c
	gssapi/krb5/inquire_sec_context_by_oid.c
	gssapi/krb5/pname_to_uid.c
	gssapi/krb5/process_context_token.c
	gssapi/krb5/prf.c
	gssapi/krb5/release_buffer.c
	gssapi/krb5/release_cred.c
	gssapi/krb5/release_name.c
	gssapi/krb5/sequence.c
	gssapi/krb5/store_cred.c
	gssapi/krb5/set_cred_option.c
	gssapi/krb5/set_sec_context_option.c
	gssapi/krb5/ticket_flags.c
	gssapi/krb5/unwrap.c
	gssapi/krb5/verify_mic.c
	gssapi/krb5/wrap.c

	gssapi/mech/context.h
	gssapi/mech/context.c
	gssapi/mech/cred.h
	gssapi/mech/gss_accept_sec_context.c
	gssapi/mech/gss_acquire_cred.c
	gssapi/mech/gss_acquire_cred_ext.c
	gssapi/mech/gss_acquire_cred_with_password.c
	gssapi/mech/gss_add_cred.c
	gssapi/mech/gss_add_cred_with_password.c
	gssapi/mech/gss_add_oid_set_member.c
	gssapi/mech/gss_aeap.c
	gssapi/mech/gss_authorize_localname.c
	gssapi/mech/gss_buffer_set.c
	gssapi/mech/gss_canonicalize_name.c
	gssapi/mech/gss_compare_name.c
	gssapi/mech/gss_context_time.c
	gssapi/mech/gss_create_empty_oid_set.c
	gssapi/mech/gss_cred.c
	gssapi/mech/gss_decapsulate_token.c
	gssapi/mech/gss_delete_name_attribute.c
	gssapi/mech/gss_delete_sec_context.c
	gssapi/mech/gss_display_name.c
	gssapi/mech/gss_display_name_ext.c
	gssapi/mech/gss_display_status.c
	gssapi/mech/gss_duplicate_name.c
	gssapi/mech/gss_duplicate_oid.c
	gssapi/mech/gss_encapsulate_token.c
	gssapi/mech/gss_export_name.c
	gssapi/mech/gss_export_name_composite.c
	gssapi/mech/gss_export_sec_context.c
	gssapi/mech/gss_get_mic.c
	gssapi/mech/gss_get_name_attribute.c
	gssapi/mech/gss_import_name.c
	gssapi/mech/gss_import_sec_context.c
	gssapi/mech/gss_indicate_mechs.c
	gssapi/mech/gss_init_sec_context.c
	gssapi/mech/gss_inquire_context.c
	gssapi/mech/gss_inquire_cred.c
	gssapi/mech/gss_inquire_cred_by_mech.c
	gssapi/mech/gss_inquire_cred_by_oid.c
	gssapi/mech/gss_inquire_mechs_for_name.c
	gssapi/mech/gss_inquire_name.c
	gssapi/mech/gss_inquire_names_for_mech.c
	gssapi/mech/gss_krb5.c
	gssapi/mech/gss_mech_switch.c
	gssapi/mech/gss_mo.c
	gssapi/mech/gss_names.c
	gssapi/mech/gss_oid.c
	gssapi/mech/gss_oid_equal.c
	gssapi/mech/gss_oid_to_str.c
	gssapi/mech/gss_pname_to_uid.c
	gssapi/mech/gss_process_context_token.c
	gssapi/mech/gss_pseudo_random.c
	gssapi/mech/gss_release_buffer.c
	gssapi/mech/gss_release_cred.c
	gssapi/mech/gss_release_name.c
	gssapi/mech/gss_release_oid.c
	gssapi/mech/gss_release_oid_set.c
	gssapi/mech/gss_seal.c
	gssapi/mech/gss_set_cred_option.c
	gssapi/mech/gss_set_name_attribute.c
	gssapi/mech/gss_set_sec_context_option.c
	gssapi/mech/gss_sign.c
	gssapi/mech/gss_store_cred.c
	gssapi/mech/gss_test_oid_set_member.c
	gssapi/mech/gss_unseal.c
	gssapi/mech/gss_unwrap.c
	gssapi/mech/gss_utils.c
	gssapi/mech/gss_verify.c
	gssapi/mech/gss_verify_mic.c
	gssapi/mech/gss_wrap.c
	gssapi/mech/gss_wrap_size_limit.c
	gssapi/mech/gss_inquire_sec_context_by_oid.c
	gssapi/mech/mech_switch.h
	gssapi/mech/mechqueue.h
	gssapi/mech/mech_locl.h
	gssapi/mech/name.h
	gssapi/mech/utils.h

	gssapi/spnego/accept_sec_context.c
	gssapi/spnego/compat.c
	gssapi/spnego/context_stubs.c
	gssapi/spnego/cred_stubs.c
	gssapi/spnego/external.c
	gssapi/spnego/init_sec_context.c
	gssapi/spnego/spnego_locl.h

	gssapi/ntlm/accept_sec_context.c
	gssapi/ntlm/acquire_cred.c
	gssapi/ntlm/add_cred.c
	gssapi/ntlm/canonicalize_name.c
	gssapi/ntlm/compare_name.c
	gssapi/ntlm/context_time.c
	gssapi/ntlm/creds.c
	gssapi/ntlm/crypto.c
	gssapi/ntlm/delete_sec_context.c
	gssapi/ntlm/display_name.c
	gssapi/ntlm/display_status.c
	gssapi/ntlm/duplicate_name.c
	gssapi/ntlm/export_name.c
	gssapi/ntlm/export_sec_context.c
	gssapi/ntlm/external.c
	gssapi/ntlm/ntlm.h
	gssapi/ntlm/import_name.c
	gssapi/ntlm/import_sec_context.c
	gssapi/ntlm/indicate_mechs.c
	gssapi/ntlm/init_sec_context.c
	gssapi/ntlm/inquire_context.c
	gssapi/ntlm/inquire_cred_by_mech.c
	gssapi/ntlm/inquire_mechs_for_name.c
	gssapi/ntlm/inquire_names_for_mech.c
	gssapi/ntlm/inquire_sec_context_by_oid.c
	gssapi/ntlm/iter_cred.c
	gssapi/ntlm/process_context_token.c
	gssapi/ntlm/release_cred.c
	gssapi/ntlm/release_name.c
	gssapi/ntlm/kdc.c

	${WIN10DIR}/gssapi/gkrb5_err.c
	${WIN10DIR}/gssapi/gkrb5_err.h

	${WIN10DIR}/gssapi/gssapi/asn1_gssapi_asn1.c
	${WIN10DIR}/gssapi/gssapi/gssapi_asn1.h
	${WIN10DIR}/gssapi/gssapi/gssapi_asn1-priv.h

	${WIN10DIR}/gssapi/krb5/gsskrb5-private.h

	${WIN10DIR}/gssapi/ntlm/ntlm-private.h

	${WIN10DIR}/gssapi/spnego/asn1_spnego_asn1.c
	${WIN10DIR}/gssapi/spnego/spnego-private.h
	${WIN10DIR}/gssapi/spnego/spnego_asn1.h
	${WIN10DIR}/gssapi/spnego/spnego_asn1-priv.h
)
add_library(gssapi SHARED ${gssapi_SOURCES})
target_include_directories(gssapi 
	PRIVATE 
		${CMAKE_SOURCE_DIR}/gssapi 
		${CMAKE_SOURCE_DIR}/gssapi/gssapi 
		${CMAKE_SOURCE_DIR}/gssapi/mech
		${WIN10DIR}/includes 
		${WIN10DIR}/gssapi 
		${WIN10DIR}/gssapi/gssapi 
		${WIN10DIR}/gssapi/krb5
		${WIN10DIR}/gssapi/ntlm
		${WIN10DIR}/gssapi/spnego)
target_link_libraries(gssapi heimdal heimntlm)
target_compile_definitions(gssapi PRIVATE -DBUILD_GSSAPI_LIB -DASN1_LIB)
set_target_properties(gssapi PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS 1)
