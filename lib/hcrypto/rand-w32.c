/*
 * Copyright (c) 2006 Kungliga Tekniska Högskolan
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

#include <config.h>
#include <roken.h>

//#include <wincrypt.h>
#include <bcrypt.h>

#include <rand.h>
#include <heim_threads.h>

#include "randi.h"

volatile static BCRYPT_ALG_HANDLE g_cryptprovider = NULL;

static BCRYPT_ALG_HANDLE
_hc_CryptProvider(void)
{
    int rv;
    BCRYPT_ALG_HANDLE cryptprovider = NULL;

    if (g_cryptprovider != NULL)
	goto out;

    /* try just a default random number generator */
    rv = BCryptOpenAlgorithmProvider(&cryptprovider, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (BCRYPT_SUCCESS(rv)) {
        InterlockedCompareExchangePointer((PVOID *) &g_cryptprovider, (PVOID) cryptprovider, NULL);
    }

out:
    return g_cryptprovider;
}

/*
 *
 */


static void
w32crypto_seed(const void *indata, int size)
{
}


static int
w32crypto_bytes(unsigned char *outdata, int size)
{
    int ret;
    ret = BCryptGenRandom(_hc_CryptProvider(), outdata, size, 0);
    return BCRYPT_SUCCESS(ret) ? 0 : -1;
}

static void
w32crypto_cleanup(void)
{
    BCRYPT_ALG_HANDLE cryptprovider;

    if (InterlockedCompareExchangePointer((PVOID *) &cryptprovider,
					  0, (PVOID) g_cryptprovider) == 0) {
        (void)BCryptCloseAlgorithmProvider(cryptprovider, 0);
    }
}

static void
w32crypto_add(const void *indata, int size, double entropi)
{
}

static int
w32crypto_status(void)
{
    if (_hc_CryptProvider() == 0)
	return 0;
    return 1;
}

const RAND_METHOD hc_rand_w32crypto_method = {
    w32crypto_seed,
    w32crypto_bytes,
    w32crypto_cleanup,
    w32crypto_add,
    w32crypto_bytes,
    w32crypto_status
};

const RAND_METHOD *
RAND_w32crypto_method(void)
{
    return &hc_rand_w32crypto_method;
}
