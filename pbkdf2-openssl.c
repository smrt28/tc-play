/*
 * Copyright (c) 2011 Alex Hornung <alex@alexhornung.com>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#error not supported

#include <errno.h>
#include <openssl/evp.h>

#include "tcplay.h"

#include "config.h"

#ifdef HAVE_ARGON2
#include "argon2-hash.h"
#endif

#ifdef DEBUG
static void print_hex(unsigned char *buf, size_t len) {
    size_t i;
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);

    printf("\n");
}
#endif


int
pbkdf2(struct pbkdf_prf_algo *hash, const char *pass, int passlen,
    const unsigned char *salt, int saltlen,
    int keylen, unsigned char *out)
{
#ifdef HAVE_ARGON2
    if (strcmp(hash->name, "ARGON2") == 0) {
        if (argon2(pass, passlen,
                    salt, saltlen,
                    out, keylen, hash->iteration_count) != 0) {
            tc_log(1, "Error in ARGON2\n");
            return EINVAL;
        }
#ifdef DEBUG
        printf("ARGON2 derived key: ");
        print_hex(out, keylen);
#endif
        return 0;
    } else
#endif
    {

        const EVP_MD *md;
        int r;

        OpenSSL_add_all_algorithms();

        md = EVP_get_digestbyname(hash->name);
        if (md == NULL) {
            tc_log(1, "Hash %s not found\n", hash->name);
            return ENOENT;
        }
        r = PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen,
                hash->iteration_count, md, keylen, out);

        if (r == 0) {
            tc_log(1, "Error in PBKDF2\n");
            return EINVAL;
        }

        return 0;
    }
    return EINVAL;
}
