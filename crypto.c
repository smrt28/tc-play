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
#include <sys/types.h>
#include <sys/param.h>
#include <inttypes.h>

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "config.h"

#include "crc32.h"
#include "tcplay.h"

#ifdef HAVE_YUBIKEY
#include "yubico/tc.h"


#ifdef TC_YK_DEBUG
static void print_hex(const unsigned char *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);

    printf("\n");
}
#endif // TC_YK_DEBUG

#endif // HAVE_YUBIKEY

int
tc_cipher_chain_populate_keys(struct tc_cipher_chain *cipher_chain,
    unsigned char *key)
{
    int total_key_bytes, used_key_bytes;
    struct tc_cipher_chain *dummy_chain;

    /*
     * We need to determine the total key bytes as the key locations
     * depend on it.
     */
    total_key_bytes = tc_cipher_chain_klen(cipher_chain);

    /*
     * Now we need to get prepare the keys, as the keys are in
     * forward order with respect to the cipher cascade, but
     * the actual decryption is in reverse cipher cascade order.
     */
    used_key_bytes = 0;
    for (dummy_chain = cipher_chain;
        dummy_chain != NULL;
        dummy_chain = dummy_chain->next) {
        dummy_chain->key = alloc_safe_mem(dummy_chain->cipher->klen);
        if (dummy_chain->key == NULL) {
            tc_log(1, "tc_decrypt: Could not allocate key "
                "memory\n");
            return ENOMEM;
        }

        /* XXX: here we assume XTS operation! */
        memcpy(dummy_chain->key,
            key + used_key_bytes/2,
            dummy_chain->cipher->klen/2);
        memcpy(dummy_chain->key + dummy_chain->cipher->klen/2,
            key + (total_key_bytes/2) + used_key_bytes/2,
            dummy_chain->cipher->klen/2);

        /* Remember how many key bytes we've seen */
        used_key_bytes += dummy_chain->cipher->klen;
    }

    return 0;
}

int
tc_cipher_chain_free_keys(struct tc_cipher_chain *cipher_chain)
{
    for (; cipher_chain != NULL; cipher_chain = cipher_chain->next) {
        if (cipher_chain->key != NULL) {
            free_safe_mem(cipher_chain->key);
            cipher_chain->key = NULL;
        }
    }

    return 0;
}

int
tc_encrypt(struct tc_cipher_chain *cipher_chain, unsigned char *key,
    unsigned char *iv,
    unsigned char *in, int in_len, unsigned char *out)
{
    struct tc_cipher_chain *chain_start;
    int err;

    chain_start = cipher_chain;

    if ((err = tc_cipher_chain_populate_keys(cipher_chain, key)))
        return err;

#ifdef DEBUG
    printf("tc_encrypt: starting chain\n");
#endif

    /*
     * Now process the actual decryption, in forward cascade order.
     */
    for (;
        cipher_chain != NULL;
        cipher_chain = cipher_chain->next) {
#ifdef DEBUG
        printf("tc_encrypt: Currently using cipher %s\n",
            cipher_chain->cipher->name);
#endif

        err = syscrypt(cipher_chain->cipher, cipher_chain->key,
            cipher_chain->cipher->klen, iv, in, out, in_len, 1);

        /* Deallocate this key, since we won't need it anymore */
        free_safe_mem(cipher_chain->key);
        cipher_chain->key = NULL;

        if (err != 0) {
            tc_cipher_chain_free_keys(chain_start);
            return err;
        }

        /* Set next input buffer as current output buffer */
        in = out;
    }

    tc_cipher_chain_free_keys(chain_start);

    return 0;
}

int
tc_decrypt(struct tc_cipher_chain *cipher_chain, unsigned char *key,
    unsigned char *iv,
    unsigned char *in, int in_len, unsigned char *out)
{
    struct tc_cipher_chain *chain_start;
    int err;

    chain_start = cipher_chain;

    if ((err = tc_cipher_chain_populate_keys(cipher_chain, key)))
        return err;

#ifdef DEBUG
    printf("tc_decrypt: starting chain!\n");
#endif

    /*
     * Now process the actual decryption, in reverse cascade order; so
     * first find the last element in the chain.
     */
    for (; cipher_chain->next != NULL; cipher_chain = cipher_chain->next)
        ;
    for (;
        cipher_chain != NULL;
        cipher_chain = cipher_chain->prev) {
#ifdef DEBUG
        printf("tc_decrypt: Currently using cipher %s\n",
            cipher_chain->cipher->name);
#endif

        err = syscrypt(cipher_chain->cipher, cipher_chain->key,
            cipher_chain->cipher->klen, iv, in, out, in_len, 0);

        /* Deallocate this key, since we won't need it anymore */
        free_safe_mem(cipher_chain->key);
        cipher_chain->key = NULL;

        if (err != 0) {
            tc_cipher_chain_free_keys(chain_start);
            return err;
        }

        /* Set next input buffer as current output buffer */
        in = out;
    }

    tc_cipher_chain_free_keys(chain_start);

    return 0;
}

int
apply_keyfiles(unsigned char *pass, size_t pass_memsz, const char *keyfiles[],
    int nkeyfiles)
{
    int rv = 0;
    int pl, k;
    unsigned char *kpool = NULL;
    unsigned char *kdata = NULL;
    int kpool_idx;
    size_t i, kdata_sz;
    uint32_t crc;

#ifdef HAVE_YUBIKEY
    char errmsg[ERR_MESSAGE_LEN];
#endif

#ifdef HAVE_YK_PIV
    char *ykpin = NULL;
    int yktype;
    struct tc_yubico_key yk;
#endif

    if (pass_memsz < MAX_PASSSZ) {
        tc_log(1, "Not enough memory for password manipulation\n");
        rv = ENOMEM; goto err;
    }

    pl = strlen((char *)pass);
    memset(pass+pl, 0, MAX_PASSSZ-pl);

    if ((kpool = alloc_safe_mem(KPOOL_SZ)) == NULL) {
        tc_log(1, "Error allocating memory for keyfile pool\n");
        rv = ENOMEM; goto err;
    }

    memset(kpool, 0, KPOOL_SZ);


    for (k = 0; k < nkeyfiles; k++) {
#ifdef DEBUG
        printf("Loading keyfile %s into kpool\n", keyfiles[k]);
#endif

#ifdef HAVE_YUBIKEY
    yktype = tc_parse_yubikey_path(keyfiles[k], &yk, errmsg);
    if (yktype != 0) {
        switch (yktype) {
#ifdef HAVE_YK_CHL
            case YUBIKEY_METHOD_CHL:
                kdata = alloc_safe_mem(YKCHL_RESPONSE_LENGTH);
                if (!kdata) {
                    tc_log(1, "Error allocating memory for chal/resp secret\n");
                    rv = ENOMEM; goto err;
                }
                kdata_sz = YKCHL_RESPONSE_LENGTH;

                if (tc_ykchl_hmac(yk.slot, pass, MAX_PASSSZ, kdata, errmsg) != 0) {
                    tc_log(1, "error: %s\n", errmsg);
                    rv = EIO; goto err;
                }
#ifdef TC_YK_DEBUG
                printf("TC_YK_DEBUG: +yubico-chl-secret: ");
                print_hex(kdata, YKCHL_RESPONSE_LENGTH);
#endif
                break;
#endif
#ifdef HAVE_YK_PIV
            case YUBIKEY_METHOD_PIV:
                if (!ykpin) {
                    ykpin = alloc_safe_mem(YKPIV_PIN_BUF_SIZE);
                    if (!ykpin) {
                        tc_log(1, "Error allocating memory for piv PIN\n");
                        rv = ENOMEM; goto err;
                    }
                    kdata = alloc_safe_mem(YKPIV_SECRET_LEN);
                    if (!kdata) {
                        tc_log(1, "Error allocating memory for piv secret\n");
                        rv = ENOMEM; goto err;
                    }
                    kdata_sz = YKPIV_SECRET_LEN;
                }

                if (tc_ykpiv_getpin(ykpin, errmsg) != 0) {
                    tc_log(1, "error: %s", errmsg);
                    rv = EIO; goto err;
                }

                memset(kdata, 0, YKPIV_SECRET_LEN);

                if (yk.secret_len == 0) {
                    if (tc_ykpiv_fetch_secret(yk.slot, ykpin, kdata, YKPIV_SECRET_LEN,
                        pass, MAX_PASSSZ, errmsg) != 0)
                    {
                        tc_log(1, "error: %s\n", errmsg);
                        rv = EIO; goto err;
                    }
                } else {
                    if (tc_ykpiv_fetch_secret(yk.slot, ykpin, kdata, YKPIV_SECRET_LEN,
                        yk.secret, MAX_PASSSZ, errmsg) != 0)
                    {
                        tc_log(1, "error: %s\n", errmsg);
                        rv = EIO; goto err;
                    }
                }

#ifdef TC_YK_DEBUG
                printf("TC_YK_DEBUG: yubico-piv-secret(len=%d): ", YKPIV_SECRET_LEN);
                print_hex(kdata, YKPIV_SECRET_LEN);
#endif
                break;
#endif // HAVE_YK_PIV
            case -1:
                tc_log(1, "Error: %s\n", errmsg);
                rv = ENOMEM; goto err;
                break;

        }
    }
#endif //HAVE_YUBIKEY

        kpool_idx = 0;
        crc = ~0U;

        if (!kdata) {
            kdata_sz = MAX_KFILE_SZ;
            if ((kdata = read_to_safe_mem(keyfiles[k], 0, &kdata_sz)) == NULL) {
                tc_log(1, "Error reading keyfile %s content\n",
                    keyfiles[k]);
                rv = EIO; goto err;
            }
        }

        for (i = 0; i < kdata_sz; i++) {
            crc = crc32_intermediate(crc, kdata[i]);

            kpool[kpool_idx++] += (unsigned char)(crc >> 24);
            kpool[kpool_idx++] += (unsigned char)(crc >> 16);
            kpool[kpool_idx++] += (unsigned char)(crc >> 8);
            kpool[kpool_idx++] += (unsigned char)(crc);

            /* Wrap around */
            if (kpool_idx == KPOOL_SZ)
                kpool_idx = 0;
        }

        free_safe_mem(kdata);
        kdata = NULL;

    }

#ifdef DEBUG
    printf("Applying kpool to passphrase\n");
#endif
    /* Apply keyfile pool to passphrase */
    for (i = 0; i < KPOOL_SZ; i++)
        pass[i] += kpool[i];

err:
#ifdef HAVE_YK_PIV
    free_safe_mem(ykpin);
#endif
    free_safe_mem(kpool);
    free_safe_mem(kdata);

    return rv;
}
