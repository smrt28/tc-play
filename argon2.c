#include <argon2.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "safe_mem.h"
#include "config.h"
#include "argon2-hash.h"



static int argon_mem_alloc(uint8_t **memory, size_t bytes_to_allocate) {
    *memory = (uint8_t *)alloc_safe_mem(bytes_to_allocate);
    return 0;
}

static void argon_mem_free(uint8_t *memory, size_t bytes_to_allocate) {
    free_safe_mem(memory);
}

int argon2(const char *pass_, int passlen,
        const unsigned char *_salt, int saltlen,
        unsigned char *hash, size_t hash_len,
        int cost)
{
    uint32_t t_cost = 3;            // 1-pass computation
    uint32_t m_cost = 0;
    uint32_t parallelism = 1;       // number of threads and lanes
    unsigned char *pass = NULL;
    unsigned char *salt = NULL;
    int rv = -1, i;

    m_cost = (1 << cost);

    if (m_cost == 0) goto err;

    salt = alloc_safe_mem(saltlen);
    if (!salt) goto err;
    memcpy(salt, _salt, saltlen);

    pass = alloc_safe_mem(passlen);
    memcpy(pass, pass_, passlen);
    if (!pass) goto err;

    // low-level API
    argon2_context context = {
        hash,  /* output array, at least HASHLEN in size */
        hash_len, /* digest length */
        pass, /* password array */
        passlen, /* password length */
        salt,  /* salt array */
        saltlen, /* salt length */
        NULL, 0, /* optional secret data */
        NULL, 0, /* optional associated data */
        t_cost, m_cost, parallelism, parallelism,
        ARGON2_VERSION_13, /* algorithm version */
        argon_mem_alloc, argon_mem_free, /* custom memory allocation / deallocation functions */
        /* by default only internal memory is cleared (pwd is not wiped) */
        ARGON2_DEFAULT_FLAGS
    };

    if ((i = argon2i_ctx(&context)) != ARGON2_OK) {
        fprintf(stderr, "Error: %s\n", argon2_error_message(i));
        goto err;
    }

    rv = 0;
err:
    free_safe_mem(pass);
    free_safe_mem(salt);
    return rv;
}

