#include <string.h>

#include <ykpiv.h>
#include <gcrypt.h>

#include "yubico/piv.h"
#include "yubico/error.h"
#include "safe_mem.h"

#ifdef TC_YK_DEBUG
#define YK_DEBUG 1
#else
#define YK_DEBUG 0
#endif

#define KEY_LEN 24
#define YKPIV_ENCRYPTED_SECRET_LEN 256


static struct tc_ykpiv_protected_object_t secret_objects[] = {
    { "fingerprints", YKPIV_OBJ_FINGERPRINTS },
    { "facial", YKPIV_OBJ_FACIAL },
    { "printed", YKPIV_OBJ_PRINTED },
    { "iris", YKPIV_OBJ_IRIS },
    { 0, 0 }
};

const struct tc_ykpiv_protected_object_t * tc_ykpiv_get_protected_objects(void) {
    return secret_objects;
}

static void * _pfn_alloc(void *data, size_t size) {
    (void)data;
    return calloc_safe_mem(size);
}

static void _pfn_free(void *data, void *p) {
    (void)data;
    free_safe_mem(p);
}

static void * _pfn_realloc(void *data, void *p, size_t cb) {
    (void)data;
    return realloc_safe_mem(p, cb);
}

static int init_and_verify(struct ykpiv_state **state,
        const char *pin, char *errmsg)
{
    int rv = 0, tries = 0;
    int yrv;
    *state = NULL;

    ykpiv_allocator a;
    a.pfn_alloc = _pfn_alloc;
    a.pfn_free = _pfn_free;
    a.pfn_realloc = _pfn_realloc;

    // yrv = ykpiv_init(state, YK_DEBUG);
    yrv = ykpiv_init_with_allocator(state, YK_DEBUG, &a);
    if (yrv != YKPIV_OK)
        CERROR(ERR_YK_INIT, "Yubikey init failed");

    if (ykpiv_connect(*state, NULL) != YKPIV_OK)
        CERROR(ERR_YK_INIT, "Yubikey connection failed");

    if (pin) {
        switch (ykpiv_verify(*state, pin, &tries)) {
            case YKPIV_OK: break;
            case YKPIV_WRONG_PIN:
                CERROR(ERR_YK_WRONG_PIN,
                        "Wrong Yubikey pin! (%d tries remaining)", tries);
                break;
            default:
                CERROR(ERR_YK_VERIFY, "Yubikey verification failed");
                break;
        }
    }

    return 0;

err:
    if (*state) {
        ykpiv_done(*state);
        *state = 0;
    }
    return rv;
}

static int expand_secret(int iter, const unsigned char *secret, int secret_len, unsigned char *out, int out_len) {
    if (gcry_kdf_derive((const char *)secret, secret_len, GCRY_KDF_PBKDF2, GCRY_MD_BLAKE2B_512, "\0", 1, iter,
            out_len, (char *)out) != 0) return -1;
    return 0;
}

int  tc_ykpiv_fetch_secret(int slot, const char * pin,
        unsigned char *secret_out, int secret_out_len,
        const unsigned char * pass, size_t pass_len,
        char *errmsg)
{
    int rv = 0;
    unsigned char *ciphertext = NULL;
    unsigned char *plaintext = NULL;
    struct ykpiv_state *state = NULL;
    size_t len = YKPIV_ENCRYPTED_SECRET_LEN;

    rv = init_and_verify(&state, pin, errmsg);
    if (rv) goto err;

    plaintext = alloc_safe_mem(YKPIV_ENCRYPTED_SECRET_LEN);
    if (!plaintext) CERROR(ERR_YK_ALLOC, "Error allocating memory for secret plaintext");

    ciphertext = alloc_safe_mem(YKPIV_ENCRYPTED_SECRET_LEN);
    if (!ciphertext) CERROR(ERR_YK_ALLOC, "Error allocating memory for ciphertext");

    if (expand_secret(1000, pass, pass_len, ciphertext, YKPIV_ENCRYPTED_SECRET_LEN) != 0)
        CERROR(ERR_YK_CRYPTO, "Expand secret failed");

    ciphertext[0] &= 0x7f;

    if (ykpiv_decipher_data(state, ciphertext, YKPIV_ENCRYPTED_SECRET_LEN,
            plaintext, &len, YKPIV_ALGO_RSA2048, slot) != YKPIV_OK)
                CERROR(ERR_YK_CRYPTO, "Yubikey can't decrypt data");

    if (len != YKPIV_ENCRYPTED_SECRET_LEN) CERROR(ERR_YK_CRYPTO,
            "Wrong expected Yubikey object length");

    if (expand_secret(10, plaintext, len, secret_out, secret_out_len) != 0) {
        CERROR(ERR_YK_CRYPTO, "Expand secret failed");
    }

err:
    free_safe_mem(ciphertext);
    free_safe_mem(plaintext);
    if (state) ykpiv_done(state);
    return rv;
}


int tc_fetch_object(const char *pin, int id, unsigned char * secret, unsigned long *len, char *errmsg) {
    int rv = 0;
    struct ykpiv_state *state = NULL;

    rv = init_and_verify(&state, pin, errmsg);
    if (rv) goto err;

    if (ykpiv_authenticate(state, 0) != YKPIV_OK)
        CERROR(-1, "ykpiv_authenticate failed");

    if (ykpiv_fetch_object(state, id, secret, len) != YKPIV_OK)
        CERROR(ERR_YK_INPUT, "can't fetch object");

err:
    if (state) ykpiv_done(state);
    return rv;
}
