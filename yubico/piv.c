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

static int init_and_verify(struct ykpiv_state **state,
        const char *pin, char *errmsg)
{
    int rv = 0, tries = 0;

    *state = NULL;

    if (ykpiv_init(state, YK_DEBUG) != YKPIV_OK)
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
        CERROR(ERR_YK_CRYPTO, "expand secret failed");

    ciphertext[0] &= 0x7f;

    if (ykpiv_decipher_data(state, ciphertext, YKPIV_ENCRYPTED_SECRET_LEN,
            plaintext, &len, YKPIV_ALGO_RSA2048, slot) != YKPIV_OK)
                CERROR(ERR_YK_CRYPTO, "Yubikey can't decrypt data");

    if (len != YKPIV_ENCRYPTED_SECRET_LEN) CERROR(ERR_YK_CRYPTO,
            "Wrong expected Yubikey object length");

    if (expand_secret(3, plaintext, len, secret_out, secret_out_len) != 0) {
        CERROR(ERR_YK_CRYPTO, "Can't expand secret");
    }

err:
    free_safe_mem(ciphertext);
    free_safe_mem(plaintext);
    return rv;
}
