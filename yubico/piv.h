#ifndef YUBICO_PIV_H
#define YUBICO_PIV_H

#define ERR_YK_INIT        -100
#define ERR_YK_WRONG_PIN   -101
#define ERR_YK_VERIFY      -102
#define ERR_YK_NOTSET      -103
#define ERR_YK_ARGS        -104
#define ERR_YK_INVALID     -105
#define ERR_YK_GENERAL     -106
#define ERR_YK_CRYPTO      -107
#define ERR_YK_ALLOC       -108
#define ERR_YK_INPUT       -109

#define YKPIV_PIN_MAX_SIZE 8
#define YKPIV_PIN_MIN_SIZE 6
#define YKPIV_PIN_BUF_SIZE (YKPIV_PIN_MAX_SIZE + 1)
#define YKPIV_SECRET_LEN 64

int tc_ykpiv_fetch_secret(int n, const char *pin,
        unsigned char *secret_out, int secret_out_len,
        const unsigned char * pass, size_t pass_len,
        char *errmsg);

int tc_ykpiv_getpin(char *pin);

#endif
