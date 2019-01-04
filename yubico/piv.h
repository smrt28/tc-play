#ifndef YUBICO_PIV_H
#define YUBICO_PIV_H


#define YKPIV_PIN_BUF_SIZE 10
#define YKPIV_SECRET_LEN 64

int tc_ykpiv_fetch_secret(int n, const char *pin,
        unsigned char *secret_out, int secret_out_len,
        const unsigned char * pass, size_t pass_len,
        char *errmsg);

int tc_ykpiv_getpin(char *pin, char *errmsg);

#endif
