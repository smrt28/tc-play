#ifndef YUBICO_PIV_H
#define YUBICO_PIV_H


#define YKPIV_PIN_BUF_SIZE 10
#define YKPIV_SECRET_LEN 64

int tc_ykpiv_fetch_secret(int n, const char *pin,
        unsigned char *secret_out, int secret_out_len,
        const unsigned char * pass, size_t pass_len,
        char *errmsg);



int tc_ykpiv_getpin(char *pin, char *errmsg);

int tc_fetch_object(const char *pin, int id, unsigned char * secret, unsigned long *len, char *errmsg);

struct tc_ykpiv_protected_object_t {
    const char *name;
    int id;
};

const struct tc_ykpiv_protected_object_t * tc_ykpiv_get_protected_objects(void);

#endif
