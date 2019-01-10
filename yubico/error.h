#ifndef YUBICO_COMMON_H
#define YUBICO_COMMON_H

#include <stdio.h>
#include "yubico/tc-common.h"

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

#define CERROR(code, format, ...) \
    do { snprintf(errmsg, ERR_MESSAGE_LEN, format, ##__VA_ARGS__); \
        errmsg[ERR_MESSAGE_LEN - 1] = 0; \
        rv = code; \
        goto err; } while(0)


#define GERROR(format, ...) \
    do { snprintf(errmsg, ERR_MESSAGE_LEN, format, ##__VA_ARGS__); \
        errmsg[ERR_MESSAGE_LEN - 1] = 0; \
        rv = ERR_YK_GENERAL; \
        goto err; } while(0)


#endif
