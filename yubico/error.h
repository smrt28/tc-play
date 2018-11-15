#ifndef YUBICO_COMMON_H
#define YUBICO_COMMON_H

#include <stdio.h>
#include "yubico/tc-common.h"

#define CERROR(code, format, ...) \
    do { snprintf(errmsg, ERR_MESSAGE_LEN, format, ##__VA_ARGS__); \
        errmsg[ERR_MESSAGE_LEN - 1] = 0; \
        rv = code; \
        goto err; } while(0)

#endif
