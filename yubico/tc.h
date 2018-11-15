#ifndef YUBICO_TC_H
#define YUBICO_TC_H

#include "config.h"

#ifndef HAVE_YUBIKEY
#error "Yubikey support is disable, can't include tc-common.h!"
#endif


#include "yubico/tc-common.h"

#ifdef HAVE_YK_PIV
#include "yubico/piv.h"
#endif

#ifdef HAVE_YK_CHL
#include "yubico/chalresp.h"
#endif


#endif
