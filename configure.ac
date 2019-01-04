AC_PREREQ(2.61)
AC_INIT(tcplay, 1.00, ondrej.holecek@gmail.com)
AC_CONFIG_SRCDIR([main.c])
m4_ifdef([AM_SILENT_RULES],
  [AM_SILENT_RULES([yes])],
  [AC_SUBST([AM_DEFAULT_VERBOSITY], [1])])
AC_USE_SYSTEM_EXTENSIONS
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_MAINTAINER_MODE([enable])
LT_INIT

PKG_PROG_PKG_CONFIG
AC_PROG_CC
AC_PROG_CC_STDC
AC_LANG_WERROR

PKG_CHECK_MODULES([TCPLAY_DEPS],[ uuid, devmapper ])

AC_ARG_WITH(yubico-piv, AS_HELP_STRING([--with-yubico-piv], [with yubico piv support]), [
        PKG_CHECK_MODULES([YKPIV], [ ykpiv >= 1.6 ])
        AC_DEFINE([HAVE_YK_PIV], [1], [Define yubico piv])
], [])

AC_ARG_WITH(yubico-chl, AS_HELP_STRING([--with-yubico-chl], [with yubico challenge-response support]), [
        PKG_CHECK_MODULES([YKCHL], [ ykpers-1 >= 1.19.0 ])
        AC_DEFINE([HAVE_YK_CHL], [1], [Define yubico piv])
], [])

AC_ARG_WITH(argon2, AS_HELP_STRING([--with-argon2], [with argon2 support]), [
        PKG_CHECK_MODULES([ARGON2], [ libargon2 ])
        AC_DEFINE([HAVE_ARGON2], [1], [Define argon2])
], [])


AC_ARG_ENABLE([tc-debug],
    AS_HELP_STRING([--enable-tc-debug], [Enable debug logs]))

AC_ARG_ENABLE([tc-yubico-debug],
    AS_HELP_STRING([--enable-tc-yubico-debug], [Enable yubico debug logs]))

if [ test "x$with_yubico_piv" = xyes -o "x$with_yubico_chl" = xyes ]; then
    AC_DEFINE([HAVE_YUBIKEY], [1], [You have Yubikey])
    AM_CONDITIONAL([WITH_YUBICO], [ true ])
else
    AM_CONDITIONAL([WITH_YUBICO], [ false ])
fi


AM_CONDITIONAL([ENABLE_TC_YUBICO_DEBUG], [test "x$enable_tc_yubico_debug" = xyes])
AM_CONDITIONAL([ENABLE_TC_DEBUG], [test "x$enable_tc_debug" = xyes])
AM_CONDITIONAL([WITH_YUBICO_PIV], [test "x$with_yubico_piv" = xyes])
AM_CONDITIONAL([WITH_YUBICO_CHL], [test "x$with_yubico_chl" = xyes])
AM_CONDITIONAL([WITH_ARGON2], [test "x$with_argon2" = xyes])

AC_CHECK_LIB(gcrypt, gcry_free, [
    TCPLAY_DEPS_LIBS+=' -lgcrypt'
], [AC_MSG_ERROR([library 'grypt' is required])])

AC_CONFIG_HEADER(config.h)
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
