AC_INIT([cryptotest], [0.1], [clabbe.montjoie@gmail.com])

AM_INIT_AUTOMAKE([-Wall foreign])

AC_PREREQ

AC_PROG_CC
AC_FUNC_MALLOC

AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

AC_CHECK_FUNCS([gettimeofday])
AC_CHECK_FUNCS([socket])
AC_CHECK_FUNCS([strerror])
AC_CHECK_FUNCS([strtol])
AC_CHECK_FUNCS([strtoul])
AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([sys/time.h])

AC_CHECK_LIB(crypto, EVP_DigestUpdate)

WANT_AF_ALG=yes
COMPILE_AF_ALG=no
case "${WANT_AF_ALG}" in
	yes)
	AC_CHECK_HEADERS("linux/if_alg.h",
		[COMPILE_AF_ALG=true])
	;;
	*)
	[echo "AF_ALG disabled"]
	;;
esac
AM_CONDITIONAL([COMPILE_AF_ALG], [test x$COMPILE_AF_ALG = xtrue])

WANT_CRYPTODEV=yes
COMPILE_CRYPTODEV=no
case "${WANT_CRYPTODEV}" in
	yes)
	AC_CHECK_HEADERS("crypto/cryptodev.h",
		[COMPILE_CRYPTODEV=true])
	;;
	*)
	[echo "cryptodev disabled"]
	;;
esac
AM_CONDITIONAL([COMPILE_CRYPTODEV], [test x$COMPILE_CRYPTODEV = xtrue])
case "${COMPILE_CRYPTODEV}" in
	true)
		[echo "cryptodev support is enabled"]
	;;
	*)
		[echo "cryptodev support cannot be enabled"]
	;;
esac

AC_CONFIG_FILES([
 Makefile
 af_alg/Makefile
 cryptodev/Makefile
])
AC_OUTPUT

