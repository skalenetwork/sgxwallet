
AC_INIT([SGX GMP Test], 1.0, [john.p.mechalas@intel.com])

AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([foreign])

AC_PROG_CC
AC_PROG_CXX
AC_PROG_CPP
AM_PROG_CC_C_O

SGX_INIT()

gmpdir=${PWD}/gmp-build
tgmpdir=${PWD}/tgmp-build


AS_IF([test "$gmpdir" != ""], [
	AC_SUBST([GMP_CPPFLAGS], [-I$gmpdir/include])
	AC_SUBST([GMP_LDFLAGS], [-L$gmpdir/lib])
])

AS_IF([test "$tgmpdir" != ""], [
	AC_SUBST([TGMP_CPPFLAGS], [-I$tgmpdir/include])
	AC_SUBST([TGMP_LDFLAGS], [-L$tgmpdir/lib])
])

AC_CONFIG_FILES([Makefile secure_enclave/Makefile])

AC_OUTPUT()
