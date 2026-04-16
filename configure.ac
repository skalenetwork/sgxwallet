
AC_INIT([SGX GMP Test], 1.0, [john.p.mechalas@intel.com])

AC_CONFIG_MACRO_DIRS([m4])

# Automake options:
#  - foreign: relax GNU project file requirements (no need for NEWS/AUTHORS/ChangeLog, etc.)
#  - subdir-objects: place .o files in per-source subdirectories (avoids collisions + future automake changes).
#                    Avoids warnings because of setting source files from different directories.
AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_PROG_CC
AC_PROG_CXX
AC_PROG_CPP
AM_PROG_CC_C_O
AM_PROG_AR
AC_PROG_RANLIB

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
