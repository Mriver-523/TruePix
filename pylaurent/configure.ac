#                                               -*- Autoconf -*-
# Process this file with ./autogen.sh to produce a configure script

AC_PREREQ([2.68])
AC_INIT([pylaurent], [0.01], [rsw@cs.nyu.edu])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_SRCDIR([src/pylaurent.cc])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

# Add C++ flags
GLOBAL_CXXFLAGS="-m64 -std=c++11 -Wall -Werror -Wextra -Wno-unused-parameter -Wshadow -Wpointer-arith -Wcast-qual -Wformat=2 -O2"
AC_SUBST([GLOBAL_CXXFLAGS])

AC_ARG_ENABLE([debug],
  [AS_HELP_STRING([--enable-debug], [Enable -Og -g flags])],
  [case "$enableval" in
     no)
       OPT_CXXFLAGS="-O2 -DNDEBUG"
       ;;
     '' | yes)
       OPT_CXXFLAGS="-Og -g"
       ;;
     *)
       AC_MSG_ERROR([Unknown argument '$enableval' to --enable-debug])
       ;;
   esac],
  [OPT_CXXFLAGS="-O2"])
AC_SUBST(OPT_CXXFLAGS)

# don't let autoconf override our optimization flags
: ${CXXFLAGS=""}

# Checks for programs.
AC_PROG_CXX
LT_INIT

# Find the NTL Library
# this is borrowed from https://github.com/JohnCremona/eclib configure.ac
AC_ARG_WITH(ntl, [AS_HELP_STRING([--with-ntl=<path>], [prefix of NTL installation. e.g. /usr/local or /usr])], [], [])
case "$with_ntl" in
  ""|yes)
    NTL_LDFLAGS=""
    NTL_CFLAGS=""
    ;;
  no)
    AC_MSG_ERROR([Compiling without libntl impossible (but --without-ntl given)])
    ;;
  *)
    NTL_LDFLAGS="-L${with_ntl}/lib"
    NTL_CFLAGS="-I${with_ntl}/include"
    ;;
esac
AC_LANG_PUSH(C++)
CXXFLAGS_save=$CXXFLAGS
LDFLAGS_save=$LDFLAGS
CXXFLAGS="$CXXFLAGS $NTL_CFLAGS -std=c++11"
LDFLAGS="$LDFLAGS $NTL_LDFLAGS -lpthread -lgmp -lntl"
AC_CHECK_HEADER(NTL/ZZ.h, , [AC_MSG_ERROR([Could not find NTL, you might want to use --with-ntl=<path> to point to its location])])
AC_LINK_IFELSE([AC_LANG_PROGRAM([#include <NTL/mat_ZZ_p.h>], [NTL::Mat<NTL::ZZ> x{NTL::conv<NTL::Mat<NTL::ZZ>>("[[1 1 1] [2 2 2] [3 3 3]]")}])], , [AC_MSG_ERROR([Could not find NTL >= 10.x. Do you need --with-ntl=/path/to/ntl ?])])
AC_LANG_POP(C++)
CXXFLAGS=$CXXFLAGS_save
LDFLAGS=$LDFLAGS_save
NTL_LIBS="-lntl"
AC_SUBST(NTL_LIBS)
AC_SUBST(NTL_CFLAGS)
AC_SUBST(NTL_LDFLAGS)

# Check for libraries.
AC_CHECK_LIB(gmp, __gmpz_powm_sec, , [AC_MSG_ERROR([GnuMP >= 5 not found. You need libgmp-dev or equivalent.])])

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_CONFIG_FILES([Makefile src/Makefile])

AC_OUTPUT
