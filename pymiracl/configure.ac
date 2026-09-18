#                                               -*- Autoconf -*-
# Process this file with ./autogen.sh to produce a configure script

AC_PREREQ([2.68])
AC_INIT([miracl], [0.01], [rsw@cs.nyu.edu])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_SRCDIR([src/miracl/mrcore.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

# Add C++ flags
#PICKY_CXXFLAGS="-Wall -Wpedantic -Wextra -Weffc++ -Werror"
#PICKIER_CXXFLAGS="-Werror -Wall -Wextra -Wshadow -Wpointer-arith -Wcast-qual -Wformat=2 -Weffc++"
GLOBAL_CXXFLAGS="-m64 -std=gnu99"
AC_SUBST([GLOBAL_CXXFLAGS])

AC_ARG_ENABLE([debug],
  [AS_HELP_STRING([--enable-debug], [Enable -Og -g flags])],
  [case "$enableval" in
     no)
       OPT_CFLAGS="-O2 -DNDEBUG"
       ;;
     '' | yes)
       OPT_CFLAGS="-Og -g"
       ;;
     *)
       AC_MSG_ERROR([Unknown argument '$enableval' to --enable-debug])
       ;;
   esac],
  [OPT_CFLAGS="-O2 -DNDEBUG"])
AC_SUBST(OPT_CFLAGS)

# don't let autoconf override our optimization flags
: ${CFLAGS=""}

# Checks for programs.
AC_PROG_CC
LT_INIT

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_CONFIG_FILES([Makefile src/Makefile src/miracl/Makefile src/pymiracl/Makefile src/tests/Makefile])

AC_OUTPUT
