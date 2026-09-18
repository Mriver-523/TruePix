AM_CFLAGS = -I$(srcdir)/../miracl $(GLOBAL_CFLAGS) $(OPT_CFLAGS)

GLOBAL_LDADD = ../miracl/libmiracl.la

check_PROGRAMS = ecsgen

ecsgen_SOURCES = ecsgen.c
ecsgen_LDADD = $(GLOBAL_LDADD)

dist_check_SCRIPTS = ecsgen_driver.test

TESTS = ecsgen_driver.test
