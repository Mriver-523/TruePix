AM_CFLAGS = -I$(srcdir)/../miracl $(GLOBAL_CFLAGS) $(OPT_CFLAGS)
AM_CFLAGS += -pedantic -pedantic-errors -Werror -Wall -Wextra -Wshadow -Wpointer-arith -Wcast-qual -Wformat=2 -Wstrict-prototypes -Wmissing-prototypes

lib_LTLIBRARIES = pymiracl.la

pymiracl_la_SOURCES = pymiracl.c pymiracl.h
pymiracl_la_LIBADD = ../miracl/libmiracl_impl.la
pymiracl_la_LDFLAGS = -module -shared -export-symbols-regex pymr_
