AM_CPPFLAGS = -I$(srcdir)/../circuit $(OpenSSL_CFLAGS)
AM_CXXFLAGS = $(GLOBAL_CXXFLAGS) $(OPT_CXXFLAGS)
AM_CXXFLAGS += -m64 -pedantic -pedantic-errors -std=c++14 -Werror -Wall -Wextra -Wshadow -Wpointer-arith -Wcast-qual -Wformat=2
#-Weffc++ --- not using because circuit's initializers aren't written in the correct style

lib_LTLIBRARIES = pylibpws.la

pylibpws_la_SOURCES = pylibpws.cc
pylibpws_la_LIBADD = ../circuit/libcircuit_impl.la -lgmp $(OpenSSL_LIBS)
pylibpws_la_LDFLAGS = -module -shared -export-symbols-regex pypws_
