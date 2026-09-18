AM_CXXFLAGS = $(GLOBAL_CXXFLAGS) $(OPT_CXXFLAGS) $(NTL_CFLAGS)

lib_LTLIBRARIES = pylaurent.la

pylaurent_la_SOURCES = pylaurent.cc
pylaurent_la_LDFLAGS = -module -shared $(NTL_LDFLAGS)
pylaurent_la_LIBADD = $(NTL_LIBS)
##
# INCLPATHS := -I$(HOME)/toolchains/include
# LIBPATHS := -Wl,-rpath,$(HOME)/toolchains/lib -L$(HOME)/toolchains/lib
# LIBS := -lpthread -lgmp -lntl
# CXXOPTS := -m64 -std=c++14 -Wall -Werror -Wextra -Wno-unused-parameter -Wshadow -Wpointer-arith -Wcast-qual -Wformat=2 -O2
# SHARED := -fPIC -shared
# 
# all: pylaurent.so
# 
# pylaurent.so: pylaurent.cc
# 	$(CXX) $(INCLPATHS) $(CXXOPTS) $(SHARED) -o $@ $< $(LIBPATHS) $(LIBS)
# 
# .PHONY: clean
# clean:
# 	@rm -f pylaurent.so
