#/usr/bin/python
#
# (C) 2018 Riad S. Wahby <rsw@cs.stanford.edu>
#
# cffi interface to the pws reader

import os.path as OP

import cffi
ffi = cffi.FFI()
ffi.cdef("""
    const char *pypws_get_error(void);
    const char *pypws_parse(bool optimize, char *filename, char *prime_str);
    void pypws_clear(void);
""")
pypwsffi = ffi.dlopen(OP.join(OP.dirname(OP.realpath(__file__)), 'lib', 'pylibpws.so'))

def _parse(opt, fname, prime):
    cret = pypwsffi.pypws_parse(opt, fname, str(prime))
    if cret == ffi.NULL:
        pypwsffi.pypws_clear()
        raise RuntimeError(ffi.string(pypwsffi.pypws_get_error()))

    ret = eval(ffi.string(cret)) # pylint: disable=eval-used
    pypwsffi.pypws_clear()
    return ret

def parse_pws(fname, prime):
    return _parse(True, fname, prime)

def parse_pws_unopt(fname, prime):
    return _parse(False, fname, prime)
