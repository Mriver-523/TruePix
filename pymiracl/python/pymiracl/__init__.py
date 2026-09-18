#!/usr/bin/python
#
# (C) 2018 Riad S. Wahby <rsw@cs.stanford.edu>
#
# cffi interface to MIRACL
# TODO look at how numpypy gets bigints back and forth to C
#
# pylint: disable=unused-variable

from itertools import islice
import os.path as OP
import random

# set up FFI
import cffi
ffi = cffi.FFI()
ffi.cdef("""
    void pymr_clear(void);
    char **pymr_set_curve(char *filename, int nelms, bool check_points);
    char **pymr_pow_gh(char *varg, char *varh);
    char **pymr_pow_g(char *varg);
    char **pymr_pow_h(char *varh);
    char **pymr_maul(char **bval, char *xval);
    char **pymr_exp_mul(char **bmvals, char *xval);
    char **pymr_exp_powh(char **bval, char *xval, char *yval);
    char **pymr_exp(char **bval, char *xval);
    char **pymr_div(char **bcvals);
    char **pymr_mul(char **bcvals);
    char **pymr_sqr(char **bval);
    char **pymr_multiexp(char **blst, char **xlst, unsigned num);
    char **pymr_multimul(char **blst, unsigned lb);
    char **pymr_pow_gih(char **lst, unsigned lx, char *varh, unsigned nstart);
    char **pymr_pow_gi(char **lst, unsigned lx, unsigned nstart, int nskip);
    char **pymr_decompress(char *xval);
    char *pymr_compress(char **bval);
    char *pymr_get_error(void);
    int *pymr_get_sizes(void);
""")
mircffi = ffi.dlopen(OP.join(OP.dirname(OP.realpath(__file__)), 'lib', 'pymiracl.so'))

class MiraclEC(object):
    # pylint: disable=too-many-public-methods
    curve = 'm191'

    def __init__(self, curve=None, maxbases=-1, check_points=False, keepstrs=False):
        self.rand = random.SystemRandom()
        self.keepstrs = keepstrs

        self.curve = curve if curve is not None else self.curve
        ecsfile = self.ec_file_path(self.curve)
        (self.q, self.maxlen) = self.set_curve(ecsfile, maxbases, check_points)
        self.set_data_sizes()

        self.g = self.pow_g(1)
        self.h = self.pow_h(1)
        self.gh = self.pow_gh(1, 1)

    @staticmethod
    def ec_file_path(curve):
        return OP.join(OP.dirname(OP.realpath(__file__)), 'ecslib', '%s_multi.ecs'%curve)

    @staticmethod
    def get_curve_line(curve, num):
        with open(MiraclEC.ec_file_path(curve), 'r') as f:
            return [ f.readline() for _ in range(0, num) ][-1]

    @staticmethod
    def get_order(curve):
        return int(MiraclEC.get_curve_line(curve, 5), 16)

    @staticmethod
    def get_field(curve):
        return int(MiraclEC.get_curve_line(curve, 2), 16)

    @staticmethod
    def clear():
        mircffi.pymr_clear()

    def points_to_cstrs(self, points, length=None):
        if length is None:
            length = len(points)
        # allocate one giant output string
        outdata = ffi.new('char []', length * self.point_size)
        offsets = [None] * 2 * length
        for (idx, point) in enumerate(islice(points, length)):
            if isinstance(point[0], str):
                xstr = point[0]
                ystr = point[1]
            else:
                xstr = '%x'%point[0]
                ystr = '%x'%point[1]
            ioff = self.point_size * idx
            offsets[2*idx] = outdata + ioff
            offsets[2*idx+1] = outdata + ioff + self.scalar_size
            ffi.memmove(offsets[2*idx], xstr.encode('utf-8'), len(xstr))
            ffi.memmove(offsets[2*idx+1], ystr.encode('utf-8'), len(ystr))
        return (ffi.new('char *[]', offsets), outdata)

    def scalars_to_cstrs(self, scalars, length=None):
        if length is None:
            length = len(scalars)
        # allocate one giant output string
        outdata = ffi.new('char []', length * self.scalar_size)
        offsets = [None] * length
        for (idx, scalar) in enumerate(islice(scalars, length)):
            outstr = '%x'%scalar
            offsets[idx] = outdata + self.scalar_size * idx
            ffi.memmove(offsets[idx], outstr.encode('utf-8'), len(outstr))
        return (ffi.new('char *[]', offsets), outdata)

    def set_data_sizes(self):
        data_sizes = ffi.unpack(mircffi.pymr_get_sizes(), 3)
        # scalar_size has to fit either a struct big or a string encoding a data_sizes[0]-bit number
        self.scalar_size = max(2 + (data_sizes[0] + 3) // 4, data_sizes[1])
        # point_size has to fit either two scalar_sizes or a struct epoint
        self.point_size = max(2 * self.scalar_size, data_sizes[2])

    def return_point(self, cstrs, force=False):
        if cstrs == ffi.NULL:
            raise RuntimeError(ffi.string(mircffi.pymr_get_error()))

        if self.keepstrs and not force:
            return (ffi.string(cstrs[0]), ffi.string(cstrs[1]))
        return (int(ffi.string(cstrs[0]), 16), int(ffi.string(cstrs[1]), 16))

    def rand_scalar(self):
        return self.rand.randint(1, self.q - 1)

    def set_curve(self, ecsfile, max_bases, check_points):
        ecsfile_bytes = ecsfile.encode('utf-8') if isinstance(ecsfile, str) else ecsfile
        return self.return_point(mircffi.pymr_set_curve(ecsfile_bytes, max_bases, check_points), True)

    def compress(self, point):
        if point == (0, 0):
            return None
        else:
            (arg, refs) = self.points_to_cstrs((point,))
            ret = mircffi.pymr_compress(arg)
            if ret == ffi.NULL:
                raise RuntimeError(ffi.string(mircffi.pymr_get_error()))
            if self.keepstrs:
                return ffi.string(ret)
            return int(ffi.string(ret), 16)

    def decompress(self, point):
        if point is None:
            return (0, 0)
        point_str = '%x'%point
        return self.return_point(mircffi.pymr_decompress(point_str.encode('utf-8')))

    def pow_gh(self, valg, valh):
        valg_str = '%x'%valg
        valh_str = '%x'%valh
        return self.return_point(mircffi.pymr_pow_gh(valg_str.encode('utf-8'), valh_str.encode('utf-8')))

    def pow_g(self, valg):
        valg_str = '%x'%valg
        return self.return_point(mircffi.pymr_pow_g(valg_str.encode('utf-8')))

    def pow_h(self, valh):
        valh_str = '%x'%valh
        return self.return_point(mircffi.pymr_pow_h(valh_str.encode('utf-8')))

    def maul(self, bval, xval):
        (arg, refs) = self.points_to_cstrs((bval,))
        xval_str = '%x'%xval
        return self.return_point(mircffi.pymr_maul(arg, xval_str.encode('utf-8')))

    def exp_mul(self, bval, xval, mval):
        (arg, refs) = self.points_to_cstrs((bval, mval))
        xval_str = '%x'%xval
        return self.return_point(mircffi.pymr_exp_mul(arg, xval_str.encode('utf-8')))

    def exp_powh(self, bval, xval, yval):
        (arg, refs) = self.points_to_cstrs((bval,))
        xval_str = '%x'%xval
        yval_str = '%x'%yval
        return self.return_point(mircffi.pymr_exp_powh(arg, xval_str.encode('utf-8'), yval_str.encode('utf-8')))

    def exp(self, bval, xval):
        (arg, refs) = self.points_to_cstrs((bval,))
        xval_str = '%x'%xval
        return self.return_point(mircffi.pymr_exp(arg, xval_str.encode('utf-8')))

    def div(self, c1val, c2val):
        (arg, refs) = self.points_to_cstrs((c1val, c2val))
        return self.return_point(mircffi.pymr_div(arg))

    def mul(self, c1val, c2val):
        (arg, refs) = self.points_to_cstrs((c1val, c2val))
        return self.return_point(mircffi.pymr_mul(arg))

    def sqr(self, c1val):
        (arg, refs) = self.points_to_cstrs((c1val,))
        return self.return_point(mircffi.pymr_sqr(arg))

    def multiexp(self, bvals, xvals, length=None):
        if length is None:
            length = min(len(bvals), len(xvals))
        (arg, refs) = self.points_to_cstrs(bvals, length)
        (arg2, refs2) = self.scalars_to_cstrs(xvals, length)
        return self.return_point(mircffi.pymr_multiexp(arg, arg2, length))

    def multimul(self, bvals):
        (arg, refs) = self.points_to_cstrs(bvals)
        return self.return_point(mircffi.pymr_multimul(arg, len(bvals)))

    def pow_gih(self, lvalg, valh, gi, length=None):
        if length is None:
            length = len(lvalg)
        (arg, refs) = self.scalars_to_cstrs(lvalg, length)
        valh_str = '%x'%valh
        return self.return_point(mircffi.pymr_pow_gih(arg, length, valh_str.encode('utf-8'), gi))

    def pow_gi(self, lvalg, gi, skip=1, length=None):
        if length is None:
            length = len(lvalg)
        (arg, refs) = self.scalars_to_cstrs(lvalg, length)
        return self.return_point(mircffi.pymr_pow_gi(arg, length, gi, skip))

    def pow_gij(self, i, j, valx1, valx2):
        (arg, refs) = self.scalars_to_cstrs((valx1, valx2))
        return self.return_point(mircffi.pymr_pow_gi(arg, 2, min(i,j), abs(j-i)))
