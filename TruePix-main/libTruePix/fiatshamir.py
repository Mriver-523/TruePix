#!/usr/bin/python3
#
# (C) 2017

import bz2
from collections import deque
import hashlib
import pickle
import struct
import array
import types
import sys

import libTruePix.util as util

class FiatShamir(object):
    # VERSION 4: decimal transcript (unused)
    # VERSION 5: may embed Fp2 challenges; still pickles Python objects
    VERSION = 4
    VERSION_FP2 = 5
    ndb = None
    rvstart = None
    rvend = None
    wDiv = None
    protocol = "truepix"

    def __init__(self, q, protocol="truepix"):
        self.q = q
        self.protocol = protocol
        self._bin_hash = True

        # compare to a multiple of q to minimize probability of throwing away values
        divr = 1
        maskbits = util.clog2(q)
        maskdiff = (2 ** maskbits - q) / (2 ** maskbits + 0.0)
        for d in range(2, 128):
            tq = d * q
            tbits = util.clog2(tq)
            tdiff = (2 ** tbits - tq) / (2 ** tbits + 0.0)

            if tbits > 512:
                break
            elif tdiff < maskdiff:
                divr = d
                maskbits = tbits
                maskdiff = tdiff

        nbits = maskbits
        self.mask = 2 ** maskbits - 1
        self.comp = divr * q

        self.rnum = 0
        self.io = deque()
        self.trans = deque()
        self.can_put = True

        if nbits <= 256:
            self.hash = hashlib.sha256()
        elif nbits <= 384:
            self.hash = hashlib.sha384()
        elif nbits <= 512:
            self.hash = hashlib.sha512()
        else:
            assert False, "FiatShamir cannot handle q longer than 512 bits!"

        self.hash.update(b"TruePix,")  # NOTE: translated from original Chinese comment.
        self.hash.update(str(protocol).encode("utf-8"))
        self.hash.update(b",")
        # Binary field-element encoding.
        self.hash.update(b"binhash1,")

    def hash_update(self, vals):
        if self._bin_hash:
            self._hash_update_bin(vals)
        else:
            self._hash_update_dec(vals)

    def _hash_update_dec(self, vals):
        from libTruePix.extfield import Fp2
        # Stream decimal tokens (legacy transcript encoding).
        buf = bytearray()
        extend = buf.extend
        append = buf.append
        comma = 44  # ','
        for elm in util.flatten_iter(vals):
            if type(elm) is Fp2:
                extend(str(elm.real).encode("ascii"))
                append(comma)
                extend(str(elm.imag).encode("ascii"))
                append(comma)
            elif isinstance(elm, str):
                extend(elm.encode("utf-8"))
                append(comma)
            else:
                assert isinstance(elm, (int, type(None)))
                extend(str(elm).encode("ascii"))
                append(comma)
        if buf:
            self.hash.update(buf)

    def _hash_update_bin(self, vals):
        """Binary FS absorb for truepix: much faster on large IO vectors."""
        from libTruePix.extfield import Fp2
        # Fast path: flat list of Python ints (circuit outputs / wire vectors).
        if isinstance(vals, list) and vals and type(vals[0]) is int:
            try:
                a = array.array("Q", vals)
            except (TypeError, OverflowError):
                a = None
            if a is not None:
                self.hash.update(b"\x01")
                self.hash.update(struct.pack("<I", len(a)))
                self.hash.update(a.tobytes())
                return

        buf = bytearray()
        extend = buf.extend
        pack = struct.pack
        for elm in util.flatten_iter(vals):
            if type(elm) is int:
                extend(b"\x02")
                extend(pack("<Q", elm & 0xFFFFFFFFFFFFFFFF))
            elif type(elm) is Fp2:
                extend(b"\x03")
                extend(pack("<QQ", elm.real & 0xFFFFFFFFFFFFFFFF, elm.imag & 0xFFFFFFFFFFFFFFFF))
            elif isinstance(elm, str):
                b = elm.encode("utf-8")
                extend(b"\x04")
                extend(pack("<I", len(b)))
                extend(b)
            elif elm is None:
                extend(b"\x05")
            else:
                raise TypeError("unsupported FS element: %r" % (type(elm),))
        if buf:
            self.hash.update(buf)

    def hash_append(self, elm):
        if self._bin_hash:
            self._hash_update_bin([elm])
        else:
            self.hash.update((str(elm) + ',').encode('utf-8'))

    def rand_scalar(self):
        ret = self.comp

        while ret >= self.comp:
            self.hash_append(self.rnum)
            self.rnum += 1
            ret = int(self.hash.hexdigest(), 16) & self.mask

        return ret % self.q

    def rand_ext(self, label="chal"):
        """Draw an Fp2 challenge from the transcript (truepix)."""
        from libTruePix.extfield import Fp2
        # Domain-separated draws for real/imag coordinates.
        self.hash_append("ext")
        self.hash_append(label)
        self.hash_append("real")
        real = self.rand_scalar()
        self.hash_append("ext")
        self.hash_append(label)
        self.hash_append("imag")
        imag = self.rand_scalar()
        return Fp2(real, imag, self.q)

    def put(self, vals, is_io=False):
        if not self.can_put:
            assert False, "Cannot put values into an input FS transcript"

        call_items = False
        if isinstance(vals, dict):
            call_items = True
        elif not isinstance(vals, list):
            vals = [vals]

        if is_io:
            self.io.append(vals)
        else:
            self.trans.append(vals)

        if call_items:
            self.hash_update(list(vals.items()))
        else:
            self.hash_update(vals)

    def take(self, take_io=False):
        if self.can_put:
            assert False, "Cannot take values from an output FS transcript"

        if take_io:
            vals = self.io.popleft()
        else:
            vals = self.trans.popleft()

        if isinstance(vals, dict):
            self.hash_update(list(vals.items()))
        else:
            self.hash_update(vals)

        return vals

    @classmethod
    def from_string(cls, string, protocol="truepix"):
        (q, iovals, tvals, ndb, rvstart, rvend, wDiv) = cls.unpack_proof(string)

        ret = cls(q, protocol=protocol)
        ret.can_put = False
        ret.io.extend(iovals)
        ret.trans.extend(tvals)
        ret.ndb = ndb
        ret.rvstart = rvstart
        ret.rvend = rvend
        ret.wDiv = wDiv

        return ret

    @classmethod
    def proof_size(cls, string):
        (_, _, tvals, _, _, _, _) = cls.unpack_proof(string)

        nelems = len(list(util.flatten_iter(tvals)))
        size = len(bz2.compress(pickle.dumps(tvals, -1))) 

        return (nelems, size)

    @classmethod
    def unpack_proof(cls, string):
        (q, iovals, tvals, ndb, rvstart, rvend, wDiv, version) = pickle.loads(string)
        assert version == cls.VERSION, "Version: expected %d, got %d" % (cls.VERSION, version)
        return (q, iovals, tvals, ndb, rvstart, rvend, wDiv)

    def to_string(self, full=True):
        if full:
            return pickle.dumps((self.q, list(self.io), list(self.trans), self.ndb, self.rvstart, self.rvend, self.wDiv, self.VERSION), -1)
        return pickle.dumps(list(self.trans), -1)
