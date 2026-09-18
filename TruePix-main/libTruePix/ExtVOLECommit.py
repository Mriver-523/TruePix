#!/usr/bin/python3
"""
Extension-field VOLE commitment for protocol truepix.

Default security_repetitions=1 returns Fp2 scalars (drop-in shaped like legacy).
security_repetitions>=2 returns per-repetition lists.

Legacy VOLECommit.py is left unchanged.
"""

from __future__ import annotations

import json
from typing import List, Sequence, Union

from libTruePix.extfield import BASE_PRIME_61, Fp2, _as_fp2
from libTruePix.gateprover_vole import GateFunctionsVC


Fp2OrList = Union[Fp2, List[Fp2]]


class ExtVOLECommit(object):
    FIELD_ID = "fp2-mersenne61"
    PROTOCOL = "truepix"

    def __init__(self, base_prime=None, rec=None, fs=None, security_repetitions=1, field_size=None, delta=None):
        # Accept legacy positional style: ExtVOLECommit(Defs.prime, com_rec)
        if field_size is not None and base_prime is None:
            base_prime = field_size
        self.p = int(base_prime) if base_prime is not None else BASE_PRIME_61
        self.q = self.p  # compatibility with legacy asserts Defs.prime == self.com.q
        self.rec = rec
        self.fs = fs
        if security_repetitions is None:
            security_repetitions = 1
        self.security_repetitions = max(1, int(security_repetitions))

        self.deltas: List[Fp2] = []
        self.u_lists: List[List[Fp2]] = []
        self.v_lists: List[List[Fp2]] = []
        self.p_lists: List[List[Fp2]] = []

        self.numVOLE = 0
        self.VOLEindex = 0
        self.messages: List[Fp2] = []
        # unused legacy attr kept for interface compatibility
        self.delta = delta

    def _record_op(self, op_type, count=1):
        if self.rec is not None:
            getattr(self.rec, f"did_{op_type}")(count)

    def _pack(self, values: List[Fp2]) -> Fp2OrList:
        if self.security_repetitions == 1:
            return values[0]
        return values

    def _unpack(self, value) -> List[Fp2]:
        if isinstance(value, list):
            return [_as_fp2(v, self.p) for v in value]
        return [_as_fp2(value, self.p)] * self.security_repetitions

    def load_from_file_prover(self, filename: str):
        with open(filename, "r") as fh:
            data = json.load(fh)
        if data.get("protocol") != self.PROTOCOL or data.get("field") != self.FIELD_ID:
            raise ValueError("Not an ExtVOLE prover file for truepix")
        self.security_repetitions = int(data["security_repetitions"])
        try:
            from libTruePix.native_fp2_bridge import Fp2Buf, AVAILABLE as _nat
            import ctypes
            _U64 = ctypes.c_uint64
        except ImportError:
            _nat = False

        def _pack_streams(key):
            if not _nat:
                return [[Fp2.deserialize(pair, self.p) for pair in stream] for stream in data[key]]
            packed = []
            for stream in data[key]:
                n = len(stream)
                rr = (_U64 * n)()
                ii = (_U64 * n)()
                for j, pair in enumerate(stream):
                    rr[j] = int(pair[0])
                    ii[j] = int(pair[1])
                packed.append(Fp2Buf(rr, ii, n))
            return packed

        self.u_lists = _pack_streams("u")
        # Drop JSON stream ASAP to cut peak RSS before packing v.
        if isinstance(data, dict):
            data.pop("u", None)
        self.v_lists = _pack_streams("v")
        if isinstance(data, dict):
            data.pop("v", None)
        self.VOLEindex = len(self.u_lists[0]) if self.u_lists else 0
        self.numVOLE = 0
        self.messages = []
        del data
        return self.VOLEindex

    def load_from_file_verifier(self, filename: str):
        with open(filename, "r") as fh:
            data = json.load(fh)
        if data.get("protocol") != self.PROTOCOL or data.get("field") != self.FIELD_ID:
            raise ValueError("Not an ExtVOLE verifier file for truepix")
        self.security_repetitions = int(data["security_repetitions"])
        self.deltas = [Fp2.deserialize(pair, self.p) for pair in data["delta"]]
        # Pack VOLE MAC stream into contiguous buffers to cut peak object memory.
        try:
            from libTruePix.native_fp2_bridge import Fp2Buf, AVAILABLE as _nat
            import ctypes
            _U64 = ctypes.c_uint64
        except ImportError:
            _nat = False
        if _nat:
            packed = []
            for stream in data["p"]:
                n = len(stream)
                rr = (_U64 * n)()
                ii = (_U64 * n)()
                for j, pair in enumerate(stream):
                    rr[j] = int(pair[0])
                    ii[j] = int(pair[1])
                packed.append(Fp2Buf(rr, ii, n))
            self.p_lists = packed
        else:
            self.p_lists = [
                [Fp2.deserialize(pair, self.p) for pair in stream]
                for stream in data["p"]
            ]
        self.VOLEindex = len(self.p_lists[0]) if self.p_lists else 0
        self.numVOLE = 0
        self.messages = []
        del data
        return self.VOLEindex

    def _consume_index(self) -> int:
        if self.VOLEindex <= 0:
            raise IndexError("VOLE instance index out of range")
        idx = self.numVOLE
        self.numVOLE += 1
        self.VOLEindex -= 1
        return idx

    def used_vole_stats(self):
        """
        Return (count, bytes) for VOLE correlations consumed so far.

        count = numVOLE * security_repetitions (one correlation per repetition).
        Bytes are canonical encodings: each Fp2 element is 16 bytes (2×u64
        over Mersenne-61). Prover holds (u,v) per correlation; verifier holds p.
        """
        n_idx = int(self.numVOLE)
        reps = max(1, int(self.security_repetitions))
        count = n_idx * reps
        fp2_bytes = 16
        if self.u_lists:
            nbytes = count * 2 * fp2_bytes
        else:
            nbytes = count * 1 * fp2_bytes
        return count, nbytes

    def commit(self, m):
        msg = _as_fp2(m, self.p)
        idx = self._consume_index()
        tags = []
        ds = []
        for rep in range(self.security_repetitions):
            u = self.u_lists[rep][idx]
            v = self.v_lists[rep][idx]
            tags.append(v)
            ds.append(msg - u)
        # Do not retain committed messages: unused by subsequent checks and
        # would accumulate ~100k Fp2 objects on the prover hot path.
        self._record_op("rng")
        self._record_op("add", self.security_repetitions)
        return self._pack(tags), self._pack(ds)

    def change_commit(self, d_m):
        ds = self._unpack(d_m)
        idx = self._consume_index()
        out = []
        for rep in range(self.security_repetitions):
            out.append(self.p_lists[rep][idx] + ds[rep] * self.deltas[rep])
        return self._pack(out)

    def change_commit_sum(self, d_sum, n: int):
        """
        Legacy create_pok_vec puts a single summed correction d = sum_i (m_i - u_i).
        Reconstruct MAC(sum m_i) = sum_i p_i + d * Delta.
        """
        d_sum_u = self._unpack(d_sum)
        indices = [self._consume_index() for _ in range(n)]
        out = []
        for rep in range(self.security_repetitions):
            acc = Fp2.zero(self.p)
            for idx in indices:
                acc = acc + self.p_lists[rep][idx]
            acc = acc + d_sum_u[rep] * self.deltas[rep]
            out.append(acc)
        self._record_op("add", n * self.security_repetitions)
        self._record_op("mul", self.security_repetitions)
        return self._pack(out)

    def pok_finish(self, m, v_m, c):
        msg = _as_fp2(m, self.p)
        chal = _as_fp2(c, self.p)
        tags = self._unpack(v_m)
        z1 = msg * chal
        z2s = [tag * chal for tag in tags]
        self._record_op("mul", 1 + len(tags))
        return z1, self._pack(z2s)

    def pok_check(self, z1, z2, c, pval) -> bool:
        chal = _as_fp2(c, self.p)
        z1v = _as_fp2(z1, self.p)
        z2s = self._unpack(z2)
        pvals = self._unpack(pval)
        ok = True
        for rep in range(self.security_repetitions):
            lhs = z1v * self.deltas[rep] + z2s[rep]
            rhs = pvals[rep] * chal
            ok = ok and (lhs == rhs)
        self._record_op("mul", 2 * self.security_repetitions)
        self._record_op("add", self.security_repetitions)
        return ok

    def est_eq(self, v1, v2, c):
        chal = _as_fp2(c, self.p)
        t1 = self._unpack(v1)
        t2 = self._unpack(v2)
        out = [(t1[rep] - t2[rep]) * chal for rep in range(self.security_repetitions)]
        self._record_op("sub", self.security_repetitions)
        self._record_op("mul", self.security_repetitions)
        return self._pack(out)

    def est_eq_check(self, q1, q2, c, v_z) -> bool:
        chal = _as_fp2(c, self.p)
        a = self._unpack(q1)
        b = self._unpack(q2)
        z = self._unpack(v_z)
        ok = True
        for rep in range(self.security_repetitions):
            ok = ok and (((a[rep] - b[rep]) * chal) == z[rep])
        self._record_op("sub", self.security_repetitions)
        return ok

    def est_val(self, v_r, c):
        chal = _as_fp2(c, self.p)
        tags = self._unpack(v_r)
        out = [tag * chal for tag in tags]
        self._record_op("mul", len(out))
        return self._pack(out)

    def est_val_check(self, p_x, c, val, v_z) -> bool:
        chal = _as_fp2(c, self.p)
        msg = _as_fp2(val, self.p)
        pvals = self._unpack(p_x)
        zs = self._unpack(v_z)
        ok = True
        for rep in range(self.security_repetitions):
            rhs = (pvals[rep] - msg * self.deltas[rep]) * chal
            ok = ok and (zs[rep] == rhs)
        self._record_op("mul", 2 * self.security_repetitions)
        self._record_op("sub", self.security_repetitions)
        return ok

    def prod_finish(self, xvals, vval):
        x1, x2, prod = [_as_fp2(x, self.p) for x in xvals]
        v1 = self._unpack(vval[0])
        v2 = self._unpack(vval[1])
        v3 = self._unpack(vval[2])
        a1s = []
        a2s = []
        for rep in range(self.security_repetitions):
            a1s.append(v1[rep] * v2[rep])
            a2s.append(x1 * v2[rep] + x2 * v1[rep] - v3[rep])
        self._record_op("mul", 3 * self.security_repetitions)
        self._record_op("add", self.security_repetitions)
        self._record_op("sub", self.security_repetitions)
        return (self._pack(a1s), self._pack(a2s))

    def prod_check(self, pval, aval) -> bool:
        p1 = self._unpack(pval[0])
        p2 = self._unpack(pval[1])
        p3 = self._unpack(pval[2])
        a1 = self._unpack(aval[0])
        a2 = self._unpack(aval[1])
        ok = True
        for rep in range(self.security_repetitions):
            lhs = p1[rep] * p2[rep] - p3[rep] * self.deltas[rep]
            rhs = a1[rep] + a2[rep] * self.deltas[rep]
            ok = ok and (lhs == rhs)
        self._record_op("mul", 3 * self.security_repetitions)
        self._record_op("add", self.security_repetitions)
        self._record_op("sub", self.security_repetitions)
        return ok

    def multvector(self, base_vals, exp_vals):
        acc = Fp2.zero(self.p)
        for base, exp in zip(base_vals, exp_vals):
            acc = acc + _as_fp2(base, self.p) * _as_fp2(exp, self.p)
        return acc

    def tV_eval(self, cvals, mlext_evals, mlx_z2):
        c0 = self._unpack(cvals[0])
        c1 = self._unpack(cvals[1])
        c2 = self._unpack(cvals[2])
        mlx = _as_fp2(mlx_z2, self.p)
        outs = []
        for rep in range(self.security_repetitions):
            acc = Fp2.zero(self.p)
            for (idx, elm) in enumerate(mlext_evals):
                base = GateFunctionsVC[idx](c0[rep], c1[rep], c2[rep], self.rec)
                acc = acc + _as_fp2(base, self.p) * (_as_fp2(elm, self.p) * mlx)
            outs.append(acc)
        if self.rec:
            nops = len(mlext_evals)
            self.rec.did_mul(nops)
            self.rec.did_add(nops)
        return self._pack(outs)
