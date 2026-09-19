#!/usr/bin/python3
"""
ctypes bridge to native_fp2 batch kernels.

The CPU library is Orion-backed. When ENABLE_GPU is true and a CUDA device
is present, hot kernels and the early-round session use libnative_fp2_gpu.so.
Otherwise every call stays on the existing CPU library.
"""

from __future__ import annotations

import ctypes
import os
from typing import List, Optional, Sequence, Tuple, Union

from libTruePix.extfield import BASE_PRIME_61, Fp2, _raw

# Set False to force the existing CPU path even when a GPU is available.
ENABLE_GPU = True

_LIB = None
_GPU_LIB = None
AVAILABLE = False
GPU_ACTIVE = False

_U64 = ctypes.c_uint64
_I32 = ctypes.c_int
_SIZE = ctypes.c_size_t
_VOID_P = ctypes.c_void_p


def _bind_batch(lib) -> None:
    lib.native_fp2_fold.restype = None
    lib.native_fp2_fold.argtypes = [
        ctypes.POINTER(_U64), ctypes.POINTER(_U64), _SIZE,
        _U64, _U64,
        ctypes.POINTER(_U64), ctypes.POINTER(_U64),
    ]
    lib.native_fp2_expand.restype = None
    lib.native_fp2_expand.argtypes = [
        ctypes.POINTER(_U64), ctypes.POINTER(_U64), _SIZE, _SIZE,
        ctypes.POINTER(_U64), ctypes.POINTER(_U64),
    ]
    lib.native_fp2_sumcheck_early.restype = None
    lib.native_fp2_sumcheck_early.argtypes = [
        _I32,
        ctypes.POINTER(_I32), ctypes.POINTER(_I32), ctypes.POINTER(_I32),
        ctypes.POINTER(_U64), ctypes.POINTER(_U64),
        _I32, _I32,
        ctypes.POINTER(_U64), ctypes.POINTER(_U64),
        ctypes.POINTER(_U64), ctypes.POINTER(_U64),
        ctypes.POINTER(_U64), ctypes.POINTER(_U64),
        ctypes.POINTER(_U64), ctypes.POINTER(_U64),
        ctypes.POINTER(_U64), ctypes.POINTER(_U64),
        ctypes.POINTER(_U64), ctypes.POINTER(_U64),
        ctypes.POINTER(_U64),
    ]
    lib.native_fp2_compute_beta.restype = None
    lib.native_fp2_compute_beta.argtypes = [
        ctypes.POINTER(_U64), ctypes.POINTER(_U64), _I32,
        _U64, _U64,
        ctypes.POINTER(_U64), ctypes.POINTER(_U64),
    ]
    lib.native_fp2_mle_eval_base.restype = None
    lib.native_fp2_mle_eval_base.argtypes = [
        ctypes.POINTER(_U64),
        ctypes.POINTER(_U64), ctypes.POINTER(_U64), _I32,
        ctypes.POINTER(_U64), ctypes.POINTER(_U64),
    ]


def _bind_early(lib) -> None:
    lib.native_fp2_early_create.restype = _VOID_P
    lib.native_fp2_early_create.argtypes = [
        _I32,
        ctypes.POINTER(_I32), ctypes.POINTER(_I32), ctypes.POINTER(_I32),
        ctypes.POINTER(_U64), ctypes.POINTER(_U64),
        _I32, _I32,
        ctypes.POINTER(_U64), ctypes.POINTER(_U64),
        ctypes.POINTER(_U64), ctypes.POINTER(_U64),
    ]
    lib.native_fp2_early_claim.restype = ctypes.c_int
    lib.native_fp2_early_claim.argtypes = [_VOID_P, ctypes.POINTER(_U64)]
    lib.native_fp2_early_fold.restype = ctypes.c_int
    lib.native_fp2_early_fold.argtypes = [_VOID_P, _U64, _U64]
    lib.native_fp2_early_finish.restype = ctypes.c_int
    lib.native_fp2_early_finish.argtypes = [
        _VOID_P,
        ctypes.POINTER(_U64), ctypes.POINTER(_U64),
        ctypes.POINTER(_U64), ctypes.POINTER(_U64),
    ]
    lib.native_fp2_early_n_copies.restype = ctypes.c_int
    lib.native_fp2_early_n_copies.argtypes = [_VOID_P]
    lib.native_fp2_early_n_wires.restype = ctypes.c_int
    lib.native_fp2_early_n_wires.argtypes = [_VOID_P]
    lib.native_fp2_early_destroy.restype = None
    lib.native_fp2_early_destroy.argtypes = [_VOID_P]


def _load():
    global _LIB, _GPU_LIB, AVAILABLE, GPU_ACTIVE
    here = os.path.dirname(os.path.realpath(__file__))
    libdir = os.path.normpath(os.path.join(here, "..", "native_fp2", "lib"))
    cpu_path = os.path.join(libdir, "libnative_fp2.so")
    if not os.path.isfile(cpu_path):
        AVAILABLE = False
        return
    lib = ctypes.CDLL(cpu_path)
    lib.native_fp2_init.restype = ctypes.c_int
    lib.native_fp2_init.argtypes = []
    if lib.native_fp2_init() != 0:
        AVAILABLE = False
        return
    _bind_batch(lib)
    _LIB = lib
    AVAILABLE = True

    if not ENABLE_GPU:
        return
    gpu_path = os.path.join(libdir, "libnative_fp2_gpu.so")
    if not os.path.isfile(gpu_path):
        return
    try:
        gpu = ctypes.CDLL(gpu_path)
    except OSError:
        return
    gpu.native_fp2_init.restype = ctypes.c_int
    gpu.native_fp2_init.argtypes = []
    if not hasattr(gpu, "native_fp2_cuda_available") or not hasattr(gpu, "native_fp2_early_create"):
        return
    gpu.native_fp2_cuda_available.restype = ctypes.c_int
    gpu.native_fp2_cuda_available.argtypes = []
    if gpu.native_fp2_init() != 0 or not gpu.native_fp2_cuda_available():
        return
    _bind_batch(gpu)
    _bind_early(gpu)
    _GPU_LIB = gpu
    _LIB = gpu
    GPU_ACTIVE = True


_load()


def cuda_available() -> bool:
    return GPU_ACTIVE


def early_session_supported() -> bool:
    return GPU_ACTIVE and _GPU_LIB is not None


class Fp2Buf:
    """Contiguous Fp2 vector (real[], imag[]) with list-like access."""
    __slots__ = ("real", "imag", "n")

    def __init__(self, real, imag, n: Optional[int] = None):
        self.real = real
        self.imag = imag
        self.n = int(n if n is not None else len(real))

    def __len__(self) -> int:
        return self.n

    def __getitem__(self, idx):
        if isinstance(idx, slice):
            start, stop, step = idx.indices(self.n)
            if step != 1:
                return [_raw(self.real[i], self.imag[i], BASE_PRIME_61)
                        for i in range(start, stop, step)]
            n = stop - start
            if n <= 0:
                return Fp2Buf((_U64 * 0)(), (_U64 * 0)(), 0)
            rr = (_U64 * n)()
            ii = (_U64 * n)()
            ctypes.memmove(rr, ctypes.byref(self.real, start * 8), n * 8)
            ctypes.memmove(ii, ctypes.byref(self.imag, start * 8), n * 8)
            return Fp2Buf(rr, ii, n)
        return _raw(self.real[idx], self.imag[idx], BASE_PRIME_61)

    def __iter__(self):
        for i in range(self.n):
            yield _raw(self.real[i], self.imag[i], BASE_PRIME_61)

    def to_list(self) -> List[Fp2]:
        return list(self)


def _as_fp2_challenge(val) -> Fp2:
    if type(val) is Fp2:
        return val
    return _raw(int(val) % BASE_PRIME_61, 0, BASE_PRIME_61)


def _coords_from_values(values: Sequence) -> Tuple["ctypes.Array", "ctypes.Array", int]:
    if isinstance(values, Fp2Buf):
        return values.real, values.imag, values.n
    n = len(values)
    re = (_U64 * n)()
    im = (_U64 * n)()
    p = BASE_PRIME_61
    for i, v in enumerate(values):
        if type(v) is Fp2:
            re[i] = v.real
            im[i] = v.imag
        else:
            re[i] = int(v) % p
    return re, im, n


def _pack_wire_rows(rows: Sequence, n_wires: int, n_cols: int):
    p = BASE_PRIME_61
    re = (_U64 * (n_wires * n_cols))()
    im = (_U64 * (n_wires * n_cols))()
    for w in range(n_wires):
        row = rows[w]
        base = w * n_cols
        if isinstance(row, Fp2Buf):
            ctypes.memmove(ctypes.byref(re, base * 8), row.real, n_cols * 8)
            ctypes.memmove(ctypes.byref(im, base * 8), row.imag, n_cols * 8)
            continue
        for c in range(n_cols):
            v = row[c]
            if type(v) is Fp2:
                re[base + c] = v.real
                im[base + c] = v.imag
            else:
                re[base + c] = int(v) % p
    return re, im


def fold_values(values: Sequence, challenge, expand_ncopies: int = 1) -> Tuple[Fp2Buf, Fp2Buf]:
    """Fold pairs; returns (outputs, scratch) as Fp2Buf (no per-element Python objects)."""
    if not AVAILABLE:
        raise RuntimeError("native_fp2 library not available")
    chal = _as_fp2_challenge(challenge)
    in_r, in_i, n_in = _coords_from_values(values)
    n_out = n_in // 2
    out_r = (_U64 * n_out)()
    out_i = (_U64 * n_out)()
    _LIB.native_fp2_fold(
        in_r, in_i, _SIZE(n_out),
        _U64(chal.real), _U64(chal.imag),
        out_r, out_i,
    )
    scratch = Fp2Buf(out_r, out_i, n_out)
    if expand_ncopies <= 1:
        return scratch, scratch

    n_exp = n_out * expand_ncopies
    exp_r = (_U64 * n_exp)()
    exp_i = (_U64 * n_exp)()
    _LIB.native_fp2_expand(out_r, out_i, _SIZE(n_out), _SIZE(expand_ncopies), exp_r, exp_i)
    return Fp2Buf(exp_r, exp_i, n_exp), scratch


def sumcheck_early(
    gate_type: Sequence[int],
    in0: Sequence[int],
    in1: Sequence[int],
    z1: Sequence,
    n_copies: int,
    n_wires: int,
    values: Sequence,
    fact0: Sequence,
    fact1: Sequence,
    beta: Sequence,
    beta_f0: Sequence,
    beta_f1: Sequence,
) -> List[Fp2]:
    if not AVAILABLE:
        raise RuntimeError("native_fp2 library not available")
    n_gates = len(gate_type)
    half_n = n_copies >> 1
    p = BASE_PRIME_61

    gt = (_I32 * n_gates)(*gate_type)
    i0a = (_I32 * n_gates)(*in0)
    i1a = (_I32 * n_gates)(*in1)
    z1r = (_U64 * n_gates)()
    z1i = (_U64 * n_gates)()
    for g, z in enumerate(z1):
        if type(z) is Fp2:
            z1r[g] = z.real
            z1i[g] = z.imag
        else:
            z1r[g] = int(z) % p

    vr, vi = _pack_wire_rows(values, n_wires, n_copies)
    f0r, f0i = _pack_wire_rows(fact0, n_wires, half_n)
    f1r, f1i = _pack_wire_rows(fact1, n_wires, half_n)
    br, bi, _ = _coords_from_values(beta)
    bf0r, bf0i, _ = _coords_from_values(beta_f0)
    bf1r, bf1i, _ = _coords_from_values(beta_f1)

    out8 = (_U64 * 8)()
    _LIB.native_fp2_sumcheck_early(
        _I32(n_gates), gt, i0a, i1a, z1r, z1i,
        _I32(n_copies), _I32(n_wires),
        vr, vi, f0r, f0i, f1r, f1i,
        br, bi, bf0r, bf0i, bf1r, bf1i,
        out8,
    )
    return [
        _raw(out8[0], out8[1], p),
        _raw(out8[2], out8[3], p),
        _raw(out8[4], out8[5], p),
        _raw(out8[6], out8[7], p),
    ]


class EarlySession:
    """Resident early-round GKR session. Used only when a CUDA device is active."""

    __slots__ = ("_handle", "_n_wires")

    def __init__(self, handle, n_wires: int):
        self._handle = handle
        self._n_wires = int(n_wires)

    @property
    def n_copies(self) -> int:
        return int(_GPU_LIB.native_fp2_early_n_copies(self._handle))

    @property
    def n_wires(self) -> int:
        return self._n_wires

    def claim(self) -> List[Fp2]:
        out8 = (_U64 * 8)()
        if _GPU_LIB.native_fp2_early_claim(self._handle, out8) != 0:
            raise RuntimeError("native_fp2_early_claim failed")
        p = BASE_PRIME_61
        return [
            _raw(out8[0], out8[1], p),
            _raw(out8[2], out8[3], p),
            _raw(out8[4], out8[5], p),
            _raw(out8[6], out8[7], p),
        ]

    def fold(self, challenge) -> None:
        chal = _as_fp2_challenge(challenge)
        if _GPU_LIB.native_fp2_early_fold(self._handle, _U64(chal.real), _U64(chal.imag)) != 0:
            raise RuntimeError("native_fp2_early_fold failed")

    def finish(self) -> Tuple[List[Fp2], Fp2]:
        n = self._n_wires
        wr = (_U64 * n)()
        wi = (_U64 * n)()
        br = _U64()
        bi = _U64()
        if _GPU_LIB.native_fp2_early_finish(
            self._handle, wr, wi, ctypes.byref(br), ctypes.byref(bi)
        ) != 0:
            raise RuntimeError("native_fp2_early_finish failed")
        p = BASE_PRIME_61
        wires = [_raw(wr[i], wi[i], p) for i in range(n)]
        return wires, _raw(br.value, bi.value, p)

    def destroy(self) -> None:
        if self._handle:
            _GPU_LIB.native_fp2_early_destroy(self._handle)
            self._handle = None

    def __del__(self):
        try:
            self.destroy()
        except Exception:
            pass


def early_session_create(
    gate_type: Sequence[int],
    in0: Sequence[int],
    in1: Sequence[int],
    z1: Sequence,
    n_copies: int,
    n_wires: int,
    values: Sequence,
    beta: Sequence,
) -> EarlySession:
    if not early_session_supported():
        raise RuntimeError("native_fp2 early session API not available")
    n_gates = len(gate_type)
    p = BASE_PRIME_61
    gt = (_I32 * n_gates)(*gate_type)
    i0a = (_I32 * n_gates)(*in0)
    i1a = (_I32 * n_gates)(*in1)
    z1r = (_U64 * n_gates)()
    z1i = (_U64 * n_gates)()
    for g, z in enumerate(z1):
        if type(z) is Fp2:
            z1r[g] = z.real
            z1i[g] = z.imag
        else:
            z1r[g] = int(z) % p
    vr, vi = _pack_wire_rows(values, n_wires, n_copies)
    br, bi, _ = _coords_from_values(beta)
    handle = _GPU_LIB.native_fp2_early_create(
        _I32(n_gates), gt, i0a, i1a, z1r, z1i,
        _I32(n_copies), _I32(n_wires),
        vr, vi, br, bi,
    )
    if not handle:
        raise RuntimeError("native_fp2_early_create failed")
    return EarlySession(handle, n_wires)


def resolve_gate_type_idx(gate) -> int:
    from libTruePix import gateprover as gp
    tp = type(gate)
    if tp is gp.MuxGateProver:
        bit = gate.layer.circuit.muxbits[gate.muxbit]
        return 4 if bit else 3
    idx = getattr(gate, "gate_type_idx", None)
    if idx is not None:
        return int(idx)
    mapping = {
        gp.MulGateProver: 0,
        gp.AddGateProver: 1,
        gp.SubGateProver: 2,
        gp.OrGateProver: 5,
        gp.XorGateProver: 6,
        gp.NotGateProver: 7,
        gp.NandGateProver: 8,
        gp.NorGateProver: 9,
        gp.NxorGateProver: 10,
        gp.NaabGateProver: 11,
        gp.PassGateProver: 12,
    }
    return mapping.get(tp, 12)


def cache_gate_tables(gates) -> Tuple[List[int], List[int], List[int]]:
    return (
        [resolve_gate_type_idx(g) for g in gates],
        [g.in0 for g in gates],
        [g.in1 for g in gates],
    )


def compute_beta(z: Sequence, init=1) -> Fp2Buf:
    """Beta table over Fp2 challenges; returns Fp2Buf of length 2^len(z)."""
    if not AVAILABLE:
        raise RuntimeError("native_fp2 library not available")
    n = len(z)
    if n == 0:
        return Fp2Buf((_U64 * 0)(), (_U64 * 0)(), 0)
    zr, zi, _ = _coords_from_values(z)
    out_n = 1 << n
    out_r = (_U64 * out_n)()
    out_i = (_U64 * out_n)()
    if type(init) is Fp2:
        ir, ii = init.real, init.imag
    else:
        ir, ii = int(init) % BASE_PRIME_61, 0
    _LIB.native_fp2_compute_beta(zr, zi, _I32(n), _U64(ir), _U64(ii), out_r, out_i)
    return Fp2Buf(out_r, out_i, out_n)


def mle_eval_base(inputs: Sequence, z: Sequence) -> Fp2:
    """
    Evaluate MLE of base-field (or int) inputs at Fp2 point z.
    inputs are padded with zeros to length 2^len(z).
    """
    if not AVAILABLE:
        raise RuntimeError("native_fp2 library not available")
    import array as _array
    n_z = len(z)
    n = 1 << n_z
    p = BASE_PRIME_61
    lim = min(len(inputs), n)
    # Pack base-field ints into a contiguous uint64 buffer for the C kernel.
    if lim and type(inputs[0]) is int:
        # Truncate/pad without per-element Python mods when already in-range.
        a = _array.array("Q")
        if lim == len(inputs) and lim == n:
            try:
                a.fromlist(inputs if isinstance(inputs, list) else list(inputs))
            except (TypeError, OverflowError):
                a = _array.array("Q", (int(v) % p for v in inputs))
        else:
            a.extend(int(inputs[i]) % p for i in range(lim))
            if lim < n:
                a.extend([0] * (n - lim))
        buf = (_U64 * n).from_buffer(a)
    else:
        buf = (_U64 * n)()
        for i in range(lim):
            v = inputs[i]
            if type(v) is Fp2:
                if v.imag != 0:
                    raise TypeError("mle_eval_base expects base-field inputs")
                buf[i] = v.real
            else:
                buf[i] = int(v) % p
    zr, zi, _ = _coords_from_values(z)
    out_r = _U64()
    out_i = _U64()
    _LIB.native_fp2_mle_eval_base(buf, zr, zi, _I32(n_z), ctypes.byref(out_r), ctypes.byref(out_i))
    return _raw(out_r.value, out_i.value, p)
