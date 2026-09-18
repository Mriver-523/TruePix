#!/usr/bin/python3
"""
Quadratic extension field Fp2 = F_p[i] / (i^2 + 1) for p = 2^61 - 1.

Used for GKR challenges, VOLE MACs, and Orion opening points in
protocol mode truepix. Circuit wire values remain in the base field.

Performance model (mirrors Orion's prime_field::field_element):
- Base-field values stay native Python ints for as long as possible.
- int (base) x Fp2 is a *scalar* multiply: 2 base muls, never promoted
  to a full Karatsuba product.
- int (base) +/- Fp2 touches only the real coordinate: 1 base add/sub.
- Fp2 x Fp2 uses 3-mul Karatsuba.
- Construction via _raw skips redundant `% p` when inputs are already
  reduced (all internal arithmetic produces reduced coordinates).
"""

from __future__ import annotations

import secrets
from typing import Iterable, List, Sequence, Tuple, Union

# Mersenne prime used by Orion and by truepix circuit/base arithmetic.
BASE_PRIME_61 = (1 << 61) - 1

NumberLike = Union[int, "Fp2"]


class Fp2:
    __slots__ = ("real", "imag", "p")

    def __init__(self, real: int, imag: int, p: int = BASE_PRIME_61):
        self.real = real % p
        self.imag = imag % p
        self.p = p

    # ---- constructors -------------------------------------------------

    @classmethod
    def zero(cls, p: int = BASE_PRIME_61) -> "Fp2":
        return _raw(0, 0, p)

    @classmethod
    def one(cls, p: int = BASE_PRIME_61) -> "Fp2":
        return _raw(1, 0, p)

    @classmethod
    def from_base(cls, x: int, p: int = BASE_PRIME_61) -> "Fp2":
        return _raw(int(x) % p, 0, p)

    @classmethod
    def random(cls, p: int = BASE_PRIME_61, nonzero: bool = False) -> "Fp2":
        while True:
            real = secrets.randbelow(p)
            imag = secrets.randbelow(p)
            if not nonzero or real != 0 or imag != 0:
                return _raw(real, imag, p)

    # ---- inspection / serialization -----------------------------------

    def is_base(self) -> bool:
        return self.imag == 0

    def to_pair(self) -> Tuple[int, int]:
        return (self.real, self.imag)

    def serialize(self) -> List[int]:
        return [self.real, self.imag]

    @classmethod
    def deserialize(cls, data: Sequence[int], p: int = BASE_PRIME_61) -> "Fp2":
        if len(data) != 2:
            raise ValueError("Fp2.deserialize expects [real, imag]")
        return cls(data[0], data[1], p)

    # ---- pickling (required with __slots__) ----------------------------

    def __getstate__(self):
        return (self.real, self.imag, self.p)

    def __setstate__(self, state):
        self.real, self.imag, self.p = state

    # ---- comparisons ----------------------------------------------------

    def __eq__(self, other: object) -> bool:
        tp = type(other)
        if tp is Fp2:
            return self.real == other.real and self.imag == other.imag and self.p == other.p
        if tp is int or isinstance(other, int):
            return self.imag == 0 and self.real == (other % self.p)
        if isinstance(other, Fp2):
            return self.real == other.real and self.imag == other.imag and self.p == other.p
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.real, self.imag))

    # ---- arithmetic -----------------------------------------------------

    def __neg__(self) -> "Fp2":
        p = self.p
        return _raw((-self.real) % p, (-self.imag) % p, p)

    def __add__(self, other: NumberLike) -> "Fp2":
        p = self.p
        tp = type(other)
        if tp is Fp2:
            return _raw((self.real + other.real) % p, (self.imag + other.imag) % p, p)
        if tp is int or isinstance(other, int):
            # Base-field add: only the real coordinate moves.
            if other == 0:
                return self
            return _raw((self.real + other) % p, self.imag, p)
        if isinstance(other, Fp2):
            return _raw((self.real + other.real) % p, (self.imag + other.imag) % p, p)
        return NotImplemented

    def __radd__(self, other: NumberLike) -> "Fp2":
        return self.__add__(other)

    def __sub__(self, other: NumberLike) -> "Fp2":
        p = self.p
        tp = type(other)
        if tp is Fp2:
            return _raw((self.real - other.real) % p, (self.imag - other.imag) % p, p)
        if tp is int or isinstance(other, int):
            return _raw((self.real - other) % p, self.imag, p)
        if isinstance(other, Fp2):
            return _raw((self.real - other.real) % p, (self.imag - other.imag) % p, p)
        return NotImplemented

    def __rsub__(self, other: NumberLike) -> "Fp2":
        # other - self, other is a base int
        p = self.p
        return _raw((other - self.real) % p, (-self.imag) % p, p)

    def __mul__(self, other: NumberLike) -> "Fp2":
        p = self.p
        tp = type(other)
        if tp is Fp2:
            # Schoolbook (4 base muls) beats Karatsuba (3 muls) here: at
            # 61-bit width a CPython int multiply costs about the same as
            # an add, so Karatsuba's extra adds/subs are a net loss.
            a = self.real
            b = self.imag
            c = other.real
            d = other.imag
            return _raw((a * c - b * d) % p, (a * d + b * c) % p, p)
        if tp is int or isinstance(other, int):
            # Base-field scalar multiply: 2 base muls, stays "minimal".
            return _raw(self.real * other % p, self.imag * other % p, p)
        if isinstance(other, Fp2):
            a = self.real
            b = self.imag
            c = other.real
            d = other.imag
            return _raw((a * c - b * d) % p, (a * d + b * c) % p, p)
        return NotImplemented

    def __rmul__(self, other: NumberLike) -> "Fp2":
        return self.__mul__(other)

    def __truediv__(self, other: NumberLike) -> "Fp2":
        return self * _as_fp2(other, self.p).inverse()

    def __mod__(self, other: int) -> "Fp2":
        # Compatibility with legacy patterns like `x % Defs.prime`.
        # For Fp2 values this is a no-op when other == p.
        if other != self.p:
            raise ValueError("Fp2 % q is only defined for q == base prime")
        return self

    def inverse(self) -> "Fp2":
        # 1/(a+bi) = (a-bi)/(a^2+b^2)
        p = self.p
        denom = (self.real * self.real + self.imag * self.imag) % p
        if denom == 0:
            raise ZeroDivisionError("inverse of zero in Fp2")
        inv_den = pow(denom, p - 2, p)
        return _raw(self.real * inv_den % p, (-self.imag) * inv_den % p, p)

    def __repr__(self) -> str:
        return f"Fp2({self.real}, {self.imag})"


_FP2_NEW = Fp2.__new__


def _raw(real: int, imag: int, p: int) -> Fp2:
    """Construct from already-reduced coordinates, skipping `% p`."""
    v = _FP2_NEW(Fp2)
    v.real = real
    v.imag = imag
    v.p = p
    return v


def fold_val(in0: NumberLike, in1: NumberLike, val: NumberLike,
             p: int = BASE_PRIME_61) -> Fp2:
    """
    Fused sumcheck fold: in0 + val*(in1 - in0), where at least one of the
    three operands is Fp2. Doing this on raw ints avoids the 3 temporary
    Fp2 allocations and ~5 operator dispatches the expression form costs.
    """
    if type(in0) is Fp2:
        ar = in0.real
        ai = in0.imag
    else:
        ar = in0
        ai = 0
    if type(in1) is Fp2:
        br = in1.real
        bi = in1.imag
    else:
        br = in1
        bi = 0
    dr = br - ar
    di = bi - ai
    if type(val) is Fp2:
        vr = val.real
        vi = val.imag
        return _raw((ar + vr * dr - vi * di) % p, (ai + vr * di + vi * dr) % p, p)
    return _raw((ar + val * dr) % p, (ai + val * di) % p, p)


def _as_fp2(value: NumberLike, p: int = BASE_PRIME_61) -> Fp2:
    if isinstance(value, Fp2):
        if value.p != p:
            raise ValueError("Fp2 prime mismatch")
        return value
    if isinstance(value, int):
        return _raw(int(value) % p, 0, p)
    raise TypeError(f"Cannot convert {type(value)} to Fp2")


def embed_base_list(values: Iterable[int], p: int = BASE_PRIME_61) -> List[Fp2]:
    return [Fp2.from_base(v, p) for v in values]


def serialize_point(point: Sequence[Fp2]) -> List[List[int]]:
    return [elm.serialize() for elm in point]


def deserialize_point(data: Sequence[Sequence[int]], p: int = BASE_PRIME_61) -> List[Fp2]:
    return [Fp2.deserialize(pair, p) for pair in data]
