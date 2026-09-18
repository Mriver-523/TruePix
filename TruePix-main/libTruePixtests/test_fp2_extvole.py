#!/usr/bin/python3
"""Unit tests for Fp2 and ExtVOLE (truepix foundations)."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from libTruePix.extfield import BASE_PRIME_61, Fp2
from libTruePix.ExtVOLEGen import ExtVOLEGenerator
from libTruePix.ExtVOLECommit import ExtVOLECommit


def test_fp2_algebra():
    a = Fp2.random()
    b = Fp2.random()
    c = Fp2.random()
    assert (a + b) + c == a + (b + c)
    assert a * (b + c) == a * b + a * c
    assert a * Fp2.one() == a
    if a != Fp2.zero():
        assert a * a.inverse() == Fp2.one()
    assert Fp2.from_base(5).is_base()
    print("test_fp2_algebra OK")


def test_ext_vole_roundtrip():
    gen = ExtVOLEGenerator(security_repetitions=1)
    gen.generate_deltas()
    gen.generate_vole_instances(16)
    with tempfile.TemporaryDirectory() as td:
        pf = os.path.join(td, "p.json")
        vf = os.path.join(td, "v.json")
        gen.save_to_files(pf, vf)

        prover = ExtVOLECommit(BASE_PRIME_61, security_repetitions=1)
        verifier = ExtVOLECommit(BASE_PRIME_61, security_repetitions=1)
        prover.load_from_file_prover(pf)
        verifier.load_from_file_verifier(vf)

        msg = Fp2(123, 456)
        tag, d = prover.commit(msg)
        p_m = verifier.change_commit(d)
        # MAC relation: P_M = M*Delta + V = tag + M*Delta when V=tag
        # check via value proof
        chal = Fp2(7, 9)
        z1, z2 = prover.pok_finish(msg, tag, chal)
        assert verifier.pok_check(z1, z2, chal, p_m)

        # product proof
        x1 = Fp2(3, 4)
        x2 = Fp2(5, 6)
        prod = x1 * x2
        t1, d1 = prover.commit(x1)
        t2, d2 = prover.commit(x2)
        t3, d3 = prover.commit(prod)
        p1 = verifier.change_commit(d1)
        p2 = verifier.change_commit(d2)
        p3 = verifier.change_commit(d3)
        avals = prover.prod_finish((x1, x2, prod), (t1, t2, t3))
        assert verifier.prod_check((p1, p2, p3), avals)
    print("test_ext_vole_roundtrip OK")


if __name__ == "__main__":
    test_fp2_algebra()
    test_ext_vole_roundtrip()
    print("all foundation tests passed")
