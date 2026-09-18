#!/usr/bin/python3
#
# Defs for Pederson Commitments
#
# pylint: disable=too-many-lines

from itertools import chain
from functools import reduce

from libTruePix.gateprover import GateFunctionsVC
from libTruePix.circuitverifier import VerifierIOMLExt
import libTruePix.util as util
from pymiracl import MiraclEC

class PedCommit(metaclass=libTruePix.parse_pws.FromPWS):
    # pylint: disable=too-many-public-methods

    def __init__(self, curve=None, rec=None):
        self.gops = MiraclEC(curve)

        if isinstance(rec, (list, tuple)):
            self.rec_p = rec[0]
            self.rec_q = rec[1]
            self.rec = True
        elif rec is not None:
            self.rec_p = rec
            self.rec_q = rec
            self.rec = True
        else:
            self.rec_p = None
            self.rec_q = None
            self.rec = False

    # NOTE: translated from original Chinese comment.

    def pok_init(self):
        (t1, t2) = [self.gops.rand_scalar() for _ in range(0, 2)]
        aval = self.gops.pow_gh(t1, t2)

        if self.rec:
            self.rec_q.did_rng(2)
            self.rec_p.did_mexp(2)

        return (aval, t1, t2)

    # NOTE: translated from original Chinese comment.

    def tV_eval(self, cvals, mlext_evals, mlx_z2):
        base_vals = []
        exp_vals = []
        for (idx, elm) in enumerate(mlext_evals):
            exp_vals.append((elm * mlx_z2) % self.gops.q)
            print("GateFunctionsVC[", idx, "]", GateFunctionsVC[idx](cvals[0], cvals[1], cvals[2], self.rec))
            base_vals.append(GateFunctionsVC[idx](self.gops, cvals[0], cvals[1], cvals[2], self.rec_p))
        tV_cval = self.gops.multiexp(base_vals, exp_vals)

        if self.rec:
            nops = len(mlext_evals)
            self.rec_q.did_mul(nops)
            self.rec_p.did_mexp(nops)

        return tV_cval

    # NOTE: translated from original Chinese comment.

class WitnessLogCommitShort(_WCBase):
    # NOTE: translated from original Chinese comment.

    def redc_cont_v(self, c, LRval):
        # NOTE: translated from original Chinese comment.
        Lval, Rval = LRval
        assert self.Pvals is not None
        assert self.bvals is None
        assert self.gvals is None

        # record c, Aval, and Zval
        self.cvals.append(c)
        self.Pvals.extend((Lval, Rval))

        return self.v2bits != len(self.cvals)

    # NOTE: translated from original Chinese comment.

    def fin_check(self, c, delta_beta, z1_z2):
        delta, beta = delta_beta
        z1val, z2val = z1_z2
        
        # compute inverses
        cprod = reduce(lambda x, y: (x * y) % self.gops.q, self.cvals)
        cprodinv = util.invert_modp(cprod, self.gops.q, self.com.rec_q)
        cinvs = [0] * len(self.cvals)
        for idx in range(0, len(self.cvals)):
            cvs = chain(self.cvals[:idx], self.cvals[idx+1:])
            cinvs[idx] = reduce(lambda x, y: (x * y) % self.gops.q, cvs, cprodinv)

        csqs = [(cval * cval) % self.gops.q for cval in self.cvals]
        cinvsqs = [(cval * cval) % self.gops.q for cval in cinvs]
        # compute powers for multiexps
        gpows = [cprodinv]
        for cval in csqs:
            new = [0] * 2 * len(gpows)
            for (idx, gpow) in enumerate(gpows):
                new[2*idx] = gpow
                new[2*idx+1] = (gpow * cval) % self.gops.q
            gpows = new

        # compute powers for P commitments
        bval = (VerifierIOMLExt(self.rvals, self.com.rec_q).compute(gpows) * self.r0val) % self.gops.q
        bc = (bval * c) % self.gops.q
        azpows = [bc] + [(bc * cval) % self.gops.q for cval in chain.from_iterable(zip(csqs, cinvsqs))]

        # now compute the check values themselves
        gval = self.gops.pow_gi(gpows, 0)
        lhs = self.gops.multiexp(self.Pvals + [beta, delta], azpows + [bval, 1])
        rhs = self.gops.multiexp([gval, self.gops.g, self.gops.h], [z1val, (z1val * bval) % self.gops.q, z2val])

        if self.com.rec:
            clen = len(self.cvals)
            self.com.rec_p.did_mexps([3, 2+len(self.Pvals), len(gpows)])
            self.com.rec_q.did_mul(len(gpows) + (clen+1)*(clen-1) + 4*clen + 2)

        return lhs == rhs

WitnessLogCommit = WitnessLogCommitShort
