#!/usr/bin/python3
#
# Modification note: Replaced Pedersen commitment with VOLE commitment for non-interactive zero-knowledge proof implementation

from itertools import chain
from functools import reduce
import subprocess
import time  # Added time module
import os

import libTruePix.fiatshamir as fs
import libTruePix.parse_pws
import libTruePix.util as util
from libTruePix.defs import Defs
from libTruePix.circuitverifier import CircuitVerifier, VerifierIOMLExt
from libTruePix.ExtVOLECommit import ExtVOLECommit
from libTruePix.extfield import Fp2
from libTruePix.fp2_link import PendingInputClaim, serialize_point
from libTruePix.gateprover_vole import GateFunctionsPC

class CircuitProverNIZK(CircuitVerifier, metaclass=libTruePix.parse_pws.FromPWS):
    cat_label = "prv_nizk"
    commit_type = ExtVOLECommit

    def __init__(self, nCopies, nInputs, in0vv, in1vv, typvv, muxvv=None):
        # Initialize VOLE commitment object
        if Defs.track_fArith:
            fArith = Defs.fArith()
            self.com_p_a = fArith.new_cat("%s_com_p_%d" % (self.cat_label, hash(self)))
            self.com_q_a = fArith.new_cat("%s_com_q_%d" % (self.cat_label, hash(self)))
            com_rec = (self.com_p_a, self.com_q_a)
        else:
            self.com_p_a = None
            self.com_q_a = None
            com_rec = None

        # ExtVOLE commitment over Fp2
        self.commit_type = ExtVOLECommit
        self.com = ExtVOLECommit(
            Defs.prime,
            com_rec,
            security_repetitions=Defs.vole_security_repetitions,
        )
        self.fs = fs.FiatShamir(Defs.prime, protocol=Defs.PROTOCOL_ID)
        self.nondet_gen = lambda inputs, _: inputs
        self.v_elem=[]
        self.p_elem=[]
        self.out_elem=[]
        self.final_input_point = None
        self.final_input_tag = None
        
        # Call parent class initialization
        super().__init__(nCopies, nInputs, in0vv, in1vv, typvv, muxvv)

    def _challenge(self, label="chal"):
        """Sumcheck / layer challenges drawn in Fp2."""
        return self.fs.rand_ext(label)

    def create_pok(self, outs):
        """Generate Proof of Knowledge (PoK) - VOLE version"""
        rvals = []
        for val in outs:
            # VOLE commitment generation (returns v_m)
            (v_m, d_m) = self.com.commit(val)
            rvals.append(v_m)  # Save commitment value for subsequent verification
        
            # Initialize PoK (returns t1)
            #t1 = self.com.pok_init()
        
            # Put commitment value and initial value into transcript
            self.fs.put(d_m)

            # Generate challenge and complete PoK
            #chal = self.fs.rand_scalar()  # legacy
            chal = self._challenge("pok")
            (z1, z2) = self.com.pok_finish(val, v_m, chal)
            self.fs.put((z1, z2))

        if Defs.track_fArith:
            self.com_q_a.did_rng(len(outs))
            
        return rvals

    def create_pok_vec(self, outs):
        """Generate Proof of Knowledge (PoK) - VOLE version"""
        rvals = []
        dvals = []
        for val in outs:
            # VOLE commitment generation (returns v_m)
            (v_m, d_m) = self.com.commit(val)
            rvals.append(v_m)  # Save commitment value for subsequent verification
            dvals.append(d_m)        
            # Initialize PoK (returns t1)
            #t1 = self.com.pok_init

        vals=sum(outs)
        v_ms=sum(rvals)
        # Put commitment value and initial value into transcript
        d_ms=sum(dvals)
        self.fs.put(d_ms)
        # Generate challenge and complete PoK
        #chal = self.fs.rand_scalar()  # legacy
        chal = self._challenge("pok-vec")
        (z1, z2) = self.com.pok_finish(vals, v_ms, chal)
        self.fs.put((z1, z2))

        if Defs.track_fArith:
            self.com_q_a.did_rng(len(outs))
            
        return rvals

    def create_pok_temp(self, outs):
        """Generate Proof of Knowledge (PoK) - VOLE version"""
        rvals = []
        for val in outs:
            # VOLE commitment generation (returns v_m)
            (v_m, d_m) = self.com.commit(val)
            rvals.append(v_m)  # Save commitment value for subsequent verification
            self.fs.put(d_m)
            if len(self.v_elem)<len(outs):
                self.v_elem.append(0)
                self.out_elem.append(0)
            # Initialize PoK (returns t1)
            #t1 = self.com.pok_init

        for num in range(len(rvals)):
            self.v_elem[num]+=rvals[num]
            self.out_elem[num]+=outs[num]

        if Defs.track_fArith:
            self.com_q_a.did_rng(len(outs))
            
        return rvals

    def create_pok_final(self):
        """Generate Proof of Knowledge (PoK) - VOLE version"""
        # Put commitment value and initial value into transcript
        # Generate challenge and complete PoK
        out_sum=sum(self.out_elem)
        v_sum=sum(self.v_elem)
        #chal = self.fs.rand_scalar()  # legacy
        chal = self._challenge("pok-final")
        (z1, z2) = self.com.pok_finish(out_sum, v_sum, chal)
        self.fs.put((z1, z2))

        if Defs.track_fArith:
            self.com_q_a.did_rng(len(outs))

    def create_prod_pok(self, outs):
        """Generate product relation proof - VOLE version"""
        # Calculate product value
        prod = (outs[0] * outs[1]) % Defs.prime
    
        # Generate VOLE commitments for three values and correction values to be transmitted to verifier
        v1, d1 = self.com.commit(outs[0])
        v2, d2 = self.com.commit(outs[1]) 
        v3, d3 = self.com.commit(prod)
        rvals = (v1, v2, v3)  # Use commitments as input
        dvals = (d1, d2, d3)  # Use commitments as input

        # Put commitment values into transcript
        self.fs.put(dvals)

        # Generate challenge and complete proof
        #chal = self.fs.rand_scalar()
        xvals = (outs[0], outs[1], prod)
        avals = self.com.prod_finish(xvals, rvals)
        self.fs.put(avals)

        if Defs.track_fArith:
            self.com_q_a.did_rng()

        return rvals

    def create_final_prod_pok(self, outs): 
        """Generate final product proof - VOLE version"""
        # Generate commitment for first value
        v1, d1 = self.com.commit(outs[0])
        # Calculate sum value and its product
        sval = sum(outs) % Defs.prime
        prod = (outs[0] * sval) % Defs.prime
        # Generate product commitment
        v3, d3 = self.com.commit(prod)
        self.fs.put((d1,d3))

        # Individual corrections for outs[1:] so verifier can horner the same
        # coefficient vector; still one aggregated PoK on their sum.
        # Legacy: vvals = [v1] + self.create_pok_vec(outs[1:])
        vvals_rest = []
        dvals_rest = []
        for val in outs[1:]:
            (v_m, d_m) = self.com.commit(val)
            vvals_rest.append(v_m)
            dvals_rest.append(d_m)
            self.fs.put(d_m)
        rest_sum = sum(outs[1:]) % Defs.prime
        rest_v = sum(vvals_rest) % Defs.prime
        chal = self._challenge("pok-vec")
        (z1, z2) = self.com.pok_finish(rest_sum, rest_v, chal)
        self.fs.put((z1, z2))
        if Defs.track_fArith:
            self.com_q_a.did_rng(len(outs) - 1)

        vvals = [v1] + vvals_rest
        pr_vvals = (v1, sum(vvals) % Defs.prime, v3)

        # Generate challenge and complete proof
        #chal = self.fs.rand_scalar()
        xvals = (outs[0], sval, prod)
        avals = self.com.prod_finish(xvals, pr_vvals)
        self.fs.put(avals)

        if Defs.track_fArith:
            self.com_q_a.did_add(len(outs) - 1)
            self.com_q_a.did_mul()
            self.com_q_a.did_rng()

        return (vvals, pr_vvals)

    def create_eq_proof(self, v1val, v2val):
        """Generate equality proof - VOLE version"""
        #chal = self.fs.rand_scalar()  # legacy
        chal = self._challenge("eq")

        if v1val is None:
            v_z = self.com.est_val(v2val, chal)
        else:
            v_z = self.com.est_eq(v1val, v2val, chal)

        if Defs.track_fArith:
            self.com_q_a.did_rng()

        self.fs.put(v_z)

    def create_input_value_proof(self, tag, value):
        """Prove authenticated tag opens to public value (Orion opening)."""
        chal = self._challenge("input-val")
        v_z = self.com.est_val(tag, chal)
        if Defs.track_fArith:
            self.com_q_a.did_rng()
        self.fs.put(v_z)

    # The following methods are the same as the original version and do not involve commitment mechanism
    def set_nondet_range(self, ndb):
        assert ndb >= 0
        assert ndb < self.nInBits
        self.fs.ndb = ndb

    def set_rdl(self, rdl, nRDLInputs):
        self.nInputs = nRDLInputs
        self.nInBits = util.clog2(nRDLInputs)
        assert len(rdl) == self.nCopies
        self.rdl = rdl

    def set_nondet_gen(self, fn):
        self.nondet_gen = fn

    def set_rval_range(self, rvstart, rvend):
        assert rvstart > 0 and rvend > 0
        assert rvstart < self.nInputs and rvend < self.nInputs
        assert rvend >= rvstart
        self.fs.rvstart = rvstart
        self.fs.rvend = rvend

    def run(self, inputs, muxbits=None):
        """Main proof generation function"""
        self.build_prover()
        self.prover_fresh = False

        # Verify prime field setting is correct
        assert Defs.prime == self.com.q

        # 0. Execute computation
        assert self.prover is not None
        
        pid = os.getpid()
        self.fs.put(pid)
        if Defs.is_ext_field():
            prover_file = f"vole_ext_prover_{pid}.json"
        else:
            prover_file=f"vole_prover_{pid}.json"
        self.com.load_from_file_prover(prover_file)

        # Add time measurement - circuit execution part starts
        circuit_start_time = time.time()
        
        # Process input to ensure correctness
        inputs = self.nondet_gen(inputs, muxbits)

        # Record muxbits
        if muxbits is not None:
            self.prover.set_muxbits(muxbits)
        self.fs.put(muxbits, True)

        # Process input records
        invals = []
        invals_nd = []
        for ins in inputs:
            ins = list(ins) + [0] * (2**self.nInBits - len(ins))
            if self.fs.ndb is not None:
                loIdx = (2 ** self.nInBits) - (2 ** (self.nInBits - self.fs.ndb))
                if self.fs.rvend is not None and self.fs.rvstart is not None:
                    ins[self.fs.rvstart:self.fs.rvend+1] = [0] * (self.fs.rvend - self.fs.rvstart + 1)
                ins_nd = ins[loIdx:]
                ins[loIdx:] = [0] * (2 ** (self.nInBits - self.fs.ndb))
                invals_nd.append(ins_nd)
            invals.extend(ins)

        # Extend to nCopies using RDL
        if self.rdl is None:
            assert util.clog2(len(invals)) == self.nInBits + self.nCopyBits
            invals += [0] * (2 ** (self.nInBits + self.nCopyBits) - len(invals))
        # Legacy: put private inputs into the transcript.
        # truepix: keep inputs private; only record length metadata.
        if Defs.is_ext_field():
            # self.fs.put(invals, True)  # legacy private-input leak disabled
            self._private_invals = invals
            self.fs.put(["private_input_omitted", len(invals)], True)
        else:
            self.fs.put(invals, True)

        # Generate commitments for random values needed by verifier
        nd_rvals = []

        # Values needed for V
        if self.fs.rvstart is not None and self.fs.rvend is not None:
            r_values = [self.fs.rand_scalar() for _ in range(self.fs.rvstart, self.fs.rvend + 1)]
            if self.rdl is None:
                assert len(inputs) == self.nCopies
                for inp in inputs:
                    inp[self.fs.rvstart:self.fs.rvend+1] = r_values
            else:
                assert len(inputs) == 1
                inputs[0][self.fs.rvstart:self.fs.rvend+1] = r_values

        if self.rdl is None:
            self.prover.set_inputs(inputs)
        else:
            assert len(inputs) == 1
            rdl_inputs = []
            nd_rvals_new = []
            for r_ents in self.rdl:
                rdl_inputs.append([inputs[0][r_ent] for r_ent in r_ents])
                nd_rvals_new.extend(nd_rvals[r_ent] for r_ent in r_ents)
                nd_rvals_new.extend(0 for _ in range((2**self.nCktBits) - len(r_ents)))
            self.prover.set_inputs(rdl_inputs)
            nd_rvals = nd_rvals_new
            assert len(nd_rvals) == len(self.rdl) * 2**self.nCktBits

        # Process output
        outvals = util.flatten(self.prover.ckt_outputs)
        nOutBits = util.clog2(len(self.in0vv[-1]))
        assert util.clog2(len(outvals)) == nOutBits + self.nCopyBits
        outvals += [0] * (2 ** (nOutBits + self.nCopyBits) - len(outvals))
        self.fs.put(outvals, True)

        # truepix keeps the private input out of the transcript, so the
        # Orion commitment to that input has to be absorbed here instead --
        # otherwise every challenge below would be independent of the input and
        # the prover could choose its input after seeing them.
        if Defs.is_ext_field():
            from libTruePix.fp2_link import commit_binding, read_commit_manifest
            self.fs.put(commit_binding(read_commit_manifest()))

        # Add time measurement - circuit execution part ends
        circuit_end_time = time.time()
        circuit_time = circuit_end_time - circuit_start_time
        #print(f"Circuit execution time: {circuit_time:.4f} seconds")

        # Generate random points (z1, z2)
        #z1 = [self.fs.rand_scalar() for _ in range(0, nOutBits)]  # legacy
        #z2 = [self.fs.rand_scalar() for _ in range(0, self.nCopyBits)]  # legacy
        z1 = [self._challenge("z1-%d" % i) for i in range(0, nOutBits)]
        z1_2 = None
        z2 = [self._challenge("z2-%d" % i) for i in range(0, self.nCopyBits)]
        if Defs.track_fArith:
            self.sc_a.did_rng(nOutBits + self.nCopyBits)

        # Start coordination with input multilinear extension
        prev_rval = None
        muls = None
        project_line = len(self.in0vv) == 1
        self.prover.set_z(z1, z2, None, None, project_line)

        # 1. Interact with prover to process each layer
        gkr_sumcheck_time = 0.0
        for lay in range(0, len(self.in0vv)):
            nInBits = self.layInBits[lay]
            nOutBits = self.layOutBits[lay]

            w1 = []
            w2 = []
            w3 = []
            if Defs.track_fArith:
                self.sc_a.did_rng(2*nInBits + self.nCopyBits)

            # A. Sumcheck
            _sc_t0 = time.time()
            for rd in range(0, 2 * nInBits + self.nCopyBits):
                # Get output from prover
                outs = self.prover.get_outputs()

                # 1. Generate commitment for each value in transcript
                outs_rvals = self.create_pok_temp(outs)

                # 2. Prove poly(0) + poly(1) equals previous commitment value
                zp1_rval = (sum(outs_rvals) + outs_rvals[0]) % Defs.prime
                self.create_eq_proof(prev_rval, zp1_rval)
                if Defs.track_fArith:
                    self.sc_a.did_add(len(outs_rvals))

                # 3. Calculate new prev_rval and proceed to next round
                #nrand = self.fs.rand_scalar()  # legacy
                nrand = self._challenge("sc-%d-%d" % (lay, rd))
                self.prover.next_round(nrand)
                prev_rval = util.horner_eval(outs_rvals, nrand, self.sc_a)

                if rd < self.nCopyBits:
                    assert len(outs) == 4
                    w3.append(nrand)
                else:
                    assert len(outs) == 3
                    if rd < self.nCopyBits + nInBits:
                        w1.append(nrand)
                    else:
                        w2.append(nrand)
            gkr_sumcheck_time += time.time() - _sc_t0

            # B. Extend to next layer
            outs = self.prover.get_outputs()

            if project_line:
                assert len(outs) == 1 + nInBits
                assert lay == len(self.in0vv) - 1
                (outs_rvals, pr_rvals) = self.create_final_prod_pok(outs)
            else:
                assert len(outs)==2
                pr_rvals = self.create_prod_pok(outs)

            # Prove final value of multilinear extension evaluation
            (mlext_evals, mlx_z2) = self.eval_mlext(lay, z1, z2, w1, w2, w3, z1_2, muls)

            tV_rval = 0
            for (idx, elm) in enumerate(mlext_evals):
                tV_rval += elm * GateFunctionsPC[idx](pr_rvals[0], pr_rvals[1], pr_rvals[2], self.tV_a)
                tV_rval %= Defs.prime
            tV_rval *= mlx_z2
            tV_rval %= Defs.prime
            self.create_eq_proof(prev_rval, tV_rval)
            if Defs.track_fArith:
                self.tV_a.did_add(len(mlext_evals)-1)
                self.tV_a.did_mul(len(mlext_evals)+1)

            project_next = lay == len(self.in0vv) - 2
            if project_line:
                #tau = self.fs.rand_scalar()  # legacy
                tau = self._challenge("tau-%d" % lay)
                muls = None
                prev_rval = util.horner_eval(outs_rvals, tau)
                z1 = [(elm1 + (elm2 - elm1) * tau) % Defs.prime for (elm1, elm2) in zip(w1, w2)]
                z1_2 = None
                if Defs.track_fArith:
                    self.nlay_a.did_sub(len(w1))
                    self.nlay_a.did_mul(len(w1))
                    self.nlay_a.did_add(len(w1))
                    self.sc_a.did_rng()
            else:
                #muls = [self.fs.rand_scalar(), self.fs.rand_scalar()]  # legacy
                muls = [self._challenge("mul0-%d" % lay), self._challenge("mul1-%d" % lay)]
                self.prover.next_layer(muls, project_next)
                tau = None
                prev_rval = (muls[0] * pr_rvals[0] + muls[1] * pr_rvals[1]) % Defs.prime
                z1 = w1
                z1_2 = w2
                if Defs.track_fArith:
                    self.nlay_a.did_add()
                    self.nlay_a.did_mul(2)
                    self.sc_a.did_rng(2)

            project_line = project_next
            z2 = w3

        print("GKR Sumcheck Time: %.6f seconds" % gkr_sumcheck_time)

        self.create_pok_final()

        # truepix: bind final authenticated claim to input MLE value.
        # Verifier will replace the local MLE with Orion's opening at the same point.
        self.final_input_point = list(z1) + list(z2)
        self.final_input_tag = prev_rval
        if Defs.is_ext_field():
            local_inputs = getattr(self, "_private_invals", None)
            if local_inputs is None:
                raise RuntimeError("private inputs missing for truepix")
            # Export point before value proof so verifier can open Orion first.
            self.fs.put(["gkr_input_point", serialize_point(self.final_input_point)])
            local_a = VerifierIOMLExt(self.final_input_point, self.in_a).compute(local_inputs)
            self.create_input_value_proof(prev_rval, local_a)

        # 3. Return transcript
        return self.fs.to_string()

class CircuitVerifierNIZK(CircuitVerifier, metaclass=libTruePix.parse_pws.FromPWS):
    fs = None
    cat_label = "ver_nizk"
    commit_type = ExtVOLECommit

    def __init__(self, nCopies, nInputs, in0vv, in1vv, typvv, muxvv=None):
        # Initialize VOLE commitment object
        if Defs.track_fArith:
            fArith = Defs.fArith()
            self.com_p_a = fArith.new_cat("%s_com_p_%d" % (self.cat_label, hash(self)))
            self.com_q_a = fArith.new_cat("%s_com_q_%d" % (self.cat_label, hash(self)))
            com_rec = (self.com_p_a, self.com_q_a)
        else:
            self.com_p_a = None
            self.com_q_a = None
            com_rec = None

        self.commit_type = ExtVOLECommit
        self.com = ExtVOLECommit(
            Defs.prime,
            com_rec,
            security_repetitions=Defs.vole_security_repetitions,
        )
        super().__init__(nCopies, nInputs, in0vv, in1vv, typvv, muxvv)
        self.p_elem=[]
        self.pending_input_claim = None

    def _challenge(self, label="chal"):
        return self.fs.rand_ext(label)

    def build_prover(self):
        pass

    def set_prover(self, _):
        pass

    def check_pok(self, n):
        """Verify Proof of Knowledge - VOLE version"""
        pvals = []  
        is_ok = True

        for _ in range(0, n):
            dval = self.fs.take()[0]
            pval = self.com.change_commit(dval) # This step replaces the correction value d_m to q_u to get q_m
            #chal = self.fs.rand_scalar()  # legacy
            chal = self._challenge("pok")
            (z1, z2) = self.fs.take()[0]
            is_ok &= self.com.pok_check(z1, z2, chal, pval)
            pvals.append(pval)

        if Defs.track_fArith:
            self.com_q_a.did_rng(n)

        return (pvals, is_ok)

    def check_pok_temp(self, n):
        """Verify Proof of Knowledge - VOLE version"""
        pvals = []  
        is_ok = True

        for i in range(0, n):
            dval = self.fs.take()[0]
            pval = self.com.change_commit(dval) # This step replaces the correction value d_m to q_u to get q_m
            pvals.append(pval)
            if len(self.p_elem) < n:
                self.p_elem.append(0)
            self.p_elem[i]+=pvals[i]

        return (pvals, is_ok)

    def check_pok_vec(self, n): # This function is temporarily unused, leave it unchanged for now
        """Verify Proof of Knowledge - VOLE version"""
        pvals = []  # Complete corresponding operations using the p value corresponding to the linear relationship
        is_ok = True

        dval = self.fs.take()[0]
        if Defs.is_ext_field():
            pval = self.com.change_commit_sum(dval, n)
        else:
            pval=sum(self.com.p[self.com.numVOLE:self.com.numVOLE+n])+dval*self.com.delta
            self.com.numVOLE +=n
            self.com.VOLEindex -=n
        #chal = self.fs.rand_scalar()  # legacy
        chal = self._challenge("pok-vec")
        (z1, z2) = self.fs.take()[0]
        is_ok &= self.com.pok_check(z1, z2, chal, pval)
        pvals.append(pval)

        if Defs.track_fArith:
            self.com_q_a.did_rng(n)

        return (pvals, is_ok)

    def check_pok_final(self):
        """Verify Proof of Knowledge - VOLE version"""

        #chal = self.fs.rand_scalar()  # legacy
        chal = self._challenge("pok-final")
        pval=sum(self.p_elem)
        (z1, z2) = self.fs.take()[0]
        is_ok = self.com.pok_check(z1, z2, chal, pval)

        return is_ok

    def check_prod_pok(self):
        """Verify product relation proof - VOLE version"""
        dvals= self.fs.take()[0]
        pvals=[]
        for dval in dvals:
            pval = self.com.change_commit(dval) 
            pvals.append(pval)
        #chal = self.fs.rand_scalar()
        avals = self.fs.take()[0]

        if Defs.track_fArith:
            self.com_q_a.did_rng()

        return (pvals, self.com.prod_check(pvals, avals))

    def check_final_prod_pok(self, nInBits): # This should also be unused
        """Verify final product proof - VOLE version"""
        (d1val, d3val) = self.fs.take()[0]
        p1val = self.com.change_commit(d1val)
        p3val = self.com.change_commit(d3val)

        # Mirror create_final_prod_pok: individual MACs for outs[1:] + aggregated PoK.
        # Legacy: (pvals, is_ok) = self.check_pok_vec(nInBits)
        pvals_rest = []
        is_ok = True
        for _ in range(0, nInBits):
            dval = self.fs.take()[0]
            pvals_rest.append(self.com.change_commit(dval))
        chal = self._challenge("pok-vec")
        (z1, z2) = self.fs.take()[0]
        rest_mac = sum(pvals_rest) % Defs.prime
        is_ok &= self.com.pok_check(z1, z2, chal, rest_mac)
        if Defs.track_fArith:
            self.com_q_a.did_rng(nInBits)

        pvals = [p1val] + pvals_rest
        p2val = sum(pvals) % Defs.prime
        pr_pvals=(p1val, p2val, p3val)

        #chal = self.fs.rand_scalar()
        avals = self.fs.take()[0]

        is_ok_1= self.com.prod_check(pr_pvals, avals)
        is_ok &= is_ok_1
        if Defs.track_fArith:
            self.com_q_a.did_rng()

        return (pvals, p2val, p3val,is_ok)

    def check_final_prod_pok_vec(self, nInBits):
        """Verify final product proof - VOLE version"""
        (pvals, is_ok) = self.check_pok_temp(nInBits)
        (d1val, d3val) = self.fs.take()[0]
        p1val = self.com.change_commit(d1val)
        p3val = self.com.change_commit(d3val)
        
        # Calculate p2val = sum([p1val]+ pvals)
        pvals = [p1val]+ pvals
        p2val = sum(pvals) % Defs.prime
        pr_pvals=(p1val, p2val, p3val)

        chal = self.fs.rand_scalar()
        avals = self.fs.take()[0]

        is_ok_1= self.com.prod_check(pr_pvals, avals, chal)
        is_ok &= is_ok_1
        if Defs.track_fArith:
            self.com_q_a.did_rng()

        return (pvals, p2val, p3val,is_ok)

    def check_val_proof(self, qval, val):
        """Verify value proof - VOLE version"""
        #chal = self.fs.rand_scalar()  # legacy
        chal = self._challenge("eq")
        v_z = self.fs.take()[0]

        if Defs.track_fArith:
            self.com_q_a.did_rng()

        return self.com.est_val_check(qval, chal, val ,v_z)

    def check_eq_proof(self, q1val, q2val):
        """Verify equality proof - VOLE version"""
        #chal = self.fs.rand_scalar()  # legacy
        chal = self._challenge("eq")
        v_z = self.fs.take()[0]

        if Defs.track_fArith:
            self.com_q_a.did_rng()

        return self.com.est_eq_check(q1val, q2val, chal, v_z)

    def check_input_value_proof(self, qval, val):
        """Verify final input opening against Orion public value."""
        chal = self._challenge("input-val")
        v_z = self.fs.take()[0]
        if Defs.track_fArith:
            self.com_q_a.did_rng()
        return self.com.est_val_check(qval, chal, val, v_z)

    def set_rdl(self, rdl, nRDLInputs):
        self.nInputs = nRDLInputs
        self.nInBits = util.clog2(nRDLInputs)
        assert len(rdl) == self.nCopies
        self.rdl = rdl
        
    def process_file_to_arrays(self, file_path):
        """
        Read a file line by line and convert each line to an array of integers.
        
        Args:
            file_path (str): Path to the input file
            
        Returns:
            list: A list of arrays (lists) where each array represents a line of numbers
            
        Raises:
            ValueError: If any line doesn't contain exactly 384 space-separated numbers
                       or if any value cannot be converted to integer
        """
        result_arrays = []
        
        with open(file_path, 'r') as file:
            for line_number, line in enumerate(file, 1):
                # Remove leading/trailing whitespace and split by spaces
                stripped_line = line.strip()
                if not stripped_line:  # Skip empty lines
                    continue
                    
                data = stripped_line.split()
                
                # Validate the number of elements
                if len(data) != 384:
                    raise ValueError(
                        f"Line {line_number}: Expected 384 numbers, found {len(data)}"
                    )
                
                # Convert to integers
                try:
                    numeric_array = [int(num) for num in data]
                except ValueError as e:
                    raise ValueError(
                        f"Line {line_number}: Invalid integer value - {str(e)}"
                    )
                numeric_array += [0]*128
                result_arrays += numeric_array
        
        return result_arrays


    def run(self, pf, _=None):  # pylint: disable=arguments-differ
        """Main verification function"""
        assert Defs.prime == self.com.q
        fs_protocol = Defs.PROTOCOL_ID
        self.fs = fs.FiatShamir.from_string(pf, protocol=fs_protocol)
        assert Defs.prime == self.fs.q
        
        pid = int(self.fs.take()[0])
        if Defs.is_ext_field():
            self.com.load_from_file_verifier(f"vole_ext_verifier_{pid}.json")
        else:
            self.com.load_from_file_verifier(f"vole_verifier_{pid}.json") # Read pre-generated delta and VOLE relation q_u

        # 0. Get input and output
        self.muxbits = self.fs.take(True)
        self.inputs = self.fs.take(True)
        # truepix: self.inputs is metadata only (private inputs omitted)

        # Get witness commitments
        nd_cvals = []
        if self.fs.ndb is not None:
            num_vals = 2 ** (self.nInBits - self.fs.ndb)
            nCopies = 1
            if self.rdl is None:
                nCopies = self.nCopies
            for copy in range(0, nCopies):
                (cvals, is_ok) = self.check_pok_temp(num_vals)
                if not is_ok:
                    raise ValueError("Failed getting commitments to input for copy %d" % copy)
                if self.rdl is None:
                    nd_cvals.append(cvals)
                else:
                    nd_cvals.extend(cvals)

        # Generate random values
        if self.fs.rvstart is not None and self.fs.rvend is not None:
            r_values = [self.fs.rand_scalar() for _ in range(self.fs.rvstart, self.fs.rvend + 1)]
            nCopies = 1
            if self.rdl is None:
                nCopies = self.nCopies
            for idx in range(0, nCopies):
                first = idx * (2 ** self.nInBits) + self.fs.rvstart
                last = first + self.fs.rvend - self.fs.rvstart + 1
        # Get output
        outvals = self.process_file_to_arrays("output.txt")
        outvals += [0] * (2 ** (util.clog2(len(outvals))) - len(outvals))
        self.outputs = self.fs.take(True)
        self.outputs = outvals

        # Mirror of the prover: pull the Orion commitment out of the transcript
        # and require it to be the commitment this verifier holds, so the
        # challenges below are bound to a fixed private input.
        if Defs.is_ext_field():
            from libTruePix.fp2_link import commit_binding, read_commit_manifest
            claimed = self.fs.take()
            expected = commit_binding(read_commit_manifest())
            if list(claimed) != expected:
                raise ValueError(
                    "Orion commitment in the proof does not match the "
                    "commitment manifest"
                )
        

        # 1. Multilinear extension of output
        nOutBits = util.clog2(len(self.in0vv[-1]))
        assert util.clog2(len(self.outputs)) == nOutBits + self.nCopyBits

        # z1 and z2 values
        #z1 = [self.fs.rand_scalar() for _ in range(0, nOutBits)]  # legacy
        #z2 = [self.fs.rand_scalar() for _ in range(0, self.nCopyBits)]  # legacy
        z1 = [self._challenge("z1-%d" % i) for i in range(0, nOutBits)]
        z1_2 = None
        z2 = [self._challenge("z2-%d" % i) for i in range(0, self.nCopyBits)]
        if Defs.track_fArith:
            self.sc_a.did_rng(nOutBits + self.nCopyBits)

        # P's instructions
        muls = None
        project_line = len(self.in0vv) == 1
        expectNext = VerifierIOMLExt(z1 + z2, self.out_a).compute(self.outputs)
        prev_cval = None

        # 2. Simulate prover interaction
        for lay in range(0, len(self.in0vv)):
            nInBits = self.layInBits[lay]
            nOutBits = self.layOutBits[lay]

            w1 = []
            w2 = []
            w3 = []
            if Defs.track_fArith:
                self.sc_a.did_rng(2*nInBits + self.nCopyBits)

            # A. Sumcheck
            for rd in range(0, 2 * nInBits + self.nCopyBits):
                if rd < self.nCopyBits:
                    nelms = 4
                else:
                    nelms = 3

                # Change this part to test the results of each layer simultaneously
                (cvals, is_ok) = self.check_pok_temp(nelms)
                if not is_ok:
                    raise ValueError("PoK failed for commits in round %d of layer %d" % (rd, lay))


                ncom = (sum(cvals) + cvals[0]) % Defs.prime
                if prev_cval is None:
                    is_ok = self.check_val_proof(ncom, expectNext)
                else:
                    is_ok = self.check_eq_proof(prev_cval, ncom)
                if not is_ok:
                    raise ValueError("Verification failed in round %d of layer %d" % (rd, lay))

                #nrand = self.fs.rand_scalar()  # legacy
                nrand = self._challenge("sc-%d-%d" % (lay, rd))
                prev_cval = util.horner_eval(cvals, nrand) 

                if rd < self.nCopyBits:
                    w3.append(nrand)
                elif rd < self.nCopyBits + nInBits:
                    w1.append(nrand)
                else:
                    w2.append(nrand)

            # B. Extend to next layer
            if project_line:
                assert lay == len(self.in0vv) - 1
                (cvals, c2val, c3val, is_ok) = self.check_final_prod_pok(nInBits)
                if not is_ok:
                    raise ValueError("Verification of final product PoK failed")
                pr_cvals = (cvals[0], c2val, c3val)
            else:
                (pr_cvals, is_ok) = self.check_prod_pok() # Should the return value here be modified?
                if not is_ok:
                    raise ValueError("Verification of product PoK failed in layer %d" % lay)

            # Check final value of multilinear extension evaluation (verify against ni file)
            (mlext_evals, mlx_z2) = self.eval_mlext(lay, z1, z2, w1, w2, w3, z1_2, muls)
            tV_cval = self.com.tV_eval(pr_cvals, mlext_evals, mlx_z2) 
            is_ok = self.check_eq_proof(prev_cval, tV_cval) 
            if not is_ok:
                raise ValueError("Verification of mlext eq proof failed in layer %d" % lay)


            project_next = lay == len(self.in0vv) - 2
            if project_line:
                #tau = self.fs.rand_scalar()  # legacy
                tau = self._challenge("tau-%d" % lay)
                muls = None
                prev_cval = util.horner_eval(cvals, tau)
                z1 = [(elm1 + (elm2 - elm1) * tau) % Defs.prime for (elm1, elm2) in zip(w1, w2)]
                z1_2 = None
                if Defs.track_fArith:
                    self.nlay_a.did_sub(len(w1))
                    self.nlay_a.did_mul(len(w1))
                    self.nlay_a.did_add(len(w1))
                    self.sc_a.did_rng()
            else:
                #muls = [self.fs.rand_scalar(), self.fs.rand_scalar()]  # legacy
                muls = [self._challenge("mul0-%d" % lay), self._challenge("mul1-%d" % lay)]
                tau = None
                prev_cval = (muls[0] * pr_cvals[0] + muls[1] * pr_cvals[1]) % Defs.prime
                z1 = w1
                z1_2 = w2
                if Defs.track_fArith:
                    self.sc_a.did_rng(2)

            project_line = project_next
            z2 = w3

        is_ok = self.check_pok_final()
        if not is_ok:
            raise ValueError("PoK failed for commits " )

        self.pending_input_claim = PendingInputClaim(
            input_point=list(z1) + list(z2),
            authenticated_claim=prev_cval,
            n_copies=self.nCopies,
            n_in_bits=self.nInBits,
        )

        if Defs.is_ext_field():
            # Consume exported point metadata from prover (verifier re-derives point above).
            _ = self.fs.take()
            # Return pending claim; caller must invoke finish_input(orion_value).
            return self.pending_input_claim

        return True

    def finish_input(self, orion_value):
        """Complete truepix verification using Orion opening value."""
        if self.pending_input_claim is None:
            raise RuntimeError("finish_input called without pending claim")
        is_ok = self.check_input_value_proof(
            self.pending_input_claim.authenticated_claim,
            orion_value,
        )
        if not is_ok:
            raise ValueError("Input opening check against Orion value failed")
        return True

    def run_with_orion_value(self, pf, orion_value):
        """Convenience: run GKR verify then bind Orion opening."""
        pending = self.run(pf)
        return self.finish_input(orion_value)



ProverClass = CircuitProverNIZK
VerifierClass = CircuitVerifierNIZK
