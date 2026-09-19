#!/usr/bin/python
#
# layer provers (aka sub-provers)



from libTruePix.defs import Defs
from libTruePix.iomlext import VerifierIOMLExt
import libTruePix.gateprover as gateprover
from libTruePix.layercompute import LayerComputeV, LayerComputeBeta, LayerComputeH
import libTruePix.util as util
from libTruePix.extfield import Fp2
try:
    from libTruePix import native_fp2_bridge as _native_fp2
except ImportError:  # pragma: no cover
    _native_fp2 = None

class LayerProver(object):
    def __init__(self, nInBits, circuit, in0v, in1v, typev, muxv=None):
        # pylint: disable=protected-access
        self.nInBits = nInBits
        self.circuit = circuit
        self.nOutBits = util.clog2(len(in0v))
        self.roundNum = 0

        self.muls = None
        self.compute_v = []
        self.inputs = []
        self.output = []

        if muxv is None:
            # fake it
            muxv = [0] * len(in0v)
        assert len(in0v) == len(in1v) and len(in0v) == len(muxv) and len(in0v) == len(typev)

        # h computation subckt
        self.compute_h = LayerComputeH(self, circuit.comp_h)

        # beta computation subckt
        self.compute_beta = LayerComputeBeta(self.circuit.nCopyBits, None, circuit.comp_b)

        # z1chi computation subckt
        # this uses the Verifier's fast beta eval code
        self.compute_z1chi = None
        self.compute_z1chi_2 = None

        # v circuits are per-input---we collapse inputs in first nCopyBits rounds
        for _ in range(0, 2 ** self.nInBits):
            lcv_tmp = LayerComputeV(self.circuit.nCopyBits, circuit.comp_v)
            # outputs are collapsed
            lcv_tmp.expand_outputs = lcv_tmp.multiple_passes = False
            self.compute_v.append(lcv_tmp)

        # after finishing the first nCopyBits rounds, we only need one ComputeV circuit,
        # and everything is now 2nd order, so we only need three eval points, not four
        self.compute_v_final = LayerComputeV(self.nInBits, circuit.comp_v_fin)
        self.compute_v_final.set_other_factors([util.THIRD_EVAL_POINT])

        # pergate computation subckts for "early" rounds
        self.gates = []
        max_muxbit = 0
        for (out, (in0, in1, mx, tp)) in enumerate(zip(in0v, in1v, muxv, typev)):
            assert issubclass(tp, gateprover._GateProver)
            self.gates.append(tp(True, in0, in1, out, self, mx))
            if mx > max_muxbit:
                max_muxbit = mx
        muxlen = max_muxbit + 1
        assert len(self.circuit.muxbits) >= muxlen, "Expected %d muxbits, found %d" % (muxlen, len(self.circuit.muxbits))
        # Cached for native early sumcheck (rebuilt lazily if needed).
        self._native_gate_tables = None
        # Resident early-round session. Created only when GPU acceleration is active.
        self._early_session = None

    def _destroy_early_session(self):
        sess = getattr(self, "_early_session", None)
        if sess is not None:
            sess.destroy()
            self._early_session = None

    def _maybe_start_early_session(self):
        """Upload values/beta/gates once when a CUDA device is active."""
        if self._early_session is not None:
            return True
        if (
            _native_fp2 is None
            or not getattr(_native_fp2, "GPU_ACTIVE", False)
            or not _native_fp2.early_session_supported()
            or not self.gates
            or type(self.gates[0].accum_z1) is not Fp2
        ):
            return False
        n_copies = len(self.compute_beta.outputs)
        n_wires = len(self.compute_v)
        if n_copies < 2:
            return False
        if self._native_gate_tables is None:
            self._native_gate_tables = _native_fp2.cache_gate_tables(self.gates)
        gate_type, in0, in1 = self._native_gate_tables
        z1 = [g.accum_z1 for g in self.gates]
        values = [cv.outputs for cv in self.compute_v]
        try:
            self._early_session = _native_fp2.early_session_create(
                gate_type, in0, in1, z1,
                n_copies, n_wires,
                values, self.compute_beta.outputs,
            )
        except RuntimeError:
            self._early_session = None
            return False
        return True

    # set new inputs
    def set_inputs(self, inputs):
        assert len(inputs) == self.circuit.nCopies, "Got inputs for the wrong #copies"
        self.inputs = inputs
        self._destroy_early_session()
        for inX in range(0, 2 ** self.nInBits):
            # transpose input matrix
            inXVals = [ inCopy[inX] for inCopy in inputs ]
            self.compute_v[inX].set_inputs(inXVals)

    # set a new z vector
    def set_z(self, z1, z2, z1_2, muls, project_line):
        self.roundNum = 0
        self._destroy_early_session()
        self.compute_beta.set_inputs(z2)
        if z1_2 is not None:
            self.compute_z1chi = VerifierIOMLExt.compute_beta(z1, self.circuit.comp_chi, muls[0])
            self.compute_z1chi_2 = VerifierIOMLExt.compute_beta(z1_2, self.circuit.comp_chi, muls[1])
            assert len(muls) == 2, "Got muls of wrong size with non-None z1_2 in set_z()"
        else:
            self.compute_z1chi = VerifierIOMLExt.compute_beta(z1, self.circuit.comp_chi)
            self.compute_z1chi_2 = None
            assert muls is None

        # are we going to project a line at the beginning of the next round?
        self.compute_h.project_line = project_line

        # loop over all the gates and make them update their z coeffs
        for g in self.gates:
            g.set_z()

    # compute fj[0], fj[1], fj[-1], and maybe fj[2]
    def compute_outputs(self):
        # if we're at the last round, just return h coefficients
        if self.roundNum == self.circuit.nCopyBits + 2 * self.nInBits:
            self.output = self.compute_h.output
            return

        inEarlyRounds = True
        if self.roundNum >= self.circuit.nCopyBits:
            inEarlyRounds = False

        if inEarlyRounds:
            # GPU resident session when a device is present; otherwise the existing path.
            if self._maybe_start_early_session():
                outs = self._early_session.claim()
                if self.circuit.comp_out:
                    n_pairs = self._early_session.n_copies // 2
                    self.circuit.comp_out.did_add(n_pairs * (4 * len(self.gates) + 4))
                    self.circuit.comp_out.did_mul(n_pairs * (4 * len(self.gates) + 4))
                self.output = util.interpolate_cubic(outs, self.circuit.comp_out)
                return

            # Orion-backed batch early sumcheck when challenges are Fp2.
            use_native = (
                _native_fp2 is not None
                and getattr(_native_fp2, "AVAILABLE", False)
                and self.gates
                and type(self.gates[0].accum_z1) is Fp2
            )
            if use_native:
                n_copies = len(self.compute_beta.outputs)
                n_wires = len(self.compute_v)
                if self._native_gate_tables is None:
                    self._native_gate_tables = _native_fp2.cache_gate_tables(self.gates)
                gate_type, in0, in1 = self._native_gate_tables
                z1 = [g.accum_z1 for g in self.gates]
                values = [cv.outputs for cv in self.compute_v]
                fact0 = [cv.outputs_fact[0] for cv in self.compute_v]
                fact1 = [cv.outputs_fact[1] for cv in self.compute_v]
                outs = _native_fp2.sumcheck_early(
                    gate_type, in0, in1, z1,
                    n_copies, n_wires,
                    values, fact0, fact1,
                    self.compute_beta.outputs,
                    self.compute_beta.outputs_fact[0],
                    self.compute_beta.outputs_fact[1],
                )
                if self.circuit.comp_out:
                    n_pairs = n_copies // 2
                    self.circuit.comp_out.did_add(n_pairs * (4 * len(self.gates) + 4))
                    self.circuit.comp_out.did_mul(n_pairs * (4 * len(self.gates) + 4))
                self.output = util.interpolate_cubic(outs, self.circuit.comp_out)
            else:
                # go through each copy of the circuit
                prime = Defs.prime
                gates = self.gates
                beta_out = self.compute_beta.outputs
                beta_fact0 = self.compute_beta.outputs_fact[0]
                beta_fact1 = self.compute_beta.outputs_fact[1]
                comp_out = self.circuit.comp_out
                out0 = out1 = out2 = out3 = 0
                for copy in range(0, len(beta_out), 2):
                    v0 = v1 = v2 = v3 = 0
                    for g in gates:
                        g.compute_outputs_early(copy)
                        (g0, g1, g2, g3) = g.output
                        v0 += g0
                        v1 += g1
                        v2 += g2
                        v3 += g3

                    half = copy >> 1
                    out0 = (out0 + v0 % prime * beta_out[copy]) % prime
                    out1 = (out1 + v1 % prime * beta_out[copy + 1]) % prime
                    out2 = (out2 + v2 % prime * beta_fact0[half]) % prime
                    out3 = (out3 + v3 % prime * beta_fact1[half]) % prime

                    if comp_out:
                        comp_out.did_add(4 * len(gates) + 4)
                        comp_out.did_mul(4)

                self.output = util.interpolate_cubic([out0, out1, out2, out3], self.circuit.comp_out)

        else:
            # late rounds: only one set of gates over which to sum;
            # in these rounds we are updating w1 and then w2
            out = [0, 0, 0]
            for g in self.gates:
                g.compute_outputs()
                # sum contributions from this gate
                for j in range(0, 3):
                    out[j] += g.output[j]
                    out[j] %= Defs.prime

            for j in range(0, 3):
                out[j] *= self.compute_beta.prevPassValue

            if self.circuit.comp_out:
                self.circuit.comp_out.did_add(3 * len(self.gates))
                self.circuit.comp_out.did_mul(3)

            self.output = util.interpolate_quadratic(out, self.circuit.comp_out)

    # do updates upon receiving new random value
    def next_round(self, val):
        assert self.roundNum < self.circuit.nCopyBits + 2 * self.nInBits

        inLateRounds = True
        # do beta and V updates
        if self.roundNum < self.circuit.nCopyBits:
            inLateRounds = False
            if self._early_session is not None:
                self._early_session.fold(val)
                if self.roundNum == self.circuit.nCopyBits - 1:
                    wires, beta_prev = self._early_session.finish()
                    for i, cv in enumerate(self.compute_v):
                        cv.prevPassValue = wires[i]
                    self.compute_beta.prevPassValue = beta_prev
                    self.compute_v_final.set_inputs(wires)
                    for g in self.gates:
                        g.set_early(False)
                        g.set_z()
                    self._destroy_early_session()
            else:
                self.compute_beta.next_round(val)
                for cv in self.compute_v:
                    cv.next_round(val)
                # no gate updates in early rounds: gate circuits don't update state

                if self.roundNum == self.circuit.nCopyBits - 1:
                    inputs = [ cv.prevPassValue for cv in self.compute_v ]
                    assert all( elm is not None for elm in inputs )
                    self.compute_v_final.set_inputs(inputs)

                    for g in self.gates:
                        g.set_early(False)
                        g.set_z()

        # updating w1 or w2, which requires updating compute_v_final and the gates
        if inLateRounds:
            self.compute_v_final.next_round(val)
            for g in self.gates:
                g.next_round(val)

        # finally, update the h_vals (needs to be done after compute_v and compute_beta are updated)
        self.compute_h.next_round(val)

        self.roundNum += 1
