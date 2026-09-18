#!/usr/bin/python
#
# per-layer subckts used by layer provers



from libTruePix.defs import Defs
from libTruePix.extfield import Fp2, fold_val
from libTruePix.iomlext import VerifierIOMLExt
import libTruePix.util as util
try:
    from libTruePix import native_fp2_bridge as _native_fp2
except ImportError:  # pragma: no cover
    _native_fp2 = None

class LayerComputeV(object):
    expand_outputs = True
    multiple_passes = True

    def __init__(self, nOutBits, rec=None):
        self.outlen = 0
        self.roundNum = 0
        self.prevPassValue = None
        self.nOutBits = nOutBits
        self.inputs = []
        self.outputs = []
        self.scratch = []
        self.v1v2 = []
        self.outputs_fact = []
        self.other_factors = [util.THIRD_EVAL_POINT, util.FOURTH_EVAL_POINT]
        self.vrec = rec

    def set_other_factors(self, factors):
        self.other_factors = factors

    # set new inputs and reset counter
    def set_inputs(self, inputs):
        assert len(inputs) <= 2 ** self.nOutBits, "Got too many inputs for LayerComputeV"
        self.inputs = inputs + [0] * (2**self.nOutBits - len(inputs))
        self.outlen = 2 ** self.nOutBits
        assert len(self.inputs) == self.outlen, "Wrong number of inputs after padding"
        self.reset()

    def reset(self):
        # Prefer contiguous Fp2Buf copies over list(Fp2) materialization.
        if (
            _native_fp2 is not None
            and isinstance(self.inputs, _native_fp2.Fp2Buf)
        ):
            self.outputs = self.inputs[:]
            self.scratch = self.inputs[:]
        else:
            self.outputs = list(self.inputs)
            self.scratch = list(self.inputs)
        self.update_other_factors()
        self.roundNum = 0

    def next_pass(self):
        self.v1v2.append(self.scratch[0])
        self.prevPassValue = self.scratch[0]
        if self.multiple_passes:
            self.reset()
        else:
            self.outputs_fact = [[self.prevPassValue]] * len(self.other_factors)

    def update_other_factors(self):
        ofact = []
        for fact in self.other_factors:
            (tout, _) = self.update_outputs(fact)
            ofact.append(tout)

        self.outputs_fact = ofact

    def update_outputs(self, val):
        if self.vrec is not None:
            self.vrec.did_add()

        newlen = len(self.scratch) // 2
        ncopies = self.outlen // newlen

        # Orion-backed batch fold for Fp2 challenges, or when scratch is
        # already an Fp2Buf / contains Fp2 (e.g. other_factors = -1, 2).
        scratch0 = self.scratch[0] if self.scratch else None
        use_native = (
            _native_fp2 is not None
            and getattr(_native_fp2, "AVAILABLE", False)
            and newlen > 0
            and (
                type(val) is Fp2
                or type(scratch0) is Fp2
                or isinstance(scratch0, _native_fp2.Fp2Buf)
            )
        )
        if use_native:
            expand = ncopies if self.expand_outputs else 1
            output, scratch_out = _native_fp2.fold_values(self.scratch, val, expand)
            if self.vrec is not None:
                self.vrec.did_add(newlen)
                self.vrec.did_mul(2 * newlen)
            return (output, scratch_out)

        scratch_out = list([None] * newlen)
        if self.expand_outputs:
            output = list([None] * self.outlen)

        prime = Defs.prime
        scratch = self.scratch
        # Fused fold path avoids per-element Fp2 temporaries and operator
        # dispatch whenever extension-field values are involved.
        ext_mode = type(val) is Fp2

        for i in range(0, newlen):
            in0 = scratch[2 * i]
            in1 = scratch[2 * i + 1]
            # in0*(1-val) + in1*val == in0 + val*(in1-in0): one mul, and it
            # keeps the multiplication scalar when in0/in1 are base-field.
            if ext_mode or type(in0) is Fp2 or type(in1) is Fp2:
                result = fold_val(in0, in1, val, prime)
            else:
                result = (in0 + val * (in1 - in0)) % prime

            if self.vrec is not None:
                self.vrec.did_add()
                self.vrec.did_mul(2)

            scratch_out[i] = result
            if self.expand_outputs:
                output[i * ncopies : (i + 1) * ncopies] = [result] * ncopies

        if not self.expand_outputs:
            output = list(scratch_out)

        return (output, scratch_out)

    def next_round(self, val):
        # this assert can only fail when self.multiple_passes is false
        assert self.roundNum < self.nOutBits, "This object does not support multiple computation passes"

        (self.outputs, self.scratch) = self.update_outputs(val)
        self.roundNum += 1

        if self.roundNum == self.nOutBits:
            assert len(self.scratch) == 1
            self.next_pass()
        else:
            # prepare the evals at -1 for the next round
            assert len(self.scratch) > 1
            self.update_other_factors()

class LayerComputeBeta(LayerComputeV):
    expand_outputs = False
    multiple_passes = False

    def __init__(self, nOutBits, inputs=None, rec=None):
        super(LayerComputeBeta, self).__init__(nOutBits, rec)
        self.rec = rec
        if inputs is not None:
            self.other_factors = []
            self.set_inputs(inputs)

    def set_inputs(self, inputs):
        assert len(inputs) == self.nOutBits, "Got wrong number of inputs for LayerComputeBeta"
        self.inputs = VerifierIOMLExt.compute_beta(inputs, self.rec)
        self.outlen = 2 ** self.nOutBits
        assert len(self.inputs) == self.outlen, "Wrong number of inputs after computing"

        self.reset()

class LayerComputeH(object):
    def __init__(self, layer, rec=None):
        self.roundNum = 0
        self.layer = layer

        self.w1 = []
        self.w2 = []
        self.w2_m_w1 = []
        self.z1 = []
        self.w3 = []
        self.output = []
        self.project_line = True

        self.rec = rec

        # make subckt for each h_i
        self.h_elems = []
        for _ in range(0, self.layer.nInBits - 1):
            lcv = LayerComputeV(self.layer.nInBits, self.rec)
            lcv.expand_outputs = False
            self.h_elems.append(lcv)

    def next_layer(self, val):
        assert self.roundNum == 2 * self.layer.nInBits + self.layer.circuit.nCopyBits
        assert self.project_line
        self.z1 = [ (elm1 + elm2 * val) % Defs.prime for (elm1, elm2) in zip(self.w1, self.w2_m_w1) ]
        if Defs.track_fArith:
            self.rec.did_add(self.layer.nInBits)
            self.rec.did_mul(self.layer.nInBits)

    def next_round(self, val):
        assert self.roundNum < 2 * self.layer.nInBits + self.layer.circuit.nCopyBits

        if self.roundNum < self.layer.circuit.nCopyBits:
            # need this for going to the next layer
            self.w3.append(val)

        elif self.roundNum < self.layer.circuit.nCopyBits + self.layer.nInBits:
            self.w1.append(val)

        elif not self.project_line:
            self.w2.append(val)

        else:
            w2_m_w1 = (val - self.w1[self.roundNum - self.layer.nInBits - self.layer.circuit.nCopyBits]) % Defs.prime
            self.w2_m_w1.append(w2_m_w1)
            tmp = val
            for i in range(0, self.layer.nInBits - 1):
                tmp += w2_m_w1
                tmp %= Defs.prime

                self.h_elems[i].next_round(tmp)

            if self.rec:
                self.rec.did_sub()
                self.rec.did_add(self.layer.nInBits - 1)

        self.roundNum += 1

        # if we're done with w3s, we can build the condensed input structure
        if self.project_line and self.roundNum == self.layer.circuit.nCopyBits:
            for i in range(0, self.layer.nInBits - 1):
                self.h_elems[i].set_inputs(self.layer.compute_v_final.inputs)

        # until we've got all the values, this is all we can do
        if self.roundNum < self.layer.circuit.nCopyBits + 2 * self.layer.nInBits:
            return

        if self.project_line:
            # we've got all the w1 and w2 values, so interpolate
            h_vals = list(self.layer.compute_v_final.v1v2)
            for valu in range(2, self.layer.nInBits + 1):
                h_vals.append(self.h_elems[valu-2].prevPassValue)

            # finally, interpolate the result
            self.output = util.interpolate(h_vals, self.rec)

        else:
            self.output = list(self.layer.compute_v_final.v1v2)
