/*
 * native_fp2.cpp — Orion Mersenne-Fp2 batch kernels for TruePix GKR.
 *
 * Reuses prime_field::field_element arithmetic from Orion_zk.
 * Python binds via ctypes (see libTruePix/native_fp2_bridge.py).
 *
 * Coordinate convention in this ABI: (real, imag) — converted to/from
 * Orion's (img, real) layout at the boundary.
 */
#include <cstdint>
#include <cstring>
#include <vector>

#include "linear_gkr/prime_field.h"

using prime_field::field_element;

static inline field_element fe(uint64_t real, uint64_t imag) {
    field_element x;
    x.real = real;
    x.img = imag;
    return x;
}

static inline void store(const field_element& x, uint64_t* real, uint64_t* imag) {
    *real = x.real;
    *imag = x.img;
}

extern "C" {

int native_fp2_init(void) {
    if (!prime_field::initialized) {
        prime_field::init();
    }
    return 0;
}

/* Fold n pairs: out[i] = in[2i] + r * (in[2i+1] - in[2i]).
 * in_real/in_imag length 2*n; out length n.
 * Elements with imag==0 behave as base-field (still valid Fp2).
 */
void native_fp2_fold(
    const uint64_t* in_real,
    const uint64_t* in_imag,
    size_t n_out,
    uint64_t r_real,
    uint64_t r_imag,
    uint64_t* out_real,
    uint64_t* out_imag)
{
    field_element r = fe(r_real, r_imag);
    for (size_t i = 0; i < n_out; ++i) {
        field_element a = fe(in_real[2 * i], in_imag[2 * i]);
        field_element b = fe(in_real[2 * i + 1], in_imag[2 * i + 1]);
        field_element d = b - a;
        field_element result = a + r * d;
        store(result, &out_real[i], &out_imag[i]);
    }
}

/* Expand: each of n_src elements is replicated ncopies times into out. */
void native_fp2_expand(
    const uint64_t* in_real,
    const uint64_t* in_imag,
    size_t n_src,
    size_t ncopies,
    uint64_t* out_real,
    uint64_t* out_imag)
{
    for (size_t i = 0; i < n_src; ++i) {
        uint64_t rr = in_real[i];
        uint64_t ii = in_imag[i];
        size_t base = i * ncopies;
        for (size_t j = 0; j < ncopies; ++j) {
            out_real[base + j] = rr;
            out_imag[base + j] = ii;
        }
    }
}

/*
 * Early-round sumcheck aggregation (LayerProver.compute_outputs early path).
 *
 * Gate types match gateprover.GateFunctions indices:
 *   0 mul, 1 add, 2 sub, 3 muxL/pass-x, 4 muxR/pass-y,
 *   5 or, 6 xor, 7 not, 8 nand, 9 nor, 10 nxor, 11 naab, 12 pass(=x)
 *
 * Wire buffers are wire-major:
 *   values[wire * n_copies + copy]
 * Fact buffers:
 *   fact[wire * (n_copies/2) + (copy>>1)]
 */
void native_fp2_sumcheck_early(
    int n_gates,
    const int* gate_type,
    const int* in0,
    const int* in1,
    const uint64_t* z1_real,
    const uint64_t* z1_imag,
    int n_copies,
    int n_wires,
    const uint64_t* values_real,
    const uint64_t* values_imag,
    const uint64_t* fact0_real,
    const uint64_t* fact0_imag,
    const uint64_t* fact1_real,
    const uint64_t* fact1_imag,
    const uint64_t* beta_real,
    const uint64_t* beta_imag,
    const uint64_t* beta_f0_real,
    const uint64_t* beta_f0_imag,
    const uint64_t* beta_f1_real,
    const uint64_t* beta_f1_imag,
    uint64_t out8[8])
{
    (void)n_wires;
    field_element acc0 = field_element(0ULL);
    field_element acc1 = field_element(0ULL);
    field_element acc2 = field_element(0ULL);
    field_element acc3 = field_element(0ULL);

    const int half_n = n_copies >> 1;

    auto load_val = [&](int wire, int copy) -> field_element {
        size_t idx = (size_t)wire * (size_t)n_copies + (size_t)copy;
        return fe(values_real[idx], values_imag[idx]);
    };
    auto load_f0 = [&](int wire, int half) -> field_element {
        size_t idx = (size_t)wire * (size_t)half_n + (size_t)half;
        return fe(fact0_real[idx], fact0_imag[idx]);
    };
    auto load_f1 = [&](int wire, int half) -> field_element {
        size_t idx = (size_t)wire * (size_t)half_n + (size_t)half;
        return fe(fact1_real[idx], fact1_imag[idx]);
    };

    auto gatefn = [](int tp, const field_element& x, const field_element& y) -> field_element {
        switch (tp) {
        case 0:  return x * y;                         // mul
        case 1:  return x + y;                         // add
        case 2:  return x - y;                         // sub
        case 3:  return x;                             // muxL
        case 4:  return y;                             // muxR
        case 5:  return x + y - x * y;                 // or
        case 6:  return x + y - field_element(2) * x * y; // xor
        case 7:  return field_element(1) - x;          // not
        case 8:  return field_element(1) - x * y;      // nand
        case 9:  return field_element(1) + x * y - x - y; // nor
        case 10: return field_element(1) + field_element(2) * x * y - x - y; // nxor
        case 11: return (field_element(1) - x) * y;    // naab
        case 12: return x;                             // pass
        default: return x;
        }
    };

    for (int copy = 0; copy < n_copies; copy += 2) {
        field_element v0 = field_element(0ULL);
        field_element v1 = field_element(0ULL);
        field_element v2 = field_element(0ULL);
        field_element v3 = field_element(0ULL);
        const int half = copy >> 1;

        for (int g = 0; g < n_gates; ++g) {
            const int tp = gate_type[g];
            const int a = in0[g];
            const int b = in1[g];
            field_element z1 = fe(z1_real[g], z1_imag[g]);

            v0 = v0 + gatefn(tp, load_val(a, copy),     load_val(b, copy))     * z1;
            v1 = v1 + gatefn(tp, load_val(a, copy + 1), load_val(b, copy + 1)) * z1;
            v2 = v2 + gatefn(tp, load_f0(a, half),      load_f0(b, half))      * z1;
            v3 = v3 + gatefn(tp, load_f1(a, half),      load_f1(b, half))      * z1;
        }

        field_element b0 = fe(beta_real[copy], beta_imag[copy]);
        field_element b1 = fe(beta_real[copy + 1], beta_imag[copy + 1]);
        field_element bf0 = fe(beta_f0_real[half], beta_f0_imag[half]);
        field_element bf1 = fe(beta_f1_real[half], beta_f1_imag[half]);

        acc0 = acc0 + v0 * b0;
        acc1 = acc1 + v1 * b1;
        acc2 = acc2 + v2 * bf0;
        acc3 = acc3 + v3 * bf1;
    }

    store(acc0, &out8[0], &out8[1]);
    store(acc1, &out8[2], &out8[3]);
    store(acc2, &out8[4], &out8[5]);
    store(acc3, &out8[6], &out8[7]);
}

/* Beta table: out[i] = prod_j (z[j] if bit j of i else (1-z[j])), length 2^n_z.
 * init scales the whole table (same as Python compute_beta init).
 */
void native_fp2_compute_beta(
    const uint64_t* z_real,
    const uint64_t* z_imag,
    int n_z,
    uint64_t init_real,
    uint64_t init_imag,
    uint64_t* out_real,
    uint64_t* out_imag)
{
    if (n_z <= 0) {
        return;
    }
    const size_t n = (size_t)1 << n_z;
    field_element one = field_element(1ULL);
    // Build iteratively like a doubling product.
    out_real[0] = init_real;
    out_imag[0] = init_imag;
    size_t cur = 1;
    for (int j = 0; j < n_z; ++j) {
        field_element zj = fe(z_real[j], z_imag[j]);
        field_element omz = one - zj;
        for (size_t i = 0; i < cur; ++i) {
            field_element base = fe(out_real[i], out_imag[i]);
            field_element lo = base * omz;
            field_element hi = base * zj;
            store(lo, &out_real[i], &out_imag[i]);
            store(hi, &out_real[i + cur], &out_imag[i + cur]);
        }
        cur <<= 1;
    }
    (void)n;
}

/* MLE eval of base-field inputs at Fp2 point z (sqrt-bits algorithm).
 * inputs length must be >= 2^n_z (caller pads). Returns one Fp2.
 */
void native_fp2_mle_eval_base(
    const uint64_t* inputs,
    const uint64_t* z_real,
    const uint64_t* z_imag,
    int n_z,
    uint64_t* out_real,
    uint64_t* out_imag)
{
    if (n_z <= 0) {
        store(fe(inputs ? inputs[0] : 0ULL, 0ULL), out_real, out_imag);
        return;
    }
    // Recurse via explicit stack of (offset, n_bits) using sqrt split.
    // Allocate workspace for largest beta half: 2^(ceil(n_z/2)).
    int half = n_z / 2;
    int rest = n_z - half;
    if (half == 0) {
        // n_z == 1
        field_element z0 = fe(z_real[0], z_imag[0]);
        field_element a0 = fe(inputs[0], 0ULL);
        field_element a1 = fe(inputs[1], 0ULL);
        field_element r = a0 * (field_element(1ULL) - z0) + a1 * z0;
        store(r, out_real, out_imag);
        return;
    }

    size_t fh_len = (size_t)1 << half;
    size_t sh_len = (size_t)1 << rest;
    std::vector<uint64_t> beta_r(fh_len), beta_i(fh_len);
    native_fp2_compute_beta(z_real, z_imag, half, 1ULL, 0ULL, beta_r.data(), beta_i.data());

    std::vector<uint64_t> second_r(sh_len), second_i(sh_len);
    for (size_t i = 0; i < sh_len; ++i) {
        field_element accum = field_element(0ULL);
        const uint64_t* chunk = inputs + i * fh_len;
        for (size_t k = 0; k < fh_len; ++k) {
            uint64_t inp = chunk[k];
            if (inp == 0) continue;
            accum = accum + fe(beta_r[k], beta_i[k]) * field_element(inp);
        }
        store(accum, &second_r[i], &second_i[i]);
    }

    // Recurse on second_half with second_ins as Fp2 inputs.
    // For rest==1 use closed form; else recursive call via Fp2 input path.
    if (rest == 1) {
        field_element z0 = fe(z_real[half], z_imag[half]);
        field_element a0 = fe(second_r[0], second_i[0]);
        field_element a1 = fe(second_r[1], second_i[1]);
        field_element r = a0 * (field_element(1ULL) - z0) + a1 * z0;
        store(r, out_real, out_imag);
        return;
    }

    // General: treat second_ins as base? They're Fp2. Implement Fp2-input MLE fold.
    // Iterative fold over remaining bits:
    size_t cur_n = sh_len;
    std::vector<uint64_t> cur_r = std::move(second_r);
    std::vector<uint64_t> cur_i = std::move(second_i);
    for (int b = 0; b < rest; ++b) {
        field_element zb = fe(z_real[half + b], z_imag[half + b]);
        size_t new_n = cur_n >> 1;
        std::vector<uint64_t> nr(new_n), ni(new_n);
        for (size_t i = 0; i < new_n; ++i) {
            field_element a = fe(cur_r[2 * i], cur_i[2 * i]);
            field_element c = fe(cur_r[2 * i + 1], cur_i[2 * i + 1]);
            field_element r = a + zb * (c - a);
            store(r, &nr[i], &ni[i]);
        }
        cur_r.swap(nr);
        cur_i.swap(ni);
        cur_n = new_n;
    }
    *out_real = cur_r[0];
    *out_imag = cur_i[0];
}

}  // extern "C"
