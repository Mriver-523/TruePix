#pragma once
/*
 * Shared GKR Fp2 batch kernels (CPU host path).
 * Arithmetic uses h100-fp61 fp61::* instead of Orion prime_field::field_element.
 */
#include "fp61.cuh"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace native_fp2_core {

using fp61::Fp2;
using fp61::gkr_add;
using fp61::gkr_mul;
using fp61::gkr_sub;
using fp61::from_base;

// ABI uses std::uint64_t; fp61 uses unsigned long long (same width).
using u64 = std::uint64_t;

static inline Fp2 fe(u64 real, u64 imag) {
    return {static_cast<fp61::u64>(real), static_cast<fp61::u64>(imag)};
}

static inline void store(const Fp2& x, u64* real, u64* imag) {
    *real = static_cast<u64>(x.re);
    *imag = static_cast<u64>(x.im);
}

static inline Fp2 gatefn(int tp, const Fp2& x, const Fp2& y) {
    const Fp2 one = {1, 0};
    const Fp2 two = {2, 0};
    switch (tp) {
    case 0:  return gkr_mul(x, y);
    case 1:  return gkr_add(x, y);
    case 2:  return gkr_sub(x, y);
    case 3:  return x;
    case 4:  return y;
    case 5:  return gkr_sub(gkr_add(x, y), gkr_mul(x, y));
    case 6:  return gkr_sub(gkr_add(x, y), gkr_mul(two, gkr_mul(x, y)));
    case 7:  return gkr_sub(one, x);
    case 8:  return gkr_sub(one, gkr_mul(x, y));
    case 9:  return gkr_sub(gkr_add(one, gkr_mul(x, y)), gkr_add(x, y));
    case 10: return gkr_sub(gkr_add(one, gkr_mul(two, gkr_mul(x, y))), gkr_add(x, y));
    case 11: return gkr_mul(gkr_sub(one, x), y);
    case 12: return x;
    default: return x;
    }
}

inline void fold(
    const u64* in_real, const u64* in_imag, size_t n_out,
    u64 r_real, u64 r_imag,
    u64* out_real, u64* out_imag)
{
    const Fp2 r = fe(r_real, r_imag);
    for (size_t i = 0; i < n_out; ++i) {
        const Fp2 a = fe(in_real[2 * i], in_imag[2 * i]);
        const Fp2 b = fe(in_real[2 * i + 1], in_imag[2 * i + 1]);
        store(gkr_add(a, gkr_mul(r, gkr_sub(b, a))), &out_real[i], &out_imag[i]);
    }
}

inline void expand(
    const u64* in_real, const u64* in_imag,
    size_t n_src, size_t ncopies,
    u64* out_real, u64* out_imag)
{
    for (size_t i = 0; i < n_src; ++i) {
        const u64 rr = in_real[i];
        const u64 ii = in_imag[i];
        const size_t base = i * ncopies;
        for (size_t j = 0; j < ncopies; ++j) {
            out_real[base + j] = rr;
            out_imag[base + j] = ii;
        }
    }
}

inline void sumcheck_early(
    int n_gates,
    const int* gate_type, const int* in0, const int* in1,
    const u64* z1_real, const u64* z1_imag,
    int n_copies, int /*n_wires*/,
    const u64* values_real, const u64* values_imag,
    const u64* fact0_real, const u64* fact0_imag,
    const u64* fact1_real, const u64* fact1_imag,
    const u64* beta_real, const u64* beta_imag,
    const u64* beta_f0_real, const u64* beta_f0_imag,
    const u64* beta_f1_real, const u64* beta_f1_imag,
    u64 out8[8])
{
    Fp2 acc0{0, 0}, acc1{0, 0}, acc2{0, 0}, acc3{0, 0};
    const int half_n = n_copies >> 1;

    auto load_val = [&](int wire, int copy) -> Fp2 {
        const size_t idx = (size_t)wire * (size_t)n_copies + (size_t)copy;
        return fe(values_real[idx], values_imag[idx]);
    };
    auto load_f0 = [&](int wire, int half) -> Fp2 {
        const size_t idx = (size_t)wire * (size_t)half_n + (size_t)half;
        return fe(fact0_real[idx], fact0_imag[idx]);
    };
    auto load_f1 = [&](int wire, int half) -> Fp2 {
        const size_t idx = (size_t)wire * (size_t)half_n + (size_t)half;
        return fe(fact1_real[idx], fact1_imag[idx]);
    };

    for (int copy = 0; copy < n_copies; copy += 2) {
        Fp2 v0{0, 0}, v1{0, 0}, v2{0, 0}, v3{0, 0};
        const int half = copy >> 1;
        for (int g = 0; g < n_gates; ++g) {
            const int tp = gate_type[g];
            const int a = in0[g];
            const int b = in1[g];
            const Fp2 z1 = fe(z1_real[g], z1_imag[g]);
            v0 = gkr_add(v0, gkr_mul(gatefn(tp, load_val(a, copy), load_val(b, copy)), z1));
            v1 = gkr_add(v1, gkr_mul(gatefn(tp, load_val(a, copy + 1), load_val(b, copy + 1)), z1));
            v2 = gkr_add(v2, gkr_mul(gatefn(tp, load_f0(a, half), load_f0(b, half)), z1));
            v3 = gkr_add(v3, gkr_mul(gatefn(tp, load_f1(a, half), load_f1(b, half)), z1));
        }
        const Fp2 b0 = fe(beta_real[copy], beta_imag[copy]);
        const Fp2 b1 = fe(beta_real[copy + 1], beta_imag[copy + 1]);
        const Fp2 bf0 = fe(beta_f0_real[half], beta_f0_imag[half]);
        const Fp2 bf1 = fe(beta_f1_real[half], beta_f1_imag[half]);
        acc0 = gkr_add(acc0, gkr_mul(v0, b0));
        acc1 = gkr_add(acc1, gkr_mul(v1, b1));
        acc2 = gkr_add(acc2, gkr_mul(v2, bf0));
        acc3 = gkr_add(acc3, gkr_mul(v3, bf1));
    }
    store(acc0, &out8[0], &out8[1]);
    store(acc1, &out8[2], &out8[3]);
    store(acc2, &out8[4], &out8[5]);
    store(acc3, &out8[6], &out8[7]);
}

inline void compute_beta(
    const u64* z_real, const u64* z_imag, int n_z,
    u64 init_real, u64 init_imag,
    u64* out_real, u64* out_imag)
{
    if (n_z <= 0) return;
    out_real[0] = init_real;
    out_imag[0] = init_imag;
    size_t cur = 1;
    const Fp2 one{1, 0};
    for (int j = 0; j < n_z; ++j) {
        const Fp2 zj = fe(z_real[j], z_imag[j]);
        const Fp2 omz = gkr_sub(one, zj);
        for (size_t i = 0; i < cur; ++i) {
            const Fp2 base = fe(out_real[i], out_imag[i]);
            store(gkr_mul(base, omz), &out_real[i], &out_imag[i]);
            store(gkr_mul(base, zj), &out_real[i + cur], &out_imag[i + cur]);
        }
        cur <<= 1;
    }
}

// Host-side early-round GKR session: keep wire/beta tables resident across
// rounds; fuse eval-at-{-1,2} into claim; fold in-place on fold().
struct EarlySessionHost {
    int n_gates = 0;
    int n_wires = 0;
    int n_copies = 0;
    std::vector<int> gate_type, in0, in1;
    std::vector<u64> z1_r, z1_i;
    std::vector<u64> val_r, val_i;
    std::vector<u64> beta_r, beta_i;
};

inline EarlySessionHost* early_create(
    int n_gates,
    const int* gate_type, const int* in0, const int* in1,
    const u64* z1_real, const u64* z1_imag,
    int n_copies, int n_wires,
    const u64* values_real, const u64* values_imag,
    const u64* beta_real, const u64* beta_imag)
{
    if (n_gates <= 0 || n_wires <= 0 || n_copies < 2 || (n_copies & (n_copies - 1)) != 0)
        return nullptr;
    auto* s = new EarlySessionHost();
    s->n_gates = n_gates;
    s->n_wires = n_wires;
    s->n_copies = n_copies;
    s->gate_type.assign(gate_type, gate_type + n_gates);
    s->in0.assign(in0, in0 + n_gates);
    s->in1.assign(in1, in1 + n_gates);
    s->z1_r.assign(z1_real, z1_real + n_gates);
    s->z1_i.assign(z1_imag, z1_imag + n_gates);
    const size_t vn = (size_t)n_wires * (size_t)n_copies;
    s->val_r.assign(values_real, values_real + vn);
    s->val_i.assign(values_imag, values_imag + vn);
    s->beta_r.assign(beta_real, beta_real + n_copies);
    s->beta_i.assign(beta_imag, beta_imag + n_copies);
    return s;
}

inline void early_claim(EarlySessionHost* s, u64 out8[8])
{
    const int n_copies = s->n_copies;
    const int half_n = n_copies >> 1;
    // Fused eval points: fold(a,b,-1)=2a-b, fold(a,b,2)=2b-a  (mod p via gkr_*).
    auto load = [&](const std::vector<u64>& re, const std::vector<u64>& im,
                    int wire, int col, int stride) -> Fp2 {
        const size_t idx = (size_t)wire * (size_t)stride + (size_t)col;
        return fe(re[idx], im[idx]);
    };
    auto fold_m1 = [&](Fp2 a, Fp2 b) -> Fp2 {
        // a + (P-1)*(b-a) == 2a - b
        return gkr_sub(gkr_add(a, a), b);
    };
    auto fold_2 = [&](Fp2 a, Fp2 b) -> Fp2 {
        // a + 2*(b-a) == 2b - a
        return gkr_sub(gkr_add(b, b), a);
    };

    Fp2 acc0{0, 0}, acc1{0, 0}, acc2{0, 0}, acc3{0, 0};
    for (int pair = 0; pair < half_n; ++pair) {
        const int copy = pair << 1;
        Fp2 v0{0, 0}, v1{0, 0}, v2{0, 0}, v3{0, 0};
        for (int g = 0; g < s->n_gates; ++g) {
            const int tp = s->gate_type[g];
            const int wa = s->in0[g];
            const int wb = s->in1[g];
            const Fp2 z1 = fe(s->z1_r[g], s->z1_i[g]);
            const Fp2 a0 = load(s->val_r, s->val_i, wa, copy, n_copies);
            const Fp2 a1 = load(s->val_r, s->val_i, wa, copy + 1, n_copies);
            const Fp2 b0 = load(s->val_r, s->val_i, wb, copy, n_copies);
            const Fp2 b1 = load(s->val_r, s->val_i, wb, copy + 1, n_copies);
            v0 = gkr_add(v0, gkr_mul(gatefn(tp, a0, b0), z1));
            v1 = gkr_add(v1, gkr_mul(gatefn(tp, a1, b1), z1));
            v2 = gkr_add(v2, gkr_mul(gatefn(tp, fold_m1(a0, a1), fold_m1(b0, b1)), z1));
            v3 = gkr_add(v3, gkr_mul(gatefn(tp, fold_2(a0, a1), fold_2(b0, b1)), z1));
        }
        const Fp2 beta0 = fe(s->beta_r[copy], s->beta_i[copy]);
        const Fp2 beta1 = fe(s->beta_r[copy + 1], s->beta_i[copy + 1]);
        acc0 = gkr_add(acc0, gkr_mul(v0, beta0));
        acc1 = gkr_add(acc1, gkr_mul(v1, beta1));
        acc2 = gkr_add(acc2, gkr_mul(v2, fold_m1(beta0, beta1)));
        acc3 = gkr_add(acc3, gkr_mul(v3, fold_2(beta0, beta1)));
    }
    store(acc0, &out8[0], &out8[1]);
    store(acc1, &out8[2], &out8[3]);
    store(acc2, &out8[4], &out8[5]);
    store(acc3, &out8[6], &out8[7]);
}

inline void early_fold(EarlySessionHost* s, u64 r_real, u64 r_imag)
{
    const int n_in = s->n_copies;
    const int n_out = n_in >> 1;
    if (n_out < 1) return;
    const Fp2 r = fe(r_real, r_imag);
    std::vector<u64> nr((size_t)s->n_wires * (size_t)n_out);
    std::vector<u64> ni((size_t)s->n_wires * (size_t)n_out);
    for (int w = 0; w < s->n_wires; ++w) {
        const size_t bin = (size_t)w * (size_t)n_in;
        const size_t bout = (size_t)w * (size_t)n_out;
        for (int i = 0; i < n_out; ++i) {
            const Fp2 a = fe(s->val_r[bin + 2 * i], s->val_i[bin + 2 * i]);
            const Fp2 b = fe(s->val_r[bin + 2 * i + 1], s->val_i[bin + 2 * i + 1]);
            store(gkr_add(a, gkr_mul(r, gkr_sub(b, a))), &nr[bout + i], &ni[bout + i]);
        }
    }
    s->val_r.swap(nr);
    s->val_i.swap(ni);

    std::vector<u64> br((size_t)n_out), bi((size_t)n_out);
    for (int i = 0; i < n_out; ++i) {
        const Fp2 a = fe(s->beta_r[2 * i], s->beta_i[2 * i]);
        const Fp2 b = fe(s->beta_r[2 * i + 1], s->beta_i[2 * i + 1]);
        store(gkr_add(a, gkr_mul(r, gkr_sub(b, a))), &br[i], &bi[i]);
    }
    s->beta_r.swap(br);
    s->beta_i.swap(bi);
    s->n_copies = n_out;
}

inline void early_finish(
    EarlySessionHost* s,
    u64* wire_real, u64* wire_imag,
    u64* beta_real, u64* beta_imag)
{
    // After nCopyBits folds, each wire/beta should be a single Fp2.
    if (s->n_copies != 1) {
        // Still finish with whatever is at index 0 (defensive).
    }
    for (int w = 0; w < s->n_wires; ++w) {
        wire_real[w] = s->val_r[(size_t)w * (size_t)s->n_copies];
        wire_imag[w] = s->val_i[(size_t)w * (size_t)s->n_copies];
    }
    *beta_real = s->beta_r[0];
    *beta_imag = s->beta_i[0];
}

inline void early_destroy(EarlySessionHost* s) { delete s; }

inline void mle_eval_base(
    const u64* inputs,
    const u64* z_real, const u64* z_imag, int n_z,
    u64* out_real, u64* out_imag)
{
    if (n_z <= 0) {
        store(fe(inputs ? inputs[0] : 0ULL, 0ULL), out_real, out_imag);
        return;
    }
    int half = n_z / 2;
    int rest = n_z - half;
    if (half == 0) {
        const Fp2 z0 = fe(z_real[0], z_imag[0]);
        const Fp2 a0 = from_base(inputs[0]);
        const Fp2 a1 = from_base(inputs[1]);
        store(gkr_add(gkr_mul(a0, gkr_sub(Fp2{1, 0}, z0)), gkr_mul(a1, z0)),
              out_real, out_imag);
        return;
    }

    const size_t fh_len = (size_t)1 << half;
    const size_t sh_len = (size_t)1 << rest;
    std::vector<u64> beta_r(fh_len), beta_i(fh_len);
    compute_beta(z_real, z_imag, half, 1ULL, 0ULL, beta_r.data(), beta_i.data());

    std::vector<u64> second_r(sh_len), second_i(sh_len);
    for (size_t i = 0; i < sh_len; ++i) {
        Fp2 accum{0, 0};
        const u64* chunk = inputs + i * fh_len;
        for (size_t k = 0; k < fh_len; ++k) {
            const u64 inp = chunk[k];
            if (inp == 0) continue;
            accum = gkr_add(accum, gkr_mul(fe(beta_r[k], beta_i[k]), from_base(inp)));
        }
        store(accum, &second_r[i], &second_i[i]);
    }

    if (rest == 1) {
        const Fp2 z0 = fe(z_real[half], z_imag[half]);
        const Fp2 a0 = fe(second_r[0], second_i[0]);
        const Fp2 a1 = fe(second_r[1], second_i[1]);
        store(gkr_add(gkr_mul(a0, gkr_sub(Fp2{1, 0}, z0)), gkr_mul(a1, z0)),
              out_real, out_imag);
        return;
    }

    size_t cur_n = sh_len;
    std::vector<u64> cur_r = std::move(second_r);
    std::vector<u64> cur_i = std::move(second_i);
    for (int b = 0; b < rest; ++b) {
        const Fp2 zb = fe(z_real[half + b], z_imag[half + b]);
        const size_t new_n = cur_n >> 1;
        std::vector<u64> nr(new_n), ni(new_n);
        for (size_t i = 0; i < new_n; ++i) {
            const Fp2 a = fe(cur_r[2 * i], cur_i[2 * i]);
            const Fp2 c = fe(cur_r[2 * i + 1], cur_i[2 * i + 1]);
            store(gkr_add(a, gkr_mul(zb, gkr_sub(c, a))), &nr[i], &ni[i]);
        }
        cur_r.swap(nr);
        cur_i.swap(ni);
        cur_n = new_n;
    }
    *out_real = cur_r[0];
    *out_imag = cur_i[0];
}

} // namespace native_fp2_core
