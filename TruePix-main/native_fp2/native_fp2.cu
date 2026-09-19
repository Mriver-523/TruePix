/*
 * native_fp2.cu — GKR Fp2 batch kernels on GPU (h100-fp61 arithmetic).
 *
 * Optimizations:
 *   A) Keep intermediates resident on device within a call (beta steps,
 *      MLE chunk+fold chain; sumcheck reduces on device → only 8 u64 D2H).
 *   B) Persistent device buffer pool: grow-once, never malloc/free per call.
 *   C) Early-round session: upload values/beta/gates once; claim+fold stay on
 *      device across nCopyBits rounds (challenge H2D + 8-limb claim D2H only).
 *   D) Fused eval-at-{-1,2} inside claim; batched multi-wire fold; parallel reduce.
 *
 * Falls back to host fp61 path when CUDA is unavailable or for tiny jobs.
 */
#include "fp61.cuh"
#include "native_fp2_core.hpp"

#include <cstdint>
#include <mutex>
#include <vector>

using fp61::Fp2;
using u64 = fp61::u64;

static_assert(sizeof(u64) == sizeof(std::uint64_t), "u64/uint64_t size mismatch");

inline const u64* as_u64(const std::uint64_t* p) {
    return reinterpret_cast<const u64*>(p);
}
inline u64* as_u64(std::uint64_t* p) {
    return reinterpret_cast<u64*>(p);
}

namespace {

constexpr int kBlock = 256;
// With pooled buffers, smaller batches amortize; still skip tiny jobs.
constexpr size_t kGpuFoldMin = 256;
constexpr int kGpuSumcheckMinCopies = 128;
constexpr int kGpuBetaMinNz = 8;
constexpr int kGpuMleMinNz = 8;

bool g_cuda_ok = false;
std::once_flag g_init_once;

struct DevBuf {
    void* ptr = nullptr;
    size_t bytes = 0;

    bool ensure(size_t need) {
        if (need == 0) return true;
        if (need <= bytes) return true;
        void* fresh = nullptr;
        if (cudaMalloc(&fresh, need) != cudaSuccess) return false;
        if (ptr) cudaFree(ptr);
        ptr = fresh;
        bytes = need;
        return true;
    }

    void release() {
        if (ptr) {
            cudaFree(ptr);
            ptr = nullptr;
            bytes = 0;
        }
    }

    template <typename T>
    T* as() { return reinterpret_cast<T*>(ptr); }

    template <typename T>
    const T* as() const { return reinterpret_cast<const T*>(ptr); }
};

// Persistent scratch across GKR kernel launches (process lifetime).
struct GpuPool {
    DevBuf a_r, a_i, b_r, b_i;          // generic ping-pong / fold / expand
    DevBuf sc_gt, sc_i0, sc_i1;
    DevBuf sc_z1r, sc_z1i;
    DevBuf sc_vr, sc_vi, sc_f0r, sc_f0i, sc_f1r, sc_f1i;
    DevBuf sc_br, sc_bi, sc_bf0r, sc_bf0i, sc_bf1r, sc_bf1i;
    DevBuf sc_pr, sc_pi, sc_out8;
    DevBuf beta_r, beta_i;
    DevBuf mle_in, mle_br, mle_bi;
};
GpuPool g_pool;

bool try_init_cuda() {
    int n = 0;
    if (cudaGetDeviceCount(&n) != cudaSuccess || n <= 0) return false;
    if (cudaSetDevice(0) != cudaSuccess) return false;
    return true;
}

void init_once() { g_cuda_ok = try_init_cuda(); }

inline int grid(size_t n) {
    return (int)((n + (size_t)kBlock - 1) / (size_t)kBlock);
}

__device__ __forceinline__ Fp2 d_gatefn(int tp, Fp2 x, Fp2 y) {
    const Fp2 one{1, 0};
    const Fp2 two{2, 0};
    switch (tp) {
    case 0:  return fp61::gkr_mul(x, y);
    case 1:  return fp61::gkr_add(x, y);
    case 2:  return fp61::gkr_sub(x, y);
    case 3:  return x;
    case 4:  return y;
    case 5:  return fp61::gkr_sub(fp61::gkr_add(x, y), fp61::gkr_mul(x, y));
    case 6:  return fp61::gkr_sub(fp61::gkr_add(x, y),
                                  fp61::gkr_mul(two, fp61::gkr_mul(x, y)));
    case 7:  return fp61::gkr_sub(one, x);
    case 8:  return fp61::gkr_sub(one, fp61::gkr_mul(x, y));
    case 9:  return fp61::gkr_sub(fp61::gkr_add(one, fp61::gkr_mul(x, y)),
                                  fp61::gkr_add(x, y));
    case 10: return fp61::gkr_sub(fp61::gkr_add(one, fp61::gkr_mul(two, fp61::gkr_mul(x, y))),
                                  fp61::gkr_add(x, y));
    case 11: return fp61::gkr_mul(fp61::gkr_sub(one, x), y);
    case 12: return x;
    default: return x;
    }
}

__global__ void fold_kernel(
    const u64* __restrict__ in_r, const u64* __restrict__ in_i,
    u64 r_re, u64 r_im,
    u64* __restrict__ out_r, u64* __restrict__ out_i,
    size_t n_out)
{
    const size_t i = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n_out) return;
    const Fp2 a{in_r[2 * i], in_i[2 * i]};
    const Fp2 b{in_r[2 * i + 1], in_i[2 * i + 1]};
    const Fp2 r{r_re, r_im};
    const Fp2 out = fp61::gkr_add(a, fp61::gkr_mul(r, fp61::gkr_sub(b, a)));
    out_r[i] = out.re;
    out_i[i] = out.im;
}

__global__ void expand_kernel(
    const u64* __restrict__ in_r, const u64* __restrict__ in_i,
    size_t n_src, size_t ncopies,
    u64* __restrict__ out_r, u64* __restrict__ out_i)
{
    const size_t idx = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    const size_t total = n_src * ncopies;
    if (idx >= total) return;
    const size_t src = idx / ncopies;
    out_r[idx] = in_r[src];
    out_i[idx] = in_i[src];
}

__device__ __forceinline__ Fp2 d_fold_chal(Fp2 a, Fp2 b, Fp2 r) {
    return fp61::gkr_add(a, fp61::gkr_mul(r, fp61::gkr_sub(b, a)));
}
__device__ __forceinline__ Fp2 d_fold_m1(Fp2 a, Fp2 b) {
    // a + (P-1)*(b-a) == 2a - b
    return fp61::gkr_sub(fp61::gkr_add(a, a), b);
}
__device__ __forceinline__ Fp2 d_fold_2(Fp2 a, Fp2 b) {
    // a + 2*(b-a) == 2b - a
    return fp61::gkr_sub(fp61::gkr_add(b, b), a);
}

__global__ void sumcheck_early_kernel(
    int n_gates,
    const int* __restrict__ gate_type,
    const int* __restrict__ in0,
    const int* __restrict__ in1,
    const u64* __restrict__ z1_r, const u64* __restrict__ z1_i,
    int n_copies,
    const u64* __restrict__ values_r, const u64* __restrict__ values_i,
    const u64* __restrict__ fact0_r, const u64* __restrict__ fact0_i,
    const u64* __restrict__ fact1_r, const u64* __restrict__ fact1_i,
    const u64* __restrict__ beta_r, const u64* __restrict__ beta_i,
    const u64* __restrict__ beta_f0_r, const u64* __restrict__ beta_f0_i,
    const u64* __restrict__ beta_f1_r, const u64* __restrict__ beta_f1_i,
    u64* __restrict__ partial_re,
    u64* __restrict__ partial_im)
{
    const int pair = (int)(blockIdx.x * blockDim.x + threadIdx.x);
    const int n_pairs = n_copies >> 1;
    if (pair >= n_pairs) return;

    const int copy = pair << 1;
    const int half = pair;
    const int half_n = n_pairs;

    auto load_val = [&](int wire, int c) -> Fp2 {
        const size_t idx = (size_t)wire * (size_t)n_copies + (size_t)c;
        return Fp2{values_r[idx], values_i[idx]};
    };
    auto load_f0 = [&](int wire, int h) -> Fp2 {
        const size_t idx = (size_t)wire * (size_t)half_n + (size_t)h;
        return Fp2{fact0_r[idx], fact0_i[idx]};
    };
    auto load_f1 = [&](int wire, int h) -> Fp2 {
        const size_t idx = (size_t)wire * (size_t)half_n + (size_t)h;
        return Fp2{fact1_r[idx], fact1_i[idx]};
    };

    Fp2 v0{0, 0}, v1{0, 0}, v2{0, 0}, v3{0, 0};
    for (int g = 0; g < n_gates; ++g) {
        const int tp = gate_type[g];
        const int a = in0[g];
        const int b = in1[g];
        const Fp2 z1{z1_r[g], z1_i[g]};
        v0 = fp61::gkr_add(v0, fp61::gkr_mul(d_gatefn(tp, load_val(a, copy), load_val(b, copy)), z1));
        v1 = fp61::gkr_add(v1, fp61::gkr_mul(d_gatefn(tp, load_val(a, copy + 1), load_val(b, copy + 1)), z1));
        v2 = fp61::gkr_add(v2, fp61::gkr_mul(d_gatefn(tp, load_f0(a, half), load_f0(b, half)), z1));
        v3 = fp61::gkr_add(v3, fp61::gkr_mul(d_gatefn(tp, load_f1(a, half), load_f1(b, half)), z1));
    }

    const Fp2 b0{beta_r[copy], beta_i[copy]};
    const Fp2 b1{beta_r[copy + 1], beta_i[copy + 1]};
    const Fp2 bf0{beta_f0_r[half], beta_f0_i[half]};
    const Fp2 bf1{beta_f1_r[half], beta_f1_i[half]};

    const Fp2 a0 = fp61::gkr_mul(v0, b0);
    const Fp2 a1 = fp61::gkr_mul(v1, b1);
    const Fp2 a2 = fp61::gkr_mul(v2, bf0);
    const Fp2 a3 = fp61::gkr_mul(v3, bf1);

    partial_re[0 * n_pairs + pair] = a0.re; partial_im[0 * n_pairs + pair] = a0.im;
    partial_re[1 * n_pairs + pair] = a1.re; partial_im[1 * n_pairs + pair] = a1.im;
    partial_re[2 * n_pairs + pair] = a2.re; partial_im[2 * n_pairs + pair] = a2.im;
    partial_re[3 * n_pairs + pair] = a3.re; partial_im[3 * n_pairs + pair] = a3.im;
}

// Session claim: fuse fold-at-{-1,2} from live values/beta (no fact H2D).
__global__ void sumcheck_early_fused_kernel(
    int n_gates,
    const int* __restrict__ gate_type,
    const int* __restrict__ in0,
    const int* __restrict__ in1,
    const u64* __restrict__ z1_r, const u64* __restrict__ z1_i,
    int n_copies,
    const u64* __restrict__ values_r, const u64* __restrict__ values_i,
    const u64* __restrict__ beta_r, const u64* __restrict__ beta_i,
    u64* __restrict__ partial_re,
    u64* __restrict__ partial_im)
{
    const int pair = (int)(blockIdx.x * blockDim.x + threadIdx.x);
    const int n_pairs = n_copies >> 1;
    if (pair >= n_pairs) return;
    const int copy = pair << 1;

    auto load_val = [&](int wire, int c) -> Fp2 {
        const size_t idx = (size_t)wire * (size_t)n_copies + (size_t)c;
        return Fp2{values_r[idx], values_i[idx]};
    };

    Fp2 v0{0, 0}, v1{0, 0}, v2{0, 0}, v3{0, 0};
    for (int g = 0; g < n_gates; ++g) {
        const int tp = gate_type[g];
        const int wa = in0[g];
        const int wb = in1[g];
        const Fp2 z1{z1_r[g], z1_i[g]};
        const Fp2 a0 = load_val(wa, copy);
        const Fp2 a1 = load_val(wa, copy + 1);
        const Fp2 b0 = load_val(wb, copy);
        const Fp2 b1 = load_val(wb, copy + 1);
        v0 = fp61::gkr_add(v0, fp61::gkr_mul(d_gatefn(tp, a0, b0), z1));
        v1 = fp61::gkr_add(v1, fp61::gkr_mul(d_gatefn(tp, a1, b1), z1));
        v2 = fp61::gkr_add(v2, fp61::gkr_mul(d_gatefn(tp, d_fold_m1(a0, a1), d_fold_m1(b0, b1)), z1));
        v3 = fp61::gkr_add(v3, fp61::gkr_mul(d_gatefn(tp, d_fold_2(a0, a1), d_fold_2(b0, b1)), z1));
    }

    const Fp2 beta0{beta_r[copy], beta_i[copy]};
    const Fp2 beta1{beta_r[copy + 1], beta_i[copy + 1]};
    const Fp2 a0 = fp61::gkr_mul(v0, beta0);
    const Fp2 a1 = fp61::gkr_mul(v1, beta1);
    const Fp2 a2 = fp61::gkr_mul(v2, d_fold_m1(beta0, beta1));
    const Fp2 a3 = fp61::gkr_mul(v3, d_fold_2(beta0, beta1));

    partial_re[0 * n_pairs + pair] = a0.re; partial_im[0 * n_pairs + pair] = a0.im;
    partial_re[1 * n_pairs + pair] = a1.re; partial_im[1 * n_pairs + pair] = a1.im;
    partial_re[2 * n_pairs + pair] = a2.re; partial_im[2 * n_pairs + pair] = a2.im;
    partial_re[3 * n_pairs + pair] = a3.re; partial_im[3 * n_pairs + pair] = a3.im;
}

// Parallel Fp2 reduce: 4 blocks (one per claim limb), shared-memory tree.
__global__ void reduce_sumcheck_partials_kernel(
    const u64* __restrict__ pr, const u64* __restrict__ pi,
    int n_pairs, u64* __restrict__ out8)
{
    const int t = (int)blockIdx.x;
    if (t >= 4) return;
    __shared__ u64 s_re[256];
    __shared__ u64 s_im[256];

    Fp2 acc{0, 0};
    const u64* re = pr + (size_t)t * (size_t)n_pairs;
    const u64* im = pi + (size_t)t * (size_t)n_pairs;
    for (int p = (int)threadIdx.x; p < n_pairs; p += (int)blockDim.x) {
        acc = fp61::gkr_add(acc, Fp2{re[p], im[p]});
    }
    s_re[threadIdx.x] = acc.re;
    s_im[threadIdx.x] = acc.im;
    __syncthreads();

    for (int stride = (int)blockDim.x >> 1; stride > 0; stride >>= 1) {
        if ((int)threadIdx.x < stride) {
            const Fp2 a{s_re[threadIdx.x], s_im[threadIdx.x]};
            const Fp2 b{s_re[threadIdx.x + stride], s_im[threadIdx.x + stride]};
            const Fp2 c = fp61::gkr_add(a, b);
            s_re[threadIdx.x] = c.re;
            s_im[threadIdx.x] = c.im;
        }
        __syncthreads();
    }
    if (threadIdx.x == 0) {
        out8[2 * t] = s_re[0];
        out8[2 * t + 1] = s_im[0];
    }
}

// Batch-fold all wires: idx covers n_wires * n_out elements.
__global__ void fold_batch_kernel(
    const u64* __restrict__ in_r, const u64* __restrict__ in_i,
    u64 r_re, u64 r_im,
    u64* __restrict__ out_r, u64* __restrict__ out_i,
    int n_wires, int n_out)
{
    const size_t idx = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    const size_t total = (size_t)n_wires * (size_t)n_out;
    if (idx >= total) return;
    const int n_in = n_out << 1;
    const int wire = (int)(idx / (size_t)n_out);
    const int i = (int)(idx % (size_t)n_out);
    const size_t base = (size_t)wire * (size_t)n_in;
    const Fp2 a{in_r[base + 2 * i], in_i[base + 2 * i]};
    const Fp2 b{in_r[base + 2 * i + 1], in_i[base + 2 * i + 1]};
    const Fp2 out = d_fold_chal(a, b, Fp2{r_re, r_im});
    const size_t o = (size_t)wire * (size_t)n_out + (size_t)i;
    out_r[o] = out.re;
    out_i[o] = out.im;
}

__global__ void beta_step_kernel(
    u64* __restrict__ out_r, u64* __restrict__ out_i,
    size_t cur, u64 zj_re, u64 zj_im)
{
    const size_t i = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= cur) return;
    const Fp2 base{out_r[i], out_i[i]};
    const Fp2 zj{zj_re, zj_im};
    const Fp2 omz = fp61::gkr_sub(Fp2{1, 0}, zj);
    const Fp2 lo = fp61::gkr_mul(base, omz);
    const Fp2 hi = fp61::gkr_mul(base, zj);
    out_r[i] = lo.re; out_i[i] = lo.im;
    out_r[i + cur] = hi.re; out_i[i + cur] = hi.im;
}

__global__ void fold_pairs_kernel(
    const u64* __restrict__ in_r, const u64* __restrict__ in_i,
    u64 z_re, u64 z_im,
    u64* __restrict__ out_r, u64* __restrict__ out_i,
    size_t n_out)
{
    const size_t i = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n_out) return;
    const Fp2 a{in_r[2 * i], in_i[2 * i]};
    const Fp2 c{in_r[2 * i + 1], in_i[2 * i + 1]};
    const Fp2 zb{z_re, z_im};
    const Fp2 out = fp61::gkr_add(a, fp61::gkr_mul(zb, fp61::gkr_sub(c, a)));
    out_r[i] = out.re;
    out_i[i] = out.im;
}

__global__ void mle_chunk_kernel(
    const u64* __restrict__ inputs,
    const u64* __restrict__ beta_r, const u64* __restrict__ beta_i,
    size_t fh_len, size_t sh_len,
    u64* __restrict__ out_r, u64* __restrict__ out_i)
{
    const size_t i = (size_t)blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= sh_len) return;
    Fp2 accum{0, 0};
    const u64* chunk = inputs + i * fh_len;
    for (size_t k = 0; k < fh_len; ++k) {
        const u64 inp = chunk[k];
        if (inp == 0) continue;
        accum = fp61::gkr_add(accum, fp61::gkr_mul(Fp2{beta_r[k], beta_i[k]}, fp61::from_base(inp)));
    }
    out_r[i] = accum.re;
    out_i[i] = accum.im;
}

bool gpu_fold(
    const u64* in_real, const u64* in_imag, size_t n_out,
    u64 r_real, u64 r_imag,
    u64* out_real, u64* out_imag)
{
    const size_t n_in = n_out * 2;
    if (!g_pool.a_r.ensure(n_in * sizeof(u64))) return false;
    if (!g_pool.a_i.ensure(n_in * sizeof(u64))) return false;
    if (!g_pool.b_r.ensure(n_out * sizeof(u64))) return false;
    if (!g_pool.b_i.ensure(n_out * sizeof(u64))) return false;

    u64* d_in_r = g_pool.a_r.as<u64>();
    u64* d_in_i = g_pool.a_i.as<u64>();
    u64* d_out_r = g_pool.b_r.as<u64>();
    u64* d_out_i = g_pool.b_i.as<u64>();

    if (cudaMemcpy(d_in_r, in_real, n_in * sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess) return false;
    if (cudaMemcpy(d_in_i, in_imag, n_in * sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess) return false;
    fold_kernel<<<grid(n_out), kBlock>>>(d_in_r, d_in_i, r_real, r_imag, d_out_r, d_out_i, n_out);
    if (cudaGetLastError() != cudaSuccess) return false;
    if (cudaMemcpy(out_real, d_out_r, n_out * sizeof(u64), cudaMemcpyDeviceToHost) != cudaSuccess) return false;
    if (cudaMemcpy(out_imag, d_out_i, n_out * sizeof(u64), cudaMemcpyDeviceToHost) != cudaSuccess) return false;
    return true;
}

bool gpu_expand(
    const u64* in_real, const u64* in_imag,
    size_t n_src, size_t ncopies,
    u64* out_real, u64* out_imag)
{
    const size_t total = n_src * ncopies;
    if (!g_pool.a_r.ensure(n_src * sizeof(u64))) return false;
    if (!g_pool.a_i.ensure(n_src * sizeof(u64))) return false;
    if (!g_pool.b_r.ensure(total * sizeof(u64))) return false;
    if (!g_pool.b_i.ensure(total * sizeof(u64))) return false;

    u64* d_in_r = g_pool.a_r.as<u64>();
    u64* d_in_i = g_pool.a_i.as<u64>();
    u64* d_out_r = g_pool.b_r.as<u64>();
    u64* d_out_i = g_pool.b_i.as<u64>();

    if (cudaMemcpy(d_in_r, in_real, n_src * sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess) return false;
    if (cudaMemcpy(d_in_i, in_imag, n_src * sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess) return false;
    expand_kernel<<<grid(total), kBlock>>>(d_in_r, d_in_i, n_src, ncopies, d_out_r, d_out_i);
    if (cudaGetLastError() != cudaSuccess) return false;
    if (cudaMemcpy(out_real, d_out_r, total * sizeof(u64), cudaMemcpyDeviceToHost) != cudaSuccess) return false;
    if (cudaMemcpy(out_imag, d_out_i, total * sizeof(u64), cudaMemcpyDeviceToHost) != cudaSuccess) return false;
    return true;
}

bool gpu_sumcheck_early(
    int n_gates,
    const int* gate_type, const int* in0, const int* in1,
    const u64* z1_real, const u64* z1_imag,
    int n_copies, int n_wires,
    const u64* values_real, const u64* values_imag,
    const u64* fact0_real, const u64* fact0_imag,
    const u64* fact1_real, const u64* fact1_imag,
    const u64* beta_real, const u64* beta_imag,
    const u64* beta_f0_real, const u64* beta_f0_imag,
    const u64* beta_f1_real, const u64* beta_f1_imag,
    u64 out8[8])
{
    const int n_pairs = n_copies >> 1;
    const int half_n = n_pairs;
    const size_t values_n = (size_t)n_wires * (size_t)n_copies;
    const size_t fact_n = (size_t)n_wires * (size_t)half_n;

    if (!g_pool.sc_gt.ensure((size_t)n_gates * sizeof(int))) return false;
    if (!g_pool.sc_i0.ensure((size_t)n_gates * sizeof(int))) return false;
    if (!g_pool.sc_i1.ensure((size_t)n_gates * sizeof(int))) return false;
    if (!g_pool.sc_z1r.ensure((size_t)n_gates * sizeof(u64))) return false;
    if (!g_pool.sc_z1i.ensure((size_t)n_gates * sizeof(u64))) return false;
    if (!g_pool.sc_vr.ensure(values_n * sizeof(u64))) return false;
    if (!g_pool.sc_vi.ensure(values_n * sizeof(u64))) return false;
    if (!g_pool.sc_f0r.ensure(fact_n * sizeof(u64))) return false;
    if (!g_pool.sc_f0i.ensure(fact_n * sizeof(u64))) return false;
    if (!g_pool.sc_f1r.ensure(fact_n * sizeof(u64))) return false;
    if (!g_pool.sc_f1i.ensure(fact_n * sizeof(u64))) return false;
    if (!g_pool.sc_br.ensure((size_t)n_copies * sizeof(u64))) return false;
    if (!g_pool.sc_bi.ensure((size_t)n_copies * sizeof(u64))) return false;
    if (!g_pool.sc_bf0r.ensure((size_t)half_n * sizeof(u64))) return false;
    if (!g_pool.sc_bf0i.ensure((size_t)half_n * sizeof(u64))) return false;
    if (!g_pool.sc_bf1r.ensure((size_t)half_n * sizeof(u64))) return false;
    if (!g_pool.sc_bf1i.ensure((size_t)half_n * sizeof(u64))) return false;
    if (!g_pool.sc_pr.ensure(4 * (size_t)n_pairs * sizeof(u64))) return false;
    if (!g_pool.sc_pi.ensure(4 * (size_t)n_pairs * sizeof(u64))) return false;
    if (!g_pool.sc_out8.ensure(8 * sizeof(u64))) return false;

    int* d_gt = g_pool.sc_gt.as<int>();
    int* d_i0 = g_pool.sc_i0.as<int>();
    int* d_i1 = g_pool.sc_i1.as<int>();
    u64* d_z1r = g_pool.sc_z1r.as<u64>();
    u64* d_z1i = g_pool.sc_z1i.as<u64>();
    u64* d_vr = g_pool.sc_vr.as<u64>();
    u64* d_vi = g_pool.sc_vi.as<u64>();
    u64* d_f0r = g_pool.sc_f0r.as<u64>();
    u64* d_f0i = g_pool.sc_f0i.as<u64>();
    u64* d_f1r = g_pool.sc_f1r.as<u64>();
    u64* d_f1i = g_pool.sc_f1i.as<u64>();
    u64* d_br = g_pool.sc_br.as<u64>();
    u64* d_bi = g_pool.sc_bi.as<u64>();
    u64* d_bf0r = g_pool.sc_bf0r.as<u64>();
    u64* d_bf0i = g_pool.sc_bf0i.as<u64>();
    u64* d_bf1r = g_pool.sc_bf1r.as<u64>();
    u64* d_bf1i = g_pool.sc_bf1i.as<u64>();
    u64* d_pr = g_pool.sc_pr.as<u64>();
    u64* d_pi = g_pool.sc_pi.as<u64>();
    u64* d_out8 = g_pool.sc_out8.as<u64>();

    if (cudaMemcpy(d_gt, gate_type, (size_t)n_gates * sizeof(int), cudaMemcpyHostToDevice) != cudaSuccess) return false;
    if (cudaMemcpy(d_i0, in0, (size_t)n_gates * sizeof(int), cudaMemcpyHostToDevice) != cudaSuccess) return false;
    if (cudaMemcpy(d_i1, in1, (size_t)n_gates * sizeof(int), cudaMemcpyHostToDevice) != cudaSuccess) return false;
    if (cudaMemcpy(d_z1r, z1_real, (size_t)n_gates * sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess) return false;
    if (cudaMemcpy(d_z1i, z1_imag, (size_t)n_gates * sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess) return false;
    if (cudaMemcpy(d_vr, values_real, values_n * sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess) return false;
    if (cudaMemcpy(d_vi, values_imag, values_n * sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess) return false;
    if (cudaMemcpy(d_f0r, fact0_real, fact_n * sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess) return false;
    if (cudaMemcpy(d_f0i, fact0_imag, fact_n * sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess) return false;
    if (cudaMemcpy(d_f1r, fact1_real, fact_n * sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess) return false;
    if (cudaMemcpy(d_f1i, fact1_imag, fact_n * sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess) return false;
    if (cudaMemcpy(d_br, beta_real, (size_t)n_copies * sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess) return false;
    if (cudaMemcpy(d_bi, beta_imag, (size_t)n_copies * sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess) return false;
    if (cudaMemcpy(d_bf0r, beta_f0_real, (size_t)half_n * sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess) return false;
    if (cudaMemcpy(d_bf0i, beta_f0_imag, (size_t)half_n * sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess) return false;
    if (cudaMemcpy(d_bf1r, beta_f1_real, (size_t)half_n * sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess) return false;
    if (cudaMemcpy(d_bf1i, beta_f1_imag, (size_t)half_n * sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess) return false;

    sumcheck_early_kernel<<<grid((size_t)n_pairs), kBlock>>>(
        n_gates, d_gt, d_i0, d_i1, d_z1r, d_z1i, n_copies,
        d_vr, d_vi, d_f0r, d_f0i, d_f1r, d_f1i,
        d_br, d_bi, d_bf0r, d_bf0i, d_bf1r, d_bf1i,
        d_pr, d_pi);
    if (cudaGetLastError() != cudaSuccess) return false;

    // Reduce on device; only the 8-limb claim returns to host (A).
    reduce_sumcheck_partials_kernel<<<4, kBlock>>>(d_pr, d_pi, n_pairs, d_out8);
    if (cudaGetLastError() != cudaSuccess) return false;
    if (cudaMemcpy(out8, d_out8, 8 * sizeof(u64), cudaMemcpyDeviceToHost) != cudaSuccess) return false;
    return true;
}

bool gpu_compute_beta(
    const u64* z_real, const u64* z_imag, int n_z,
    u64 init_real, u64 init_imag,
    u64* out_real, u64* out_imag)
{
    if (n_z <= 0) return true;
    const size_t n = (size_t)1 << n_z;
    if (!g_pool.beta_r.ensure(n * sizeof(u64))) return false;
    if (!g_pool.beta_i.ensure(n * sizeof(u64))) return false;
    u64* d_out_r = g_pool.beta_r.as<u64>();
    u64* d_out_i = g_pool.beta_i.as<u64>();

    if (cudaMemset(d_out_r, 0, n * sizeof(u64)) != cudaSuccess) return false;
    if (cudaMemset(d_out_i, 0, n * sizeof(u64)) != cudaSuccess) return false;
    if (cudaMemcpy(d_out_r, &init_real, sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess) return false;
    if (cudaMemcpy(d_out_i, &init_imag, sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess) return false;

    // All doubling steps stay on the same device buffers (A).
    size_t cur = 1;
    for (int j = 0; j < n_z; ++j) {
        beta_step_kernel<<<grid(cur), kBlock>>>(d_out_r, d_out_i, cur, z_real[j], z_imag[j]);
        if (cudaGetLastError() != cudaSuccess) return false;
        cur <<= 1;
    }
    if (cudaMemcpy(out_real, d_out_r, n * sizeof(u64), cudaMemcpyDeviceToHost) != cudaSuccess) return false;
    if (cudaMemcpy(out_imag, d_out_i, n * sizeof(u64), cudaMemcpyDeviceToHost) != cudaSuccess) return false;
    return true;
}

bool gpu_mle_eval_base(
    const u64* inputs,
    const u64* z_real, const u64* z_imag, int n_z,
    u64* out_real, u64* out_imag)
{
    if (n_z < kGpuMleMinNz) {
        native_fp2_core::mle_eval_base(
            reinterpret_cast<const std::uint64_t*>(inputs),
            reinterpret_cast<const std::uint64_t*>(z_real),
            reinterpret_cast<const std::uint64_t*>(z_imag),
            n_z,
            reinterpret_cast<std::uint64_t*>(out_real),
            reinterpret_cast<std::uint64_t*>(out_imag));
        return true;
    }

    const int half = n_z / 2;
    const int rest = n_z - half;
    if (half == 0) {
        native_fp2_core::mle_eval_base(
            reinterpret_cast<const std::uint64_t*>(inputs),
            reinterpret_cast<const std::uint64_t*>(z_real),
            reinterpret_cast<const std::uint64_t*>(z_imag),
            n_z,
            reinterpret_cast<std::uint64_t*>(out_real),
            reinterpret_cast<std::uint64_t*>(out_imag));
        return true;
    }

    const size_t fh_len = (size_t)1 << half;
    const size_t sh_len = (size_t)1 << rest;
    const size_t in_n = fh_len * sh_len;

    // Beta half-table built on device into g_pool.beta_*; leave resident.
    if (!g_pool.beta_r.ensure(fh_len * sizeof(u64))) return false;
    if (!g_pool.beta_i.ensure(fh_len * sizeof(u64))) return false;
    u64* d_beta_r = g_pool.beta_r.as<u64>();
    u64* d_beta_i = g_pool.beta_i.as<u64>();
    {
        if (cudaMemset(d_beta_r, 0, fh_len * sizeof(u64)) != cudaSuccess) return false;
        if (cudaMemset(d_beta_i, 0, fh_len * sizeof(u64)) != cudaSuccess) return false;
        u64 one = 1, zero = 0;
        if (cudaMemcpy(d_beta_r, &one, sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess) return false;
        if (cudaMemcpy(d_beta_i, &zero, sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess) return false;
        size_t cur = 1;
        for (int j = 0; j < half; ++j) {
            beta_step_kernel<<<grid(cur), kBlock>>>(d_beta_r, d_beta_i, cur, z_real[j], z_imag[j]);
            if (cudaGetLastError() != cudaSuccess) return false;
            cur <<= 1;
        }
    }

    if (!g_pool.mle_in.ensure(in_n * sizeof(u64))) return false;
    if (!g_pool.a_r.ensure(sh_len * sizeof(u64))) return false;
    if (!g_pool.a_i.ensure(sh_len * sizeof(u64))) return false;
    if (!g_pool.b_r.ensure(sh_len * sizeof(u64))) return false;
    if (!g_pool.b_i.ensure(sh_len * sizeof(u64))) return false;

    u64* d_in = g_pool.mle_in.as<u64>();
    if (cudaMemcpy(d_in, inputs, in_n * sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess) return false;

    u64* cur_r = g_pool.a_r.as<u64>();
    u64* cur_i = g_pool.a_i.as<u64>();
    mle_chunk_kernel<<<grid(sh_len), kBlock>>>(d_in, d_beta_r, d_beta_i, fh_len, sh_len, cur_r, cur_i);
    if (cudaGetLastError() != cudaSuccess) return false;

    // Fold remaining bits entirely on device (ping-pong a/b pools).
    size_t cur_n = sh_len;
    u64* nxt_r = g_pool.b_r.as<u64>();
    u64* nxt_i = g_pool.b_i.as<u64>();
    for (int b = 0; b < rest; ++b) {
        const size_t new_n = cur_n >> 1;
        fold_pairs_kernel<<<grid(new_n), kBlock>>>(
            cur_r, cur_i, z_real[half + b], z_imag[half + b], nxt_r, nxt_i, new_n);
        if (cudaGetLastError() != cudaSuccess) return false;
        // Swap roles for next round.
        u64* tr = cur_r; u64* ti = cur_i;
        cur_r = nxt_r; cur_i = nxt_i;
        nxt_r = tr; nxt_i = ti;
        cur_n = new_n;
    }

    if (cudaMemcpy(out_real, cur_r, sizeof(u64), cudaMemcpyDeviceToHost) != cudaSuccess) return false;
    if (cudaMemcpy(out_imag, cur_i, sizeof(u64), cudaMemcpyDeviceToHost) != cudaSuccess) return false;
    return true;
}


// ---- Early-round resident session (GPU preferred, host fallback) ----

struct EarlySessionGpu {
    int n_gates = 0;
    int n_wires = 0;
    int n_copies = 0;
    int n_copies_cap = 0;
    DevBuf gt, i0, i1, z1r, z1i;
    DevBuf val_r, val_i;
    DevBuf val2_r, val2_i;
    DevBuf beta_r, beta_i;
    DevBuf beta2_r, beta2_i;
    DevBuf pr, pi, out8;
    bool use_ping = false;

    ~EarlySessionGpu() {
        gt.release(); i0.release(); i1.release();
        z1r.release(); z1i.release();
        val_r.release(); val_i.release();
        val2_r.release(); val2_i.release();
        beta_r.release(); beta_i.release();
        beta2_r.release(); beta2_i.release();
        pr.release(); pi.release(); out8.release();
    }
};

bool early_gpu_claim(EarlySessionGpu* s, u64 out8[8])
{
    const int n_pairs = s->n_copies >> 1;
    if (n_pairs < 1) return false;
    if (!s->pr.ensure(4 * (size_t)n_pairs * sizeof(u64))) return false;
    if (!s->pi.ensure(4 * (size_t)n_pairs * sizeof(u64))) return false;
    if (!s->out8.ensure(8 * sizeof(u64))) return false;

    u64* d_vr = s->use_ping ? s->val2_r.as<u64>() : s->val_r.as<u64>();
    u64* d_vi = s->use_ping ? s->val2_i.as<u64>() : s->val_i.as<u64>();
    u64* d_br = s->use_ping ? s->beta2_r.as<u64>() : s->beta_r.as<u64>();
    u64* d_bi = s->use_ping ? s->beta2_i.as<u64>() : s->beta_i.as<u64>();

    sumcheck_early_fused_kernel<<<grid((size_t)n_pairs), kBlock>>>(
        s->n_gates, s->gt.as<int>(), s->i0.as<int>(), s->i1.as<int>(),
        s->z1r.as<u64>(), s->z1i.as<u64>(),
        s->n_copies, d_vr, d_vi, d_br, d_bi,
        s->pr.as<u64>(), s->pi.as<u64>());
    if (cudaGetLastError() != cudaSuccess) return false;
    reduce_sumcheck_partials_kernel<<<4, kBlock>>>(
        s->pr.as<u64>(), s->pi.as<u64>(), n_pairs, s->out8.as<u64>());
    if (cudaGetLastError() != cudaSuccess) return false;
    if (cudaMemcpy(out8, s->out8.as<u64>(), 8 * sizeof(u64), cudaMemcpyDeviceToHost) != cudaSuccess)
        return false;
    return true;
}

bool early_gpu_fold(EarlySessionGpu* s, u64 r_real, u64 r_imag)
{
    const int n_in = s->n_copies;
    const int n_out = n_in >> 1;
    if (n_out < 1) return false;

    u64* in_vr = s->use_ping ? s->val2_r.as<u64>() : s->val_r.as<u64>();
    u64* in_vi = s->use_ping ? s->val2_i.as<u64>() : s->val_i.as<u64>();
    u64* out_vr = s->use_ping ? s->val_r.as<u64>() : s->val2_r.as<u64>();
    u64* out_vi = s->use_ping ? s->val_i.as<u64>() : s->val2_i.as<u64>();
    u64* in_br = s->use_ping ? s->beta2_r.as<u64>() : s->beta_r.as<u64>();
    u64* in_bi = s->use_ping ? s->beta2_i.as<u64>() : s->beta_i.as<u64>();
    u64* out_br = s->use_ping ? s->beta_r.as<u64>() : s->beta2_r.as<u64>();
    u64* out_bi = s->use_ping ? s->beta_i.as<u64>() : s->beta2_i.as<u64>();

    const size_t total = (size_t)s->n_wires * (size_t)n_out;
    fold_batch_kernel<<<grid(total), kBlock>>>(
        in_vr, in_vi, r_real, r_imag, out_vr, out_vi, s->n_wires, n_out);
    if (cudaGetLastError() != cudaSuccess) return false;
    fold_kernel<<<grid((size_t)n_out), kBlock>>>(
        in_br, in_bi, r_real, r_imag, out_br, out_bi, (size_t)n_out);
    if (cudaGetLastError() != cudaSuccess) return false;

    s->use_ping = !s->use_ping;
    s->n_copies = n_out;
    return true;
}

bool early_gpu_finish(
    EarlySessionGpu* s,
    u64* wire_real, u64* wire_imag,
    u64* beta_real, u64* beta_imag)
{
    u64* d_vr = s->use_ping ? s->val2_r.as<u64>() : s->val_r.as<u64>();
    u64* d_vi = s->use_ping ? s->val2_i.as<u64>() : s->val_i.as<u64>();
    u64* d_br = s->use_ping ? s->beta2_r.as<u64>() : s->beta_r.as<u64>();
    u64* d_bi = s->use_ping ? s->beta2_i.as<u64>() : s->beta_i.as<u64>();
    const int stride = s->n_copies;
    // Gather wire[0] for each row with one contiguous D2H when stride==1.
    if (stride == 1) {
        if (cudaMemcpy(wire_real, d_vr, (size_t)s->n_wires * sizeof(u64), cudaMemcpyDeviceToHost) != cudaSuccess)
            return false;
        if (cudaMemcpy(wire_imag, d_vi, (size_t)s->n_wires * sizeof(u64), cudaMemcpyDeviceToHost) != cudaSuccess)
            return false;
    } else {
        for (int w = 0; w < s->n_wires; ++w) {
            if (cudaMemcpy(&wire_real[w], d_vr + (size_t)w * (size_t)stride, sizeof(u64),
                           cudaMemcpyDeviceToHost) != cudaSuccess)
                return false;
            if (cudaMemcpy(&wire_imag[w], d_vi + (size_t)w * (size_t)stride, sizeof(u64),
                           cudaMemcpyDeviceToHost) != cudaSuccess)
                return false;
        }
    }
    if (cudaMemcpy(beta_real, d_br, sizeof(u64), cudaMemcpyDeviceToHost) != cudaSuccess)
        return false;
    if (cudaMemcpy(beta_imag, d_bi, sizeof(u64), cudaMemcpyDeviceToHost) != cudaSuccess)
        return false;
    return true;
}

EarlySessionGpu* early_gpu_create(
    int n_gates,
    const int* gate_type, const int* in0, const int* in1,
    const u64* z1_real, const u64* z1_imag,
    int n_copies, int n_wires,
    const u64* values_real, const u64* values_imag,
    const u64* beta_real, const u64* beta_imag)
{
    if (n_gates <= 0 || n_wires <= 0 || n_copies < 2 || (n_copies & (n_copies - 1)) != 0)
        return nullptr;
    auto* s = new EarlySessionGpu();
    s->n_gates = n_gates;
    s->n_wires = n_wires;
    s->n_copies = n_copies;
    s->n_copies_cap = n_copies;
    const size_t vn = (size_t)n_wires * (size_t)n_copies;

    if (!s->gt.ensure((size_t)n_gates * sizeof(int)) ||
        !s->i0.ensure((size_t)n_gates * sizeof(int)) ||
        !s->i1.ensure((size_t)n_gates * sizeof(int)) ||
        !s->z1r.ensure((size_t)n_gates * sizeof(u64)) ||
        !s->z1i.ensure((size_t)n_gates * sizeof(u64)) ||
        !s->val_r.ensure(vn * sizeof(u64)) ||
        !s->val_i.ensure(vn * sizeof(u64)) ||
        !s->val2_r.ensure(vn * sizeof(u64)) ||
        !s->val2_i.ensure(vn * sizeof(u64)) ||
        !s->beta_r.ensure((size_t)n_copies * sizeof(u64)) ||
        !s->beta_i.ensure((size_t)n_copies * sizeof(u64)) ||
        !s->beta2_r.ensure((size_t)n_copies * sizeof(u64)) ||
        !s->beta2_i.ensure((size_t)n_copies * sizeof(u64))) {
        delete s;
        return nullptr;
    }

    if (cudaMemcpy(s->gt.as<int>(), gate_type, (size_t)n_gates * sizeof(int), cudaMemcpyHostToDevice) != cudaSuccess ||
        cudaMemcpy(s->i0.as<int>(), in0, (size_t)n_gates * sizeof(int), cudaMemcpyHostToDevice) != cudaSuccess ||
        cudaMemcpy(s->i1.as<int>(), in1, (size_t)n_gates * sizeof(int), cudaMemcpyHostToDevice) != cudaSuccess ||
        cudaMemcpy(s->z1r.as<u64>(), z1_real, (size_t)n_gates * sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess ||
        cudaMemcpy(s->z1i.as<u64>(), z1_imag, (size_t)n_gates * sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess ||
        cudaMemcpy(s->val_r.as<u64>(), values_real, vn * sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess ||
        cudaMemcpy(s->val_i.as<u64>(), values_imag, vn * sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess ||
        cudaMemcpy(s->beta_r.as<u64>(), beta_real, (size_t)n_copies * sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess ||
        cudaMemcpy(s->beta_i.as<u64>(), beta_imag, (size_t)n_copies * sizeof(u64), cudaMemcpyHostToDevice) != cudaSuccess) {
        delete s;
        return nullptr;
    }
    s->use_ping = false;
    return s;
}

enum class EarlyBackend { Gpu, Host };

struct EarlySession {
    EarlyBackend backend = EarlyBackend::Host;
    EarlySessionGpu* gpu = nullptr;
    native_fp2_core::EarlySessionHost* host = nullptr;
};

} // namespace

extern "C" {

int native_fp2_init(void) {
    std::call_once(g_init_once, init_once);
    return 0;
}

int native_fp2_cuda_available(void) {
    std::call_once(g_init_once, init_once);
    return g_cuda_ok ? 1 : 0;
}

void native_fp2_fold(
    const uint64_t* in_real, const uint64_t* in_imag, size_t n_out,
    uint64_t r_real, uint64_t r_imag,
    uint64_t* out_real, uint64_t* out_imag)
{
    std::call_once(g_init_once, init_once);
    if (g_cuda_ok && n_out >= kGpuFoldMin) {
        if (gpu_fold(as_u64(in_real), as_u64(in_imag), n_out, r_real, r_imag,
                     as_u64(out_real), as_u64(out_imag)))
            return;
    }
    native_fp2_core::fold(in_real, in_imag, n_out, r_real, r_imag, out_real, out_imag);
}

void native_fp2_expand(
    const uint64_t* in_real, const uint64_t* in_imag,
    size_t n_src, size_t ncopies,
    uint64_t* out_real, uint64_t* out_imag)
{
    std::call_once(g_init_once, init_once);
    if (g_cuda_ok && n_src * ncopies >= kGpuFoldMin) {
        if (gpu_expand(as_u64(in_real), as_u64(in_imag), n_src, ncopies,
                       as_u64(out_real), as_u64(out_imag)))
            return;
    }
    native_fp2_core::expand(in_real, in_imag, n_src, ncopies, out_real, out_imag);
}

void native_fp2_sumcheck_early(
    int n_gates,
    const int* gate_type, const int* in0, const int* in1,
    const uint64_t* z1_real, const uint64_t* z1_imag,
    int n_copies, int n_wires,
    const uint64_t* values_real, const uint64_t* values_imag,
    const uint64_t* fact0_real, const uint64_t* fact0_imag,
    const uint64_t* fact1_real, const uint64_t* fact1_imag,
    const uint64_t* beta_real, const uint64_t* beta_imag,
    const uint64_t* beta_f0_real, const uint64_t* beta_f0_imag,
    const uint64_t* beta_f1_real, const uint64_t* beta_f1_imag,
    uint64_t out8[8])
{
    std::call_once(g_init_once, init_once);
    if (g_cuda_ok && n_copies >= kGpuSumcheckMinCopies && n_gates > 0) {
        if (gpu_sumcheck_early(
                n_gates, gate_type, in0, in1, as_u64(z1_real), as_u64(z1_imag),
                n_copies, n_wires, as_u64(values_real), as_u64(values_imag),
                as_u64(fact0_real), as_u64(fact0_imag), as_u64(fact1_real), as_u64(fact1_imag),
                as_u64(beta_real), as_u64(beta_imag), as_u64(beta_f0_real), as_u64(beta_f0_imag),
                as_u64(beta_f1_real), as_u64(beta_f1_imag), as_u64(out8)))
            return;
    }
    native_fp2_core::sumcheck_early(
        n_gates, gate_type, in0, in1, z1_real, z1_imag,
        n_copies, n_wires, values_real, values_imag,
        fact0_real, fact0_imag, fact1_real, fact1_imag,
        beta_real, beta_imag, beta_f0_real, beta_f0_imag,
        beta_f1_real, beta_f1_imag, out8);
}

void native_fp2_compute_beta(
    const uint64_t* z_real, const uint64_t* z_imag, int n_z,
    uint64_t init_real, uint64_t init_imag,
    uint64_t* out_real, uint64_t* out_imag)
{
    std::call_once(g_init_once, init_once);
    if (g_cuda_ok && n_z >= kGpuBetaMinNz) {
        if (gpu_compute_beta(as_u64(z_real), as_u64(z_imag), n_z, init_real, init_imag,
                             as_u64(out_real), as_u64(out_imag)))
            return;
    }
    native_fp2_core::compute_beta(z_real, z_imag, n_z, init_real, init_imag, out_real, out_imag);
}

void native_fp2_mle_eval_base(
    const uint64_t* inputs,
    const uint64_t* z_real, const uint64_t* z_imag, int n_z,
    uint64_t* out_real, uint64_t* out_imag)
{
    std::call_once(g_init_once, init_once);
    if (g_cuda_ok && n_z >= kGpuMleMinNz) {
        if (gpu_mle_eval_base(as_u64(inputs), as_u64(z_real), as_u64(z_imag), n_z,
                              as_u64(out_real), as_u64(out_imag)))
            return;
    }
    native_fp2_core::mle_eval_base(inputs, z_real, z_imag, n_z, out_real, out_imag);
}

void* native_fp2_early_create(
    int n_gates,
    const int* gate_type, const int* in0, const int* in1,
    const uint64_t* z1_real, const uint64_t* z1_imag,
    int n_copies, int n_wires,
    const uint64_t* values_real, const uint64_t* values_imag,
    const uint64_t* beta_real, const uint64_t* beta_imag)
{
    std::call_once(g_init_once, init_once);
    auto* s = new EarlySession();
    if (g_cuda_ok) {
        s->gpu = early_gpu_create(
            n_gates, gate_type, in0, in1, as_u64(z1_real), as_u64(z1_imag),
            n_copies, n_wires, as_u64(values_real), as_u64(values_imag),
            as_u64(beta_real), as_u64(beta_imag));
        if (s->gpu) {
            s->backend = EarlyBackend::Gpu;
            return s;
        }
    }
    s->host = native_fp2_core::early_create(
        n_gates, gate_type, in0, in1, z1_real, z1_imag,
        n_copies, n_wires, values_real, values_imag, beta_real, beta_imag);
    if (!s->host) {
        delete s;
        return nullptr;
    }
    s->backend = EarlyBackend::Host;
    return s;
}

int native_fp2_early_claim(void* handle, uint64_t out8[8])
{
    auto* s = reinterpret_cast<EarlySession*>(handle);
    if (!s) return -1;
    if (s->backend == EarlyBackend::Gpu) {
        return early_gpu_claim(s->gpu, as_u64(out8)) ? 0 : -1;
    }
    native_fp2_core::early_claim(s->host, out8);
    return 0;
}

int native_fp2_early_fold(void* handle, uint64_t r_real, uint64_t r_imag)
{
    auto* s = reinterpret_cast<EarlySession*>(handle);
    if (!s) return -1;
    if (s->backend == EarlyBackend::Gpu) {
        return early_gpu_fold(s->gpu, r_real, r_imag) ? 0 : -1;
    }
    native_fp2_core::early_fold(s->host, r_real, r_imag);
    return 0;
}

int native_fp2_early_finish(
    void* handle,
    uint64_t* wire_real, uint64_t* wire_imag,
    uint64_t* beta_real, uint64_t* beta_imag)
{
    auto* s = reinterpret_cast<EarlySession*>(handle);
    if (!s) return -1;
    if (s->backend == EarlyBackend::Gpu) {
        return early_gpu_finish(s->gpu, as_u64(wire_real), as_u64(wire_imag),
                                as_u64(beta_real), as_u64(beta_imag)) ? 0 : -1;
    }
    native_fp2_core::early_finish(s->host, wire_real, wire_imag, beta_real, beta_imag);
    return 0;
}

int native_fp2_early_n_copies(void* handle)
{
    auto* s = reinterpret_cast<EarlySession*>(handle);
    if (!s) return 0;
    if (s->backend == EarlyBackend::Gpu) return s->gpu->n_copies;
    return s->host->n_copies;
}

int native_fp2_early_n_wires(void* handle)
{
    auto* s = reinterpret_cast<EarlySession*>(handle);
    if (!s) return 0;
    if (s->backend == EarlyBackend::Gpu) return s->gpu->n_wires;
    return s->host->n_wires;
}

void native_fp2_early_destroy(void* handle)
{
    auto* s = reinterpret_cast<EarlySession*>(handle);
    if (!s) return;
    if (s->gpu) {
        delete s->gpu;
        s->gpu = nullptr;
    }
    if (s->host) {
        native_fp2_core::early_destroy(s->host);
        s->host = nullptr;
    }
    delete s;
}

}  // extern "C"
