/*
 * native_fp2.cpp — CPU path for GKR Fp2 batch kernels.
 *
 * Uses h100-fp61 arithmetic (fp61.cuh host path). Does NOT link Orion.
 * Prefer native_fp2.cu when nvcc is available (GPU + same fp61 ops).
 */
#include "native_fp2_core.hpp"

#include <cstdint>

extern "C" {

int native_fp2_init(void) { return 0; }

int native_fp2_cuda_available(void) { return 0; }

void native_fp2_fold(
    const uint64_t* in_real,
    const uint64_t* in_imag,
    size_t n_out,
    uint64_t r_real,
    uint64_t r_imag,
    uint64_t* out_real,
    uint64_t* out_imag)
{
    native_fp2_core::fold(in_real, in_imag, n_out, r_real, r_imag, out_real, out_imag);
}

void native_fp2_expand(
    const uint64_t* in_real,
    const uint64_t* in_imag,
    size_t n_src,
    size_t ncopies,
    uint64_t* out_real,
    uint64_t* out_imag)
{
    native_fp2_core::expand(in_real, in_imag, n_src, ncopies, out_real, out_imag);
}

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
    native_fp2_core::sumcheck_early(
        n_gates, gate_type, in0, in1, z1_real, z1_imag,
        n_copies, n_wires, values_real, values_imag,
        fact0_real, fact0_imag, fact1_real, fact1_imag,
        beta_real, beta_imag, beta_f0_real, beta_f0_imag,
        beta_f1_real, beta_f1_imag, out8);
}

void native_fp2_compute_beta(
    const uint64_t* z_real,
    const uint64_t* z_imag,
    int n_z,
    uint64_t init_real,
    uint64_t init_imag,
    uint64_t* out_real,
    uint64_t* out_imag)
{
    native_fp2_core::compute_beta(z_real, z_imag, n_z, init_real, init_imag, out_real, out_imag);
}

void native_fp2_mle_eval_base(
    const uint64_t* inputs,
    const uint64_t* z_real,
    const uint64_t* z_imag,
    int n_z,
    uint64_t* out_real,
    uint64_t* out_imag)
{
    native_fp2_core::mle_eval_base(inputs, z_real, z_imag, n_z, out_real, out_imag);
}

void* native_fp2_early_create(
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
    const uint64_t* beta_real,
    const uint64_t* beta_imag)
{
    return native_fp2_core::early_create(
        n_gates, gate_type, in0, in1, z1_real, z1_imag,
        n_copies, n_wires, values_real, values_imag, beta_real, beta_imag);
}

int native_fp2_early_claim(void* handle, uint64_t out8[8])
{
    auto* s = reinterpret_cast<native_fp2_core::EarlySessionHost*>(handle);
    if (!s) return -1;
    native_fp2_core::early_claim(s, out8);
    return 0;
}

int native_fp2_early_fold(void* handle, uint64_t r_real, uint64_t r_imag)
{
    auto* s = reinterpret_cast<native_fp2_core::EarlySessionHost*>(handle);
    if (!s) return -1;
    native_fp2_core::early_fold(s, r_real, r_imag);
    return 0;
}

int native_fp2_early_finish(
    void* handle,
    uint64_t* wire_real,
    uint64_t* wire_imag,
    uint64_t* beta_real,
    uint64_t* beta_imag)
{
    auto* s = reinterpret_cast<native_fp2_core::EarlySessionHost*>(handle);
    if (!s) return -1;
    native_fp2_core::early_finish(s, wire_real, wire_imag, beta_real, beta_imag);
    return 0;
}

int native_fp2_early_n_copies(void* handle)
{
    auto* s = reinterpret_cast<native_fp2_core::EarlySessionHost*>(handle);
    return s ? s->n_copies : 0;
}

int native_fp2_early_n_wires(void* handle)
{
    auto* s = reinterpret_cast<native_fp2_core::EarlySessionHost*>(handle);
    return s ? s->n_wires : 0;
}

void native_fp2_early_destroy(void* handle)
{
    native_fp2_core::early_destroy(
        reinterpret_cast<native_fp2_core::EarlySessionHost*>(handle));
}

}  // extern "C"
