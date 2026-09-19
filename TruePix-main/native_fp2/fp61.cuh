#pragma once
// Portable Fp / Fp2 arithmetic for p = 2^61 - 1 (from h100-fp61).
// Compiles as __host__ __device__ under nvcc, and as plain C++ host otherwise.
// All public field inputs/outputs are canonical [0,P), unless stated otherwise.
// Extension basis: i^2 = -1. No constant-time machine-code guarantee is made.

#if defined(__CUDACC__)
#include <cuda_runtime.h>
#define F61_INLINE __host__ __device__ __forceinline__
#else
#define F61_INLINE inline
#endif

namespace fp61 {
using u32 = unsigned int;
using u64 = unsigned long long;
static constexpr u64 P = (1ULL << 61) - 1;

F61_INLINE u64 umul64hi(u64 a, u64 b) {
#if defined(__CUDA_ARCH__)
    return __umul64hi(a, b);
#elif defined(__SIZEOF_INT128__)
    return (u64)(((unsigned __int128)a * (unsigned __int128)b) >> 64);
#else
    const u64 a0 = (u32)a, a1 = a >> 32;
    const u64 b0 = (u32)b, b1 = b >> 32;
    const u64 p0 = a0 * b0;
    const u64 p1 = a0 * b1;
    const u64 p2 = a1 * b0;
    const u64 p3 = a1 * b1;
    const u64 mid = (p0 >> 32) + (u32)p1 + (u32)p2;
    return p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32);
#endif
}

F61_INLINE u64 canon(u64 x) { // requires x < 2P
    return x >= P ? x - P : x;
}
F61_INLINE u64 reduce64(u64 x) { // any unsigned 64-bit input
    return canon((x & P) + (x >> 61));
}
F61_INLINE u64 add(u64 a, u64 b) { return canon(a + b); }
F61_INLINE u64 sub(u64 a, u64 b) { return canon(a + P - b); }
F61_INLINE u64 neg(u64 a) { return a ? P - a : 0; }

F61_INLINE u64 mul_u64(u64 a, u64 b) {
    const u64 lo = a * b;
    const u64 hi = umul64hi(a, b);
    return canon((lo & P) + ((lo >> 61) | (hi << 3)));
}

// a<2^61 makes a<<3 exact in u64. High64((8a)*b)=floor(ab/2^61).
F61_INLINE u64 mul_shift64(u64 a, u64 b) {
    return canon(((a * b) & P) + umul64hi(a << 3, b));
}

F61_INLINE u64 wide32(u32 a, u32 b) {
#if defined(__CUDA_ARCH__)
    u64 r;
    asm("mul.wide.u32 %0, %1, %2;" : "=l"(r) : "r"(a), "r"(b));
    return r;
#else
    return (u64)a * (u64)b;
#endif
}

// Four 32x32->64 partial products; reduce them without constructing 128 bits.
F61_INLINE u64 mul_split32(u64 a, u64 b) {
    const u32 a0 = (u32)a, a1 = (u32)(a >> 32);
    const u32 b0 = (u32)b, b1 = (u32)(b >> 32);
    const u64 z0 = wide32(a0, b0);
    const u64 z1 = wide32(a0, b1) + wide32(a1, b0); // < 2^62
    const u64 z2 = wide32(a1, b1);                   // < 2^58
    const u64 s = (z0 & P) + (z0 >> 61)
                + ((z1 & ((1ULL << 29) - 1)) << 32)
                + (z1 >> 29) + (z2 << 3);            // < 2^63
    return reduce64(s);
}

// Deliberately wider contract: 0 <= a,b < 2P. Output is canonical.
F61_INLINE u64 mul_sum62(u64 a, u64 b) {
    const u64 lo = a * b;
    const u64 hi = umul64hi(a, b);
    return reduce64((lo & P) + ((lo >> 61) | (hi << 3)));
}

template<int Backend = 0>
F61_INLINE u64 mul(u64 a, u64 b) {
    static_assert(Backend >= 0 && Backend <= 2, "backend 0=u64, 1=split32, 2=shift64");
    if constexpr (Backend == 0) return mul_u64(a, b);
    else if constexpr (Backend == 1) return mul_split32(a, b);
    else return mul_shift64(a, b);
}

struct Fp2 { u64 re, im; };
F61_INLINE Fp2 add2(Fp2 a, Fp2 b) { return {add(a.re, b.re), add(a.im, b.im)}; }
F61_INLINE Fp2 sub2(Fp2 a, Fp2 b) { return {sub(a.re, b.re), sub(a.im, b.im)}; }
F61_INLINE Fp2 conjugate(Fp2 a) { return {a.re, neg(a.im)}; }
F61_INLINE Fp2 from_base(u64 x) { return {reduce64(x), 0}; }

// Variant 0: u64+3M (default GKR baseline), 1: split32+3M, 2: u64+4M,
//         3: split32+4M, 4: u64+3M delayed reduce, 5: shift64+3M.
template<int Variant = 0>
F61_INLINE Fp2 mul2(Fp2 a, Fp2 b) {
    static_assert(Variant >= 0 && Variant <= 5, "invalid variant");
    constexpr int B = Variant == 5 ? 2 : (Variant == 1 || Variant == 3 ? 1 : 0);
    const u64 ac = mul<B>(a.re, b.re);
    const u64 bd = mul<B>(a.im, b.im);
    if constexpr (Variant == 2 || Variant == 3) {
        const u64 ad = mul<B>(a.re, b.im);
        const u64 bc = mul<B>(a.im, b.re);
        return {sub(ac, bd), add(ad, bc)};
    } else {
        u64 w;
        if constexpr (Variant == 4) w = mul_sum62(a.re + a.im, b.re + b.im);
        else w = mul<B>(add(a.re, a.im), add(b.re, b.im));
        return {sub(ac, bd), sub(sub(w, ac), bd)};
    }
}

template<int B = 0>
F61_INLINE Fp2 square2(Fp2 a) {
    const u64 ab = mul<B>(a.re, a.im);
    return {mul<B>(add(a.re, a.im), sub(a.re, a.im)), add(ab, ab)};
}

template<int N, int B>
F61_INLINE u64 square_n(u64 a) {
#if defined(__CUDA_ARCH__)
#pragma unroll
#endif
    for (int j = 0; j < N; ++j) a = mul<B>(a, a);
    return a;
}

template<int B = 0>
F61_INLINE u64 inverse_nonzero(u64 a) {
    const u64 t2 = mul<B>(square_n<1, B>(a), a);
    const u64 t4 = mul<B>(square_n<2, B>(t2), t2);
    const u64 t8 = mul<B>(square_n<4, B>(t4), t4);
    const u64 t16 = mul<B>(square_n<8, B>(t8), t8);
    const u64 t32 = mul<B>(square_n<16, B>(t16), t16);
    const u64 t48 = mul<B>(square_n<16, B>(t32), t16);
    const u64 t56 = mul<B>(square_n<8, B>(t48), t8);
    const u64 t58 = mul<B>(square_n<2, B>(t56), t2);
    const u64 t59 = mul<B>(square_n<1, B>(t58), a);
    return mul<B>(square_n<2, B>(t59), a); // exponent 2^61 - 3 = P-2
}

template<int B = 0>
F61_INLINE bool inverse2(Fp2 a, Fp2& out) {
    if ((a.re | a.im) == 0) { out = {0, 0}; return false; }
    const u64 norm = add(mul<B>(a.re, a.re), mul<B>(a.im, a.im));
    const u64 inv = inverse_nonzero<B>(norm);
    out = {mul<B>(a.re, inv), neg(mul<B>(a.im, inv))};
    return true;
}

// Default GKR variant: u64 wide mul + 3M Karatsuba (回答.docx / README baseline).
constexpr int GKR_VARIANT = 0;

F61_INLINE Fp2 gkr_mul(Fp2 a, Fp2 b) { return mul2<GKR_VARIANT>(a, b); }
F61_INLINE Fp2 gkr_add(Fp2 a, Fp2 b) { return add2(a, b); }
F61_INLINE Fp2 gkr_sub(Fp2 a, Fp2 b) { return sub2(a, b); }

} // namespace fp61

#undef F61_INLINE
