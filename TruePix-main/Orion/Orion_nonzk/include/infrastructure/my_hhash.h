#ifndef __hhash
#define __hhash

/**extra 'h' before hhash can avoid some strange error by the compiler*/

#include <immintrin.h>
#include <wmmintrin.h>
#include <cassert>
#include "flo-shani-aesni/sha256/flo-shani.h"
#include <cstdio>
//#define USESHA3
#ifdef USESHA3
extern "C"{
#include "lib/libXKCP.a.headers/SimpleFIPS202.h"
}
#endif

class __hhash_digest
{
public:
    __m128i h0, h1;
    void print() const {
        // NOTE: translated from original Chinese comment.
        uint64_t h0_low  = _mm_extract_epi64(h0, 0);
        uint64_t h0_high = _mm_extract_epi64(h0, 1);
        // NOTE: translated from original Chinese comment.
        uint64_t h1_low  = _mm_extract_epi64(h1, 0);
        uint64_t h1_high = _mm_extract_epi64(h1, 1);

        // NOTE: translated from original Chinese comment.
        printf("Merkle Root Hash:\n");
        printf("h0 (low):  0x%lx\n", h0_low);
        printf("h0 (high): 0x%lx\n", h0_high);
        printf("h1 (low):  0x%lx\n", h1_low);
        printf("h1 (high): 0x%lx\n", h1_high);
    }
};

inline bool equals(const __hhash_digest &a, const __hhash_digest &b)
{
    __m128i v0 = _mm_xor_si128(a.h0, b.h0);
    __m128i v1 = _mm_xor_si128(a.h1, b.h1);
    return _mm_test_all_zeros(v0, v0) && _mm_test_all_zeros(v1, v1);
}
#include <cstring>
inline void my_hhash(const void* src, void* dst)
{
#ifdef USESHA3
    SHA3_256((unsigned char*)dst, (const unsigned char*)src, 64);
#else
    //memset(dst, 0, sizeof(__hhash_digest));
    sha256_update_shani((const unsigned char*)src, 64, (unsigned char*)dst);
#endif
}

#endif
