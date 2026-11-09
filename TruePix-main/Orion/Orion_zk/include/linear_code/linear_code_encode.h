#pragma once
#include <cstdio>
#include <cstdlib>
#include "expanders.h"

extern prime_field::field_element *scratch[2][100];

extern bool __encode_initialized;

inline bool encode_fe_is_zero(const prime_field::field_element &v)
{
    return v.real == 0 && v.img == 0;
}

// Codeword length of encode(n). Depends only on the expander shape.
inline long long encode_output_len(long long n, int dep = 0)
{
    if(n <= distance_threshold)
        return n;
    long long R = (long long)(alpha * n);
    long long L = encode_output_len(R, dep + 1);
    return n + L + D[dep].R;
}

inline void encode_ensure_scratch(long long n)
{
    if(__encode_initialized)
        return;
    __encode_initialized = true;
    for(int i = 0; (n >> i) > 1; ++i)
    {
        scratch[0][i] = new prime_field::field_element[2 * n >> i];
        scratch[1][i] = new prime_field::field_element[2 * n >> i];
    }
}

inline int encode(const prime_field::field_element *src, prime_field::field_element *dst, long long n, int dep = 0)
{
    encode_ensure_scratch(n);
    bool all_zero = true;
    for(long long i = 0; i < n; ++i)
    {
        if(!encode_fe_is_zero(src[i]))
        {
            all_zero = false;
            break;
        }
    }
    if(all_zero)
    {
        long long len = encode_output_len(n, dep);
        for(long long i = 0; i < len; ++i)
            dst[i] = prime_field::field_element(0ULL);
        return (int)len;
    }
    if(n <= distance_threshold)
    {
        for(long long i = 0; i < n; ++i)
            dst[i] = src[i];
        return n;
    }
    for(long long i = 0; i < n; ++i)
    {
        scratch[0][dep][i] = src[i];
    }
    long long R = alpha * n;
    for(long long j = 0; j < R; ++j)
        scratch[1][dep][j] = prime_field::field_element(0ULL);
    //expander mult
    for(long long i = 0; i < n; ++i)
    {
        const prime_field::field_element &val = src[i];
        if(encode_fe_is_zero(val))
            continue;
        for(int d = 0; d < C[dep].degree; ++d)
        {
            int target = C[dep].neighbor[i][d];
            scratch[1][dep][target] = scratch[1][dep][target] + C[dep].weight[i][d] * val;
        }
    }
    long long L = encode(scratch[1][dep], &scratch[0][dep][n], R, dep + 1);
    assert(D[dep].L = L);
    R = D[dep].R;
    for(long long i = 0; i < R; ++i)
    {
        scratch[0][dep][n + L + i] = prime_field::field_element(0ULL);
    }
    for(long long i = 0; i < L; ++i)
    {
        prime_field::field_element &val = scratch[0][dep][n + i];
        if(encode_fe_is_zero(val))
            continue;
        for(int d = 0; d < D[dep].degree; ++d)
        {
            long long target = D[dep].neighbor[i][d];
            scratch[0][dep][n + L + target] = scratch[0][dep][n + L + target] + val * D[dep].weight[i][d];
        }
    }
    for(long long i = 0; i < n + L + R; ++i)
    {
        dst[i] = scratch[0][dep][i];
    }
    return n + L + R;
}

// Finish one codeword after the top-level expander accumulation (length R)
// is already stored in acc_R. The recursive tail matches encode() at dep.
inline int encode_finish_from_R(
    const prime_field::field_element *msg, long long n,
    prime_field::field_element *acc_R, long long R,
    prime_field::field_element *dst, int dep)
{
    // Reused across columns. encode() is already single-threaded and uses
    // global scratch, so a process-lifetime buffer does not change the result.
    static prime_field::field_element *child = nullptr;
    static long long child_cap = 0;
    if(child_cap < n)
    {
        delete[] child;
        child = new prime_field::field_element[n];
        child_cap = n;
    }
    long long L = encode(acc_R, child, R, dep + 1);
    assert(L <= n);
    assert(D[dep].L = L);
    long long parity = D[dep].R;
    for(long long i = 0; i < n; ++i)
        dst[i] = msg[i];
    for(long long i = 0; i < L; ++i)
        dst[n + i] = child[i];
    for(long long i = 0; i < parity; ++i)
        dst[n + L + i] = prime_field::field_element(0ULL);
    for(long long i = 0; i < L; ++i)
    {
        if(encode_fe_is_zero(child[i]))
            continue;
        for(int d = 0; d < D[dep].degree; ++d)
        {
            long long target = D[dep].neighbor[i][d];
            dst[n + L + target] = dst[n + L + target] + child[i] * D[dep].weight[i][d];
        }
    }
    return (int)(n + L + parity);
}

// Top-level encode of two polynomials. The first expander layer walks each
// column once: a source that is zero in both inputs is skipped, and the
// neighbor list is not read twice. Deeper layers stay separate.
inline int encode_pair(
    const prime_field::field_element *src_a, prime_field::field_element *dst_a,
    const prime_field::field_element *src_b, prime_field::field_element *dst_b,
    long long n)
{
    encode_ensure_scratch(n);
    if(n <= distance_threshold)
    {
        for(long long i = 0; i < n; ++i)
        {
            dst_a[i] = src_a[i];
            dst_b[i] = src_b[i];
        }
        return (int)n;
    }
    long long R = (long long)(alpha * n);
    static prime_field::field_element *acc_a = nullptr;
    static prime_field::field_element *acc_b = nullptr;
    static long long acc_cap = 0;
    if(acc_cap < R)
    {
        delete[] acc_a;
        delete[] acc_b;
        acc_a = new prime_field::field_element[R];
        acc_b = new prime_field::field_element[R];
        acc_cap = R;
    }
    for(long long j = 0; j < R; ++j)
    {
        acc_a[j] = prime_field::field_element(0ULL);
        acc_b[j] = prime_field::field_element(0ULL);
    }
    for(long long i = 0; i < n; ++i)
    {
        bool za = encode_fe_is_zero(src_a[i]);
        bool zb = encode_fe_is_zero(src_b[i]);
        if(za && zb)
            continue;
        for(int d = 0; d < C[0].degree; ++d)
        {
            int target = C[0].neighbor[i][d];
            const prime_field::field_element &w = C[0].weight[i][d];
            if(!za)
                acc_a[target] = acc_a[target] + w * src_a[i];
            if(!zb)
                acc_b[target] = acc_b[target] + w * src_b[i];
        }
    }
    int len_a = encode_finish_from_R(src_a, n, acc_a, R, dst_a, 0);
    int len_b = encode_finish_from_R(src_b, n, acc_b, R, dst_b, 0);
    if(len_a != len_b)
    {
        fprintf(stderr, "encode_pair: codeword lengths differ (%d vs %d)\n", len_a, len_b);
        exit(1);
    }
    return len_a;
}