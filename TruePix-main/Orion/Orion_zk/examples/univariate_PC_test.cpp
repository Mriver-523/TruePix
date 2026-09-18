#include <cstdio>
#include <chrono>
#include "linear_code/linear_code_encode.h"
#include "VPD/linearPC.h"
#include "x86intrin.h"
#define timer_mark(x) auto x = std::chrono::high_resolution_clock::now()
#define time_diff(start, end) (std::chrono::duration_cast<std::chrono::duration<double>>(end - start).count())
//void print_hhash_digest(const __hhash_digest &digest) {
    // NOTE: translated from original Chinese comment.
 //   alignas(16) unsigned char h0_bytes[16];
   // alignas(16) unsigned char h1_bytes[16];
    //_mm_store_si128((__m128i *)h0_bytes, digest.h0);
//    _mm_store_si128((__m128i *)h1_bytes, digest.h1);

 //   printf("h0: ");
 //   for (int i = 0; i < 16; ++i) {
 //       printf("%02x", h0_bytes[i]);
   // }
   // printf("\n");

    //printf("h1: ");
    //for (int i = 0; i < 16; ++i) {
 //       printf("%02x", h1_bytes[i]);
 //   }
 //   printf("\n");
//}
void print_hhash_digest(const __hhash_digest &digest) {
    // NOTE: translated from original Chinese comment.
    uint64_t h0_low  = _mm_extract_epi64(digest.h0, 0);
    uint64_t h0_high = _mm_extract_epi64(digest.h0, 1);
    // NOTE: translated from original Chinese comment.
    uint64_t h1_low  = _mm_extract_epi64(digest.h1, 0);
    uint64_t h1_high = _mm_extract_epi64(digest.h1, 1);

    // NOTE: translated from original Chinese comment.
    printf("Merkle  Hash:\n");
    printf("h0(high): 0x%lx ", h0_high);
    printf("h0(low):  0x%lx ", h0_low);
    printf("h1(high): 0x%lx ", h1_high);
    printf("h1(low):  0x%lx ", h1_low);
    printf("\n");
}

int main(int argc, char* argv[])
{
    int N, lg_N;
    sscanf(argv[1], "%d", &lg_N);
    N = 1 << lg_N;

    expander_init(N / column_size);

    prime_field::field_element *coefs = new prime_field::field_element[N];
    for(int i = 0; i < N; ++i)
        coefs[i] = prime_field::random();
    
        
    timer_mark(commit_t0);
    auto h = commit(coefs, N);
    timer_mark(commit_t1);
    printf("Merkle Tree Hashes:\n");
    for (int i = 0; i < N / column_size * 2 ; ++i) {
        printf("Index %d:\n", i);
        print_hhash_digest(h[i]);
    }
    
    timer_mark(open_t0);
    auto result = open_and_verify(prime_field::random(), N, h);
    timer_mark(open_t1);
    printf("Commit time %lf\n", time_diff(commit_t0, commit_t1));
    printf("Open time %lf\n", time_diff(open_t0, open_t1) - last_encode_preprocess_time);
    printf("%s\n", result.second ? "succ" : "fail");
    return 0;
}