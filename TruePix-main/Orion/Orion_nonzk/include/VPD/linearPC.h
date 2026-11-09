#pragma once
#include "linear_gkr/prime_field.h"
#include "infrastructure/merkle_tree.h"

// Folding/query extraction from the compact commit-time encoded matrix.
// Counted as preprocess, not as Open / Input Prove Time.
extern double last_encode_preprocess_time;
// Prove binaries enable this only for their local recommit.
void set_retain_encoded_codeword(bool enabled);

//commit
__hhash_digest* commit(const prime_field::field_element *src, long long N);
//open

//verify
std::pair<prime_field::field_element, bool> open_and_verify(prime_field::field_element x, long long N, __hhash_digest *com_mt);
std::pair<prime_field::field_element, bool> open_and_verify(prime_field::field_element *r, int size_r, int N, __hhash_digest *com_mt);

/**
 * NIZK verify-only: check orion_proof.bin against commitment root + point.
 * Does not require the original coefficient vector / input.txt.
 */
std::pair<prime_field::field_element, bool> verify_opening_proof(
    prime_field::field_element *r, int size_r, int N,
    const __hhash_digest &expected_root,
    const char *proof_path);

