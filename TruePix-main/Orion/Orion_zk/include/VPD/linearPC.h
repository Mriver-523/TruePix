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

// Commit masked and mask together. The first expander layer is shared;
// each polynomial still gets its own Merkle tree.
struct zk_pair_commit
{
    __hhash_digest *mt_masked;
    __hhash_digest *mt_mask;
};
zk_pair_commit commit_pair(const prime_field::field_element *masked,
                           const prime_field::field_element *mask_poly,
                           long long N);
// Install the message columns that the next open_and_verify folds.
// codeword_size must already have been set by commit() or commit_pair().
void bind_open_message(const prime_field::field_element *src, long long N);
//open

//verify (interactive or NIZK prove-side that also emits orion_proof.bin)
std::pair<prime_field::field_element, bool> open_and_verify(prime_field::field_element x, long long N, __hhash_digest *com_mt,bool use_group1);
std::pair<prime_field::field_element, bool> open_and_verify(prime_field::field_element *r, int size_r, int N, __hhash_digest *com_mt,bool use_group1);

/**
 * NIZK verify-only: check orion_proof.bin against commitment root + point.
 * Does not require the original coefficient vector / input.txt.
 */
std::pair<prime_field::field_element, bool> verify_opening_proof(
    prime_field::field_element *r, int size_r, int N,
    const __hhash_digest &expected_root, bool use_group1,
    const char *proof_path);


