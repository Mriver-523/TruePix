#pragma once
#include "linear_gkr/prime_field.h"
#include "infrastructure/merkle_tree.h"

// Streaming re-encode done inside open to avoid keeping encoded_codeword.
// Counted as preprocess, not as Open / Input Prove Time.
extern double last_encode_preprocess_time;

//commit
__hhash_digest* commit(const prime_field::field_element *src, long long N);
//open

//verify
std::pair<prime_field::field_element, bool> open_and_verify(prime_field::field_element x, long long N, __hhash_digest *com_mt,bool use_group1);
std::pair<prime_field::field_element, bool> open_and_verify(prime_field::field_element *r, int size_r, int N, __hhash_digest *com_mt,bool use_group1);


