#pragma once
/**
 * Binary opening proof for Orion TruePix NIZK mode.
 *
 * Layout (little-endian), version 2:
 *   magic[8] = "ORIONPV1"
 *   version u32 = 2
 *   use_group1 u32
 *   N u64, column_size u64, msg_len u64, cw_len u64, query_count u32
 *   answer: field_element (real, img)
 *   com_root: __hhash_digest
 *   combined_root: __hhash_digest
 *   col_q[query_count]: i64
 *   queried_cols[query_count * column_size]: field_element
 *   combined_codeword[cw_len]: field_element
 *   combined_message[msg_len]: field_element
 *   com_mt_n u64 + (idx u32 + digest)[com_mt_n]   // sparse Merkle siblings
 *   combined_mt_n u64 + (idx u32 + digest)[combined_mt_n]
 *
 * Version 1 stored full Merkle arrays; v2 keeps only the sibling nodes needed
 * for the opening queries (same verify semantics, far less RSS / disk).
 */
#include "infrastructure/merkle_tree.h"
#include "linear_gkr/prime_field.h"
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace truepix_orion {

struct OpeningProof {
    uint32_t version = 2;
    uint32_t use_group1 = 1;
    uint64_t N = 0;
    uint64_t column_size = 0;
    uint64_t msg_len = 0;
    uint64_t cw_len = 0;
    uint32_t query_count = 0;
    prime_field::field_element answer{};
    __hhash_digest com_root{};
    __hhash_digest combined_root{};
    std::vector<long long> col_q;
    std::vector<prime_field::field_element> queried_cols;
    std::vector<prime_field::field_element> combined_codeword;
    std::vector<prime_field::field_element> combined_message;
    // Sparse Merkle authentication paths (sibling index + digest).
    std::vector<uint32_t> com_mt_idx;
    std::vector<__hhash_digest> com_mt;
    std::vector<uint32_t> combined_mt_idx;
    std::vector<__hhash_digest> combined_mt;

    bool write_file(const std::string &path) const;
    bool read_file(const std::string &path);
    size_t byte_size() const;

    std::unordered_map<uint32_t, __hhash_digest> com_mt_map() const;
    std::unordered_map<uint32_t, __hhash_digest> combined_mt_map() const;
};

// Collect unique Merkle siblings for the given leaf positions (same set
// verify_claim would read from a full tree).
void collect_merkle_siblings(const __hhash_digest *tree, int N_leaves,
                             const long long *positions, int npos,
                             std::vector<uint32_t> &idxs,
                             std::vector<__hhash_digest> &digests);

// Path verify equivalent to merkle_tree_verifier::verify_claim.
bool verify_claim_sparse(
    __hhash_digest root_hhash,
    const std::unordered_map<uint32_t, __hhash_digest> &tree,
    __hhash_digest leaf_hash, int pos_element_arr, int N,
    std::unordered_map<uint32_t, bool> &visited, long long &proof_size);

std::string default_proof_path();

} // namespace truepix_orion
