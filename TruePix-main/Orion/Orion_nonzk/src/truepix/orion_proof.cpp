#include "truepix/orion_proof.h"
#include "infrastructure/my_hhash.h"
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <vector>

namespace truepix_orion {

static const char kMagic[8] = {'O', 'R', 'I', 'O', 'N', 'P', 'V', '1'};

std::string default_proof_path() {
    const char *e = std::getenv("TRUEPIX_ORION_PROOF_FILE");
    if (e && e[0])
        return std::string(e);
    return "orion_proof.bin";
}

size_t OpeningProof::byte_size() const {
    return 8 + 4 + 4 + 8 * 4 + 4 + sizeof(answer) + sizeof(com_root) +
           sizeof(combined_root) + col_q.size() * 8 +
           queried_cols.size() * sizeof(prime_field::field_element) +
           combined_codeword.size() * sizeof(prime_field::field_element) +
           combined_message.size() * sizeof(prime_field::field_element) + 8 +
           com_mt_idx.size() * (sizeof(uint32_t) + sizeof(__hhash_digest)) + 8 +
           combined_mt_idx.size() * (sizeof(uint32_t) + sizeof(__hhash_digest));
}

template <typename T>
static void put(std::ostream &os, const T &v) {
    os.write(reinterpret_cast<const char *>(&v), sizeof(T));
}

template <typename T>
static bool get(std::istream &is, T &v) {
    is.read(reinterpret_cast<char *>(&v), sizeof(T));
    return static_cast<bool>(is);
}

static bool write_sparse_mt(std::ostream &os, const std::vector<uint32_t> &idxs,
                            const std::vector<__hhash_digest> &digests) {
    if (idxs.size() != digests.size())
        return false;
    uint64_t n = idxs.size();
    put(os, n);
    for (size_t i = 0; i < idxs.size(); ++i) {
        put(os, idxs[i]);
        put(os, digests[i]);
    }
    return static_cast<bool>(os);
}

static bool read_sparse_mt(std::istream &is, std::vector<uint32_t> &idxs,
                           std::vector<__hhash_digest> &digests) {
    uint64_t n = 0;
    if (!get(is, n))
        return false;
    idxs.resize(n);
    digests.resize(n);
    for (uint64_t i = 0; i < n; ++i) {
        if (!get(is, idxs[i]) || !get(is, digests[i]))
            return false;
    }
    return true;
}

bool OpeningProof::write_file(const std::string &path) const {
    std::ofstream os(path, std::ios::binary);
    if (!os)
        return false;
    os.write(kMagic, 8);
    put(os, version);
    put(os, use_group1);
    put(os, N);
    put(os, column_size);
    put(os, msg_len);
    put(os, cw_len);
    put(os, query_count);
    put(os, answer);
    put(os, com_root);
    put(os, combined_root);
    for (auto q : col_q)
        put(os, q);
    for (const auto &fe : queried_cols)
        put(os, fe);
    for (const auto &fe : combined_codeword)
        put(os, fe);
    for (const auto &fe : combined_message)
        put(os, fe);
    if (!write_sparse_mt(os, com_mt_idx, com_mt))
        return false;
    if (!write_sparse_mt(os, combined_mt_idx, combined_mt))
        return false;
    return static_cast<bool>(os);
}

bool OpeningProof::read_file(const std::string &path) {
    std::ifstream is(path, std::ios::binary);
    if (!is)
        return false;
    char magic[8];
    is.read(magic, 8);
    if (std::memcmp(magic, kMagic, 8) != 0)
        return false;
    if (!get(is, version) || version != 2)
        return false;
    if (!get(is, use_group1))
        return false;
    if (!get(is, N) || !get(is, column_size) || !get(is, msg_len) ||
        !get(is, cw_len) || !get(is, query_count))
        return false;
    if (!get(is, answer) || !get(is, com_root) || !get(is, combined_root))
        return false;
    col_q.resize(query_count);
    for (uint32_t i = 0; i < query_count; ++i)
        if (!get(is, col_q[i]))
            return false;
    queried_cols.resize(static_cast<size_t>(query_count) * column_size);
    for (auto &fe : queried_cols)
        if (!get(is, fe))
            return false;
    combined_codeword.resize(cw_len);
    for (auto &fe : combined_codeword)
        if (!get(is, fe))
            return false;
    combined_message.resize(msg_len);
    for (auto &fe : combined_message)
        if (!get(is, fe))
            return false;
    if (!read_sparse_mt(is, com_mt_idx, com_mt))
        return false;
    if (!read_sparse_mt(is, combined_mt_idx, combined_mt))
        return false;
    return true;
}

std::unordered_map<uint32_t, __hhash_digest> OpeningProof::com_mt_map() const {
    std::unordered_map<uint32_t, __hhash_digest> m;
    m.reserve(com_mt_idx.size());
    for (size_t i = 0; i < com_mt_idx.size(); ++i)
        m.emplace(com_mt_idx[i], com_mt[i]);
    return m;
}

std::unordered_map<uint32_t, __hhash_digest> OpeningProof::combined_mt_map() const {
    std::unordered_map<uint32_t, __hhash_digest> m;
    m.reserve(combined_mt_idx.size());
    for (size_t i = 0; i < combined_mt_idx.size(); ++i)
        m.emplace(combined_mt_idx[i], combined_mt[i]);
    return m;
}

void collect_merkle_siblings(const __hhash_digest *tree, int N_leaves,
                             const long long *positions, int npos,
                             std::vector<uint32_t> &idxs,
                             std::vector<__hhash_digest> &digests) {
    idxs.clear();
    digests.clear();
    // Tree array length is 2 * N_leaves for a power-of-two leaf count.
    const int tree_cap = N_leaves * 2;
    std::vector<char> seen((size_t)tree_cap, 0);
    for (int i = 0; i < npos; ++i) {
        int pos_element = (int)positions[i] + N_leaves;
        while (pos_element != 1) {
            int sib = pos_element ^ 1;
            if (sib >= 0 && sib < tree_cap && !seen[(size_t)sib]) {
                seen[(size_t)sib] = 1;
                idxs.push_back((uint32_t)sib);
                digests.push_back(tree[sib]);
            }
            pos_element /= 2;
        }
    }
}

bool verify_claim_sparse(
    __hhash_digest root_hhash,
    const std::unordered_map<uint32_t, __hhash_digest> &tree,
    __hhash_digest leaf_hash, int pos_element_arr, int N,
    std::unordered_map<uint32_t, bool> &visited, long long &proof_size) {
    if ((N & (-N)) != N)
        return false;
    int pos_element = pos_element_arr + N;
    __hhash_digest data[2];
    while (pos_element != 1) {
        data[pos_element & 1] = leaf_hash;
        const uint32_t sib = (uint32_t)(pos_element ^ 1);
        auto it = tree.find(sib);
        if (it == tree.end())
            return false;
        data[(pos_element & 1) ^ 1] = it->second;
        if (!visited[sib]) {
            visited[sib] = true;
            proof_size += (long long)sizeof(__hhash_digest);
        }
        my_hhash(data, &leaf_hash);
        pos_element /= 2;
    }
    return equals(root_hhash, leaf_hash);
}

} // namespace truepix_orion
