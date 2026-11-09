#include "infrastructure/merkle_tree.h"
#include "flo-shani-aesni/sha256/flo-shani.h"
#include "linear_code/linear_code_encode.h"
#include "linear_gkr/verifier.h"
#include "linear_gkr/prover.h"
#include <math.h>
#include <map>
#include "infrastructure/merkle_tree.h"
#include "infrastructure/my_hhash.h"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include "VPD/linearPC.h"
#include "truepix/orion_fs.h"
#include "truepix/orion_proof.h"
#include "linear_code/parameter.h"
#include "VPD/fri.h"
#include "poly_commitment/poly_commit.h"
#include "infrastructure/RS_polynomial.h"
#include <vector>
#include <unordered_map>
#include <cstring>
//commit
prime_field::field_element **encoded_codeword = nullptr;
prime_field::field_element **coef = nullptr;
long long *codeword_size = nullptr;
static prime_field::field_element *pair_encoded_masked = nullptr;
static prime_field::field_element *pair_encoded_mask = nullptr;
static long long pair_encoded_cw_len = 0;
__hhash_digest *mt;
zk_prover p;
zk_verifier v;
double last_encode_preprocess_time = 0.0;
// Default streaming. Signer commit / prove recommit enable retain via
// set_retain_encoded_codeword(true) before commit_pair()/commit().
static bool retain_encoded_codeword = false;

void set_retain_encoded_codeword(bool enabled)
{
    retain_encoded_codeword = enabled;
}

static void free_encoded_codeword()
{
    if(encoded_codeword == nullptr)
        return;
    for(int i = 0; i < column_size; ++i)
        delete[] encoded_codeword[i];
    delete[] encoded_codeword;
    encoded_codeword = nullptr;
}

static void free_pair_encoded(bool masked)
{
    prime_field::field_element *&matrix =
        masked ? pair_encoded_masked : pair_encoded_mask;
    delete[] matrix;
    matrix = nullptr;
    if(pair_encoded_masked == nullptr && pair_encoded_mask == nullptr)
        pair_encoded_cw_len = 0;
}

static void free_all_pair_encoded()
{
    free_pair_encoded(true);
    free_pair_encoded(false);
}

static void free_coef()
{
    if(coef == nullptr)
        return;
    for(int i = 0; i < column_size; ++i)
        delete[] coef[i];
    delete[] coef;
    coef = nullptr;
}

static void hash_codeword_rows(prime_field::field_element **cols, long long rows, __hhash_digest *stash);


__hhash_digest* commit(const prime_field::field_element *src, long long N)
{
    free_all_pair_encoded();
    free_encoded_codeword();
    free_coef();
    delete[] codeword_size;
    codeword_size = nullptr;
    __hhash_digest *stash = new __hhash_digest[N / column_size * 2];
    codeword_size = new long long[column_size];
    assert(N % column_size == 0);
    encoded_codeword = new prime_field::field_element*[column_size];
    coef = new prime_field::field_element*[column_size];
    for(int i = 0; i < column_size; ++i)
    {
        encoded_codeword[i] = new prime_field::field_element[N / column_size * 2];
        coef[i] = new prime_field::field_element[N / column_size];
        memcpy(coef[i], &src[i * N / column_size], sizeof(prime_field::field_element) * N / column_size);
        memset(encoded_codeword[i], 0, sizeof(prime_field::field_element) * N / column_size * 2);
        codeword_size[i] = encode(&src[i * N / column_size], encoded_codeword[i], N / column_size);
    }

    hash_codeword_rows(encoded_codeword, N / column_size * 2, stash);

    merkle_tree::merkle_tree_prover::create_tree(stash, N / column_size * 2, mt, sizeof(__hhash_digest), true);
    return mt;
}

static bool codeword_row_equal(const prime_field::field_element *a,
                               const prime_field::field_element *b,
                               long long n)
{
    for(long long i = 0; i < n; ++i)
    {
        if(a[i].real != b[i].real || a[i].img != b[i].img)
            return false;
    }
    return true;
}

// One Merkle-Damgård step: SHA-256 of prev || (x, y). Same bytes as
// hash_double_field_element_merkle_damgard.
static __hhash_digest hash_one_row(prime_field::field_element **cols, long long row)
{
    __hhash_digest h;
    memset(&h, 0, sizeof(h));
    for(int j = 0; j < column_size / 2; ++j)
    {
        h = merkle_tree::hash_double_field_element_merkle_damgard(
            cols[2 * j][row], cols[2 * j + 1][row], h);
    }
    return h;
}

// Four independent rows per SHA-NI call. Each row's chain is unchanged, so the
// leaf digest matches the scalar hash. sha256_x4 loads the message with an
// aligned movdqa, so the blocks are 16-byte aligned.
static void hash_four_rows(prime_field::field_element **cols, long long row, __hhash_digest *stash)
{
    __hhash_digest state[4];
    memset(state, 0, sizeof(state));
    alignas(64) unsigned char msg[4][64];
    alignas(32) unsigned char dig[4][32];
    unsigned char *msg_ptr[4] = {msg[0], msg[1], msg[2], msg[3]};
    unsigned char *dig_ptr[4] = {dig[0], dig[1], dig[2], dig[3]};

    for(int j = 0; j < column_size / 2; ++j)
    {
        for(int lane = 0; lane < 4; ++lane)
        {
            memcpy(msg[lane], &state[lane], sizeof(__hhash_digest));
            prime_field::field_element element[2] = {
                cols[2 * j][row + lane],
                cols[2 * j + 1][row + lane]
            };
            memcpy(msg[lane] + sizeof(__hhash_digest), element, sizeof(element));
        }
        sha256_x4_update_shani_4x(msg_ptr, 64, dig_ptr);
        for(int lane = 0; lane < 4; ++lane)
            memcpy(&state[lane], dig[lane], sizeof(__hhash_digest));
    }
    for(int lane = 0; lane < 4; ++lane)
        stash[row + lane] = state[lane];
}

static void hash_codeword_rows(prime_field::field_element **cols, long long rows, __hhash_digest *stash)
{
    long long row = 0;
    for(; row + 4 <= rows; row += 4)
        hash_four_rows(cols, row, stash);
    for(; row < rows; ++row)
        stash[row] = hash_one_row(cols, row);

    const long long check_n = rows < 4 ? rows : 4;
    for(long long i = 0; i < check_n; ++i)
    {
        __hhash_digest ref = hash_one_row(cols, i);
        if(!equals(ref, stash[i]))
        {
            fprintf(stderr, "TruePix: 4-way row hash mismatch at row %lld\n", i);
            exit(1);
        }
    }
}

// One MD step for four rows: absorb a single (col_even, col_odd) pair into state.
static void hash_four_rows_one_pair(prime_field::field_element *col0,
                                    prime_field::field_element *col1,
                                    long long row,
                                    __hhash_digest *state)
{
    alignas(64) unsigned char msg[4][64];
    alignas(32) unsigned char dig[4][32];
    unsigned char *msg_ptr[4] = {msg[0], msg[1], msg[2], msg[3]};
    unsigned char *dig_ptr[4] = {dig[0], dig[1], dig[2], dig[3]};

    for(int lane = 0; lane < 4; ++lane)
    {
        memcpy(msg[lane], &state[row + lane], sizeof(__hhash_digest));
        prime_field::field_element element[2] = {col0[row + lane], col1[row + lane]};
        memcpy(msg[lane] + sizeof(__hhash_digest), element, sizeof(element));
    }
    sha256_x4_update_shani_4x(msg_ptr, 64, dig_ptr);
    for(int lane = 0; lane < 4; ++lane)
        memcpy(&state[row + lane], dig[lane], sizeof(__hhash_digest));
}

// Absorb one column-pair into every row's Merkle-Damgård state (4-way SHA-NI).
static void hash_update_pair_rows(prime_field::field_element *col0,
                                  prime_field::field_element *col1,
                                  long long rows,
                                  __hhash_digest *state)
{
    long long row = 0;
    for(; row + 4 <= rows; row += 4)
        hash_four_rows_one_pair(col0, col1, row, state);
    for(; row < rows; ++row)
    {
        state[row] = merkle_tree::hash_double_field_element_merkle_damgard(
            col0[row], col1[row], state[row]);
    }
}

static void check_encode_pair_column(const prime_field::field_element *masked,
                                     const prime_field::field_element *mask_poly,
                                     int col,
                                     long long col_len,
                                     long long rows,
                                     const prime_field::field_element *col_masked,
                                     const prime_field::field_element *col_mask,
                                     int cw_len)
{
    prime_field::field_element *ref_m = new prime_field::field_element[rows];
    prime_field::field_element *ref_k = new prime_field::field_element[rows];
    memset(ref_m, 0, sizeof(prime_field::field_element) * (size_t)rows);
    memset(ref_k, 0, sizeof(prime_field::field_element) * (size_t)rows);
    const long long off = (long long)col * col_len;
    int len_m = encode(&masked[off], ref_m, col_len);
    int len_k = encode(&mask_poly[off], ref_k, col_len);
    bool ok = len_m == cw_len && len_k == cw_len
        && codeword_row_equal(col_masked, ref_m, cw_len)
        && codeword_row_equal(col_mask, ref_k, cw_len);
    delete[] ref_m;
    delete[] ref_k;
    if(!ok)
    {
        fprintf(stderr, "TruePix: encode_pair mismatch on column %d\n", col);
        exit(1);
    }
}

zk_pair_commit commit_pair(const prime_field::field_element *masked,
                           const prime_field::field_element *mask_poly,
                           long long N)
{
    assert(N % column_size == 0);
    assert(column_size % 2 == 0);
    const long long col_len = N / column_size;
    const long long rows = col_len * 2;
    const long long cw_len = encode_output_len(col_len);

    // When retain_encoded_codeword is set (signer commit and prove recommit),
    // keep two compact column-major encoded matrices; otherwise stream and
    // discard row scratch after hashing.
    free_encoded_codeword();
    free_coef();
    free_all_pair_encoded();
    if(codeword_size != nullptr)
        delete[] codeword_size;
    codeword_size = new long long[column_size];
    if(retain_encoded_codeword)
    {
        pair_encoded_masked =
            new prime_field::field_element[(long long)column_size * cw_len];
        pair_encoded_mask =
            new prime_field::field_element[(long long)column_size * cw_len];
        pair_encoded_cw_len = cw_len;
    }

    __hhash_digest *stash_masked = new __hhash_digest[rows];
    __hhash_digest *stash_mask = new __hhash_digest[rows];
    memset(stash_masked, 0, sizeof(__hhash_digest) * (size_t)rows);
    memset(stash_mask, 0, sizeof(__hhash_digest) * (size_t)rows);

    // Scalar reference for the first few rows (parity-check vs 4-way SHA-NI).
    const long long check_n = cw_len < 4 ? cw_len : 4;
    __hhash_digest ref_masked[4];
    __hhash_digest ref_mask[4];
    memset(ref_masked, 0, sizeof(ref_masked));
    memset(ref_mask, 0, sizeof(ref_mask));

    const long long scratch_len = retain_encoded_codeword ? cw_len : rows;
    prime_field::field_element *scratch_m0 =
        new prime_field::field_element[scratch_len];
    prime_field::field_element *scratch_m1 =
        new prime_field::field_element[scratch_len];
    prime_field::field_element *scratch_k0 =
        new prime_field::field_element[scratch_len];
    prime_field::field_element *scratch_k1 =
        new prime_field::field_element[scratch_len];
    const size_t cw_bytes =
        sizeof(prime_field::field_element) * (size_t)cw_len;

    auto sec = [](std::chrono::high_resolution_clock::time_point a,
                  std::chrono::high_resolution_clock::time_point b) {
        return std::chrono::duration_cast<std::chrono::duration<double>>(b - a).count();
    };
    double encode_sec = 0.0;
    double hash_masked_sec = 0.0;
    double hash_mask_sec = 0.0;
    double store_sec = 0.0;
    bool checked_first = false;
    bool checked_last = false;

    for(int j = 0; j < column_size / 2; ++j)
    {
        const int c0 = 2 * j;
        const int c1 = 2 * j + 1;
        const long long off0 = (long long)c0 * col_len;
        const long long off1 = (long long)c1 * col_len;
        if(!retain_encoded_codeword)
        {
            memset(scratch_m0, 0, sizeof(prime_field::field_element) * (size_t)rows);
            memset(scratch_m1, 0, sizeof(prime_field::field_element) * (size_t)rows);
            memset(scratch_k0, 0, sizeof(prime_field::field_element) * (size_t)rows);
            memset(scratch_k1, 0, sizeof(prime_field::field_element) * (size_t)rows);
        }

        auto e0 = std::chrono::high_resolution_clock::now();
        codeword_size[c0] = encode_pair(&masked[off0], scratch_m0,
                                        &mask_poly[off0], scratch_k0, col_len);
        codeword_size[c1] = encode_pair(&masked[off1], scratch_m1,
                                        &mask_poly[off1], scratch_k1, col_len);
        auto e1 = std::chrono::high_resolution_clock::now();
        encode_sec += sec(e0, e1);
        assert(codeword_size[c0] == cw_len);
        assert(codeword_size[c1] == cw_len);

        // Column 0 is mixed (private wires). The last column is padding on SD.
        if(c0 == 0 || c1 == 0)
        {
            int col = (c0 == 0) ? c0 : c1;
            const prime_field::field_element *cm = (col == c0) ? scratch_m0 : scratch_m1;
            const prime_field::field_element *ck = (col == c0) ? scratch_k0 : scratch_k1;
            check_encode_pair_column(masked, mask_poly, col, col_len, rows,
                                     cm, ck, (int)codeword_size[col]);
            checked_first = true;
        }
        if(c0 == column_size - 1 || c1 == column_size - 1)
        {
            int col = (c0 == column_size - 1) ? c0 : c1;
            const prime_field::field_element *cm = (col == c0) ? scratch_m0 : scratch_m1;
            const prime_field::field_element *ck = (col == c0) ? scratch_k0 : scratch_k1;
            check_encode_pair_column(masked, mask_poly, col, col_len, rows,
                                     cm, ck, (int)codeword_size[col]);
            checked_last = true;
        }

        auto h0 = std::chrono::high_resolution_clock::now();
        hash_update_pair_rows(
            scratch_m0, scratch_m1,
            retain_encoded_codeword ? cw_len : rows, stash_masked);
        auto h1 = std::chrono::high_resolution_clock::now();
        hash_masked_sec += sec(h0, h1);

        auto k0 = std::chrono::high_resolution_clock::now();
        hash_update_pair_rows(
            scratch_k0, scratch_k1,
            retain_encoded_codeword ? cw_len : rows, stash_mask);
        auto k1 = std::chrono::high_resolution_clock::now();
        hash_mask_sec += sec(k0, k1);

        for(long long r = 0; r < check_n; ++r)
        {
            ref_masked[r] = merkle_tree::hash_double_field_element_merkle_damgard(
                scratch_m0[r], scratch_m1[r], ref_masked[r]);
            ref_mask[r] = merkle_tree::hash_double_field_element_merkle_damgard(
                scratch_k0[r], scratch_k1[r], ref_mask[r]);
        }
        if(retain_encoded_codeword)
        {
            auto s0 = std::chrono::high_resolution_clock::now();
            memcpy(pair_encoded_masked + (long long)c0 * cw_len, scratch_m0, cw_bytes);
            memcpy(pair_encoded_masked + (long long)c1 * cw_len, scratch_m1, cw_bytes);
            memcpy(pair_encoded_mask + (long long)c0 * cw_len, scratch_k0, cw_bytes);
            memcpy(pair_encoded_mask + (long long)c1 * cw_len, scratch_k1, cw_bytes);
            auto s1 = std::chrono::high_resolution_clock::now();
            store_sec += sec(s0, s1);
        }
    }

    if(retain_encoded_codeword)
    {
        prime_field::field_element zero(0ULL);
        __hhash_digest zero_leaf;
        memset(&zero_leaf, 0, sizeof(zero_leaf));
        for(int j = 0; j < column_size / 2; ++j)
            zero_leaf = merkle_tree::hash_double_field_element_merkle_damgard(
                zero, zero, zero_leaf);
        for(long long r = cw_len; r < rows; ++r)
        {
            stash_masked[r] = zero_leaf;
            stash_mask[r] = zero_leaf;
        }
    }

    if(!checked_first || !checked_last)
    {
        fprintf(stderr, "TruePix: encode_pair boundary check skipped\n");
        exit(1);
    }
    printf("encode_pair check: column 0 and %d match encode()\n", column_size - 1);

    for(long long r = 0; r < check_n; ++r)
    {
        if(!equals(ref_masked[r], stash_masked[r]) || !equals(ref_mask[r], stash_mask[r]))
        {
            fprintf(stderr, "TruePix: 4-way row hash mismatch at row %lld\n", r);
            exit(1);
        }
    }
    delete[] scratch_m0;
    delete[] scratch_m1;
    delete[] scratch_k0;
    delete[] scratch_k1;

    auto merkle_m0 = std::chrono::high_resolution_clock::now();
    __hhash_digest *mt_masked = nullptr;
    merkle_tree::merkle_tree_prover::create_tree(stash_masked, rows, mt_masked, sizeof(__hhash_digest), true);
    auto merkle_m1 = std::chrono::high_resolution_clock::now();

    __hhash_digest *mt_mask = nullptr;
    merkle_tree::merkle_tree_prover::create_tree(stash_mask, rows, mt_mask, sizeof(__hhash_digest), true);
    auto merkle_k1 = std::chrono::high_resolution_clock::now();

    delete[] stash_masked;
    delete[] stash_mask;

    double merkle_masked_sec = hash_masked_sec + sec(merkle_m0, merkle_m1);
    double merkle_mask_sec = hash_mask_sec + sec(merkle_m1, merkle_k1);
    double pair_sec =
        encode_sec + store_sec + merkle_masked_sec + merkle_mask_sec;
    printf("Fused encode time: %lf\n", encode_sec);
    if(retain_encoded_codeword)
        printf("Encoded matrix store time: %lf\n", store_sec);
    printf("Masked merkle time: %lf\n", merkle_masked_sec);
    printf("Mask merkle time: %lf\n", merkle_mask_sec);
    printf("Fused pair time: %lf\n", pair_sec);
    // One line only. Signer keeps the last "Commit time(mask)" line, and the
    // prove parser sums every "Commit time" line. Printing the pair total
    // twice would double-count it inside Input Prove Time.
    printf("Commit time(mask): %lf\n", pair_sec);

    zk_pair_commit out;
    out.mt_masked = mt_masked;
    out.mt_mask = mt_mask;
    return out;
}

void bind_open_message(const prime_field::field_element *src, long long N)
{
    free_coef();
    assert(N % column_size == 0);
    assert(codeword_size != nullptr);
    const long long col_len = N / column_size;
    coef = new prime_field::field_element*[column_size];
    for(int i = 0; i < column_size; ++i)
    {
        coef[i] = new prime_field::field_element[col_len];
        memcpy(coef[i], &src[i * col_len], sizeof(prime_field::field_element) * col_len);
    }
}

std::map<long long, long long> gates_count;

std::pair<long long, long long> prepare_enc_count(long long input_size, long long output_size_so_far, int depth)
{
    if(input_size <= distance_threshold)
    {
        return std::make_pair(depth, output_size_so_far);
    }
    //output
    gates_count[depth + 1] = output_size_so_far + input_size + C[depth].R;
    auto output_depth_output_size = prepare_enc_count(C[depth].R, output_size_so_far + input_size, depth + 1);
    gates_count[output_depth_output_size.first + 1] = output_depth_output_size.second + D[depth].R;
    return std::make_pair(output_depth_output_size.first + 1, gates_count[output_depth_output_size.first + 1]);
}

int smallest_pow2_larger_or_equal_to(int x)
{
    for(int i = 0; i < 32; ++i)
    {
        if((1 << i) >= x)
            return (1 << i);
    }
    assert(false);
}

void prepare_gates_count(long long *query, long long N, int query_count)
{
    long long query_ptr = 0;
    //input layer
    gates_count[0] = N;

    //expander part
    gates_count[1] = N + C[0].R;
    std::pair<long long, long long> output_depth_output_size = prepare_enc_count(C[0].R, N, 1);

    gates_count[output_depth_output_size.first + 1] = N + output_depth_output_size.second + D[0].R;
    gates_count[output_depth_output_size.first + 2] = query_count;
}

std::pair<long long, long long> generate_enc_circuit(long long input_size, long long output_size_so_far, long long recursion_depth, long long input_depth)
{
    if(input_size <= distance_threshold)
    {
        return std::make_pair(input_depth, output_size_so_far);
    }
    //relay the output
    for(int i = 0; i < output_size_so_far; ++i)
    {
        v.C.circuit[input_depth + 1].gates[i] = gate(gate_types::relay, i, 0);
    }
    v.C.circuit[input_depth + 1].src_expander_C_mempool = new int[cn * C[recursion_depth].L];
    v.C.circuit[input_depth + 1].weight_expander_C_mempool = new prime_field::field_element[cn * C[recursion_depth].L];
    int mempool_ptr = 0;
    for(int i = 0; i < C[recursion_depth].R; ++i)
    {
        int neighbor_size = C[recursion_depth].r_neighbor[i].size();
        v.C.circuit[input_depth + 1].gates[output_size_so_far + i].ty = gate_types::custom_linear_comb;
        v.C.circuit[input_depth + 1].gates[output_size_so_far + i].parameter_length = neighbor_size;
        v.C.circuit[input_depth + 1].gates[output_size_so_far + i].src = &v.C.circuit[input_depth + 1].src_expander_C_mempool[mempool_ptr];
        v.C.circuit[input_depth + 1].gates[output_size_so_far + i].weight = &v.C.circuit[input_depth + 1].weight_expander_C_mempool[mempool_ptr];
        mempool_ptr += C[recursion_depth].r_neighbor[i].size();
        int C_input_offset = output_size_so_far - input_size;
        for(int j = 0; j < neighbor_size; ++j)
        {
            v.C.circuit[input_depth + 1].gates[output_size_so_far + i].src[j] = C[recursion_depth].r_neighbor[i][j] + C_input_offset;
            v.C.circuit[input_depth + 1].gates[output_size_so_far + i].weight[j] = C[recursion_depth].r_weight[i][j];
        }
    }

    auto output_depth_output_size = generate_enc_circuit(C[recursion_depth].R, output_size_so_far + C[recursion_depth].R, recursion_depth + 1, input_depth + 1);

    long long D_input_offset = output_size_so_far;

    long long final_output_depth = output_depth_output_size.first + 1;

    output_size_so_far = output_depth_output_size.second;
    mempool_ptr = 0;

    
    //relay the output
    for(long long i = 0; i < output_size_so_far; ++i)
    {
        v.C.circuit[final_output_depth].gates[i] = gate(gate_types::relay, i, 0);
    }

    v.C.circuit[final_output_depth].src_expander_D_mempool = new int[dn * D[recursion_depth].L];
    v.C.circuit[final_output_depth].weight_expander_D_mempool = new prime_field::field_element[dn * D[recursion_depth].L];

    for(long long i = 0; i < D[recursion_depth].R; ++i)
    {
        long long neighbor_size = D[recursion_depth].r_neighbor[i].size();
        v.C.circuit[final_output_depth].gates[output_size_so_far + i].ty = gate_types::custom_linear_comb;
        v.C.circuit[final_output_depth].gates[output_size_so_far + i].parameter_length = neighbor_size;
        v.C.circuit[final_output_depth].gates[output_size_so_far + i].src = &v.C.circuit[final_output_depth].src_expander_D_mempool[mempool_ptr];
        v.C.circuit[final_output_depth].gates[output_size_so_far + i].weight = &v.C.circuit[final_output_depth].weight_expander_D_mempool[mempool_ptr];
        mempool_ptr += D[recursion_depth].r_neighbor[i].size();
        for(long long j = 0; j < neighbor_size; ++j)
        {
            v.C.circuit[final_output_depth].gates[output_size_so_far + i].src[j] = D[recursion_depth].r_neighbor[i][j] + D_input_offset;
            v.C.circuit[final_output_depth].gates[output_size_so_far + i].weight[j] = D[recursion_depth].r_weight[i][j];
        }
    }
    return std::make_pair(final_output_depth, output_size_so_far + D[recursion_depth].R);
}

void generate_circuit(long long* query, long long N, int query_count, prime_field::field_element *input)
{
    std::sort(query, query + query_count);
    prepare_gates_count(query, N, query_count);
    //printf("Depth %d\n", gates_count.size());
    assert((1LL << mylog(N)) == N);
    v.C.inputs = new prime_field::field_element[N];
    // circuit[0]=input, circuit[1..size] from gates_count (incl. query width).
    // Do not allocate circuit[size+1] (was one-past-end heap corruption on small N).
    v.C.total_depth = gates_count.size() + 1;
    v.C.circuit = new layer[v.C.total_depth];
    v.C.circuit[0].bit_length = mylog(N);
    v.C.circuit[0].gates = new gate[1LL << v.C.circuit[0].bit_length];

    for(int i = 0; i < gates_count.size(); ++i)
    {
        v.C.circuit[i + 1].bit_length = mylog(smallest_pow2_larger_or_equal_to(gates_count[i]));
        v.C.circuit[i + 1].gates = new gate[1LL << v.C.circuit[i + 1].bit_length];
    }

    for(long long i = 0; i < N; ++i)
    {
        v.C.inputs[i] = input[i];
        v.C.circuit[0].gates[i] = gate(gate_types::input, 0, 0);
        v.C.circuit[1].gates[i] = gate(gate_types::direct_relay, i, 0);
    }

    for(long long i = 0; i < N; ++i)
    {
        v.C.circuit[2].gates[i] = gate(gate_types::relay, i, 0);
    }

    v.C.circuit[2].src_expander_C_mempool = new int[cn * C[0].L];
    v.C.circuit[2].weight_expander_C_mempool = new prime_field::field_element[cn * C[0].L];
    int C_mempool_ptr = 0, D_mempool_ptr = 0;
    for(long long i = 0; i < C[0].R; ++i)
    {
        v.C.circuit[2].gates[i + N] = gate(gate_types::custom_linear_comb, 0, 0);
        v.C.circuit[2].gates[i + N].parameter_length = C[0].r_neighbor[i].size();
        v.C.circuit[2].gates[i + N].src = &v.C.circuit[2].src_expander_C_mempool[C_mempool_ptr];
        v.C.circuit[2].gates[i + N].weight = &v.C.circuit[2].weight_expander_C_mempool[C_mempool_ptr];
        C_mempool_ptr += C[0].r_neighbor[i].size();
        for(long long j = 0; j < C[0].r_neighbor[i].size(); ++j)
        {
            long long L = C[0].r_neighbor[i][j];
            long long R = i;
            prime_field::field_element weight = C[0].r_weight[R][j];
            v.C.circuit[2].gates[i + N].src[j] = L;
            v.C.circuit[2].gates[i + N].weight[j] = weight;
        }
    }

    auto output_depth_output_size = generate_enc_circuit(C[0].R, N + C[0].R, 1, 2);
    //add final output
    long long final_output_depth = output_depth_output_size.first + 1;
    for(long long i = 0; i < output_depth_output_size.second; ++i)
    {
        v.C.circuit[final_output_depth].gates[i] = gate(gate_types::relay, i, 0);
    }

    long long D_input_offset = N;
    long long output_so_far = output_depth_output_size.second;
    v.C.circuit[final_output_depth].src_expander_D_mempool = new int[dn * D[0].L];
    v.C.circuit[final_output_depth].weight_expander_D_mempool = new prime_field::field_element[dn * D[0].L];

    for(long long i = 0; i < D[0].R; ++i)
    {
        v.C.circuit[final_output_depth].gates[output_so_far + i].ty = gate_types::custom_linear_comb;
        v.C.circuit[final_output_depth].gates[output_so_far + i].parameter_length = D[0].r_neighbor[i].size();
        v.C.circuit[final_output_depth].gates[output_so_far + i].src = &v.C.circuit[final_output_depth].src_expander_D_mempool[D_mempool_ptr];
        v.C.circuit[final_output_depth].gates[output_so_far + i].weight = &v.C.circuit[final_output_depth].weight_expander_D_mempool[D_mempool_ptr];
        D_mempool_ptr += D[0].r_neighbor[i].size();
        for(long long j = 0; j < D[0].r_neighbor[i].size(); ++j)
        {
            v.C.circuit[final_output_depth].gates[output_so_far + i].src[j] = D[0].r_neighbor[i][j] + N;
            v.C.circuit[final_output_depth].gates[output_so_far + i].weight[j] = D[0].r_weight[i][j];
        }
    }

    for(long long i = 0; i < query_count; ++i)
    {
        v.C.circuit[final_output_depth + 1].gates[i] = gate(gate_types::relay, query[i], 0);
    }
    assert(C_mempool_ptr == cn * C[0].L);
}

#define timer_mark(x) auto x = std::chrono::high_resolution_clock::now()
#define time_diff(start, end) (std::chrono::duration_cast<std::chrono::duration<double>>(end - start).count())

// Drop the EC circuit and the FRI/FFT buffers from one opening so the next
// opening allocates a fresh set instead of stacking on the previous one.
static void release_ec_workspace()
{
    if(v.C.circuit != nullptr)
    {
        delete[] v.C.circuit;
        v.C.circuit = nullptr;
    }
    if(v.C.inputs != nullptr)
    {
        delete[] v.C.inputs;
        v.C.inputs = nullptr;
    }
    v.C.total_depth = 0;

    delete_scratch_pad();
    fri::delete_self();

    delete[] poly_commit::l_eval;
    delete[] poly_commit::q_eval;
    delete[] poly_commit::h_eval_arr;
    delete[] poly_commit::l_coef;
    delete[] poly_commit::q_coef;
    poly_commit::l_eval = nullptr;
    poly_commit::q_eval = nullptr;
    poly_commit::h_eval_arr = nullptr;
    poly_commit::l_coef = nullptr;
    poly_commit::q_coef = nullptr;
    poly_commit::pre_prepare_executed = false;
}

std::pair<prime_field::field_element, bool> tensor_product_protocol(prime_field::field_element *r0, prime_field::field_element *r1, long long size_r0, long long size_r1, long long N, __hhash_digest *com_mt,bool use_group1)
{
    double verification_time = 0;
    assert(size_r0 * size_r1 == N);
    assert(coef != nullptr);

    const long long msg_len = N / column_size;
    const long long cw_len = codeword_size[0];
    const bool nizk = (truepix_orion::orion_mode_from_env() == truepix_orion::OrionMode::Nizk);

    // Fiat--Shamir public absorb (NIZK). Interactive mode ignores global_fs.
    if (nizk) {
        truepix_orion::fs_reset_global();
        auto &fs = truepix_orion::global_fs();
        fs.absorb_label("tensor-open");
        fs.absorb_digest(com_mt[1]);
        fs.absorb_u64(static_cast<uint64_t>(N));
        fs.absorb_u64(use_group1 ? 1ULL : 0ULL);
        for (long long i = 0; i < size_r0; ++i)
            fs.absorb_field(r0[i]);
        for (long long i = 0; i < size_r1; ++i)
            fs.absorb_field(r1[i]);
    }

    bool *visited_com = new bool[msg_len * 4];
    bool *visited_combined_com = new bool[msg_len * 4];
    memset(visited_com, 0, sizeof(bool) * (msg_len * 4));
    memset(visited_combined_com, 0, sizeof(bool) * (msg_len * 4));

    long long proof_size = 0;

    const int query_count = -128 / (log2(1 - target_distance));
    //printf("Query count %d\n", query_count);
    //printf("Column size %d\n", column_size);
    //printf("Number of merkle pathes %d\n", query_count);
    //printf("Number of field elements %d\n", query_count * column_size);

    // (Zero-knowledge) Divide column indices to ensure the two openings don't overlap
    int* group1 = new int[(cw_len + 1) / 2];
    int* group2 = new int[cw_len / 2];
    int group1_size = 0, group2_size = 0;

    for (long long i = 0; i < cw_len; ++i) {
        if (i % 2 == 0) {
            group1[group1_size++] = (int)i;
        } else {
            group2[group2_size++] = (int)i;
        }
    }

    int* current_group = use_group1 ? group1 : group2;
    int current_group_size = use_group1 ? group1_size : group2_size;

    long long *col_q = new long long[query_count];
    for(int i = 0; i < query_count; ++i)
        col_q[i] = current_group[truepix_orion::orion_challenge_index(current_group_size)];

    prime_field::field_element *pair_matrix =
        use_group1 ? pair_encoded_masked : pair_encoded_mask;
    const bool use_pair_matrix = pair_matrix != nullptr;
    const bool use_legacy_matrix = !use_pair_matrix && encoded_codeword != nullptr;
    if(use_pair_matrix)
        assert(pair_encoded_cw_len == cw_len);

    // Prefer a retained prove-recommit matrix. Open/legacy callers that did not
    // request retention keep the original per-column re-encode fallback.
    prime_field::field_element *combined_codeword = new prime_field::field_element[cw_len];
    memset(combined_codeword, 0, sizeof(prime_field::field_element) * cw_len);
    prime_field::field_element *queried_cols = new prime_field::field_element[(long long)query_count * column_size];
    prime_field::field_element *combined_message = new prime_field::field_element[msg_len];
    memset(combined_message, 0, sizeof(prime_field::field_element) * msg_len);
    prime_field::field_element *col_scratch =
        (use_pair_matrix || use_legacy_matrix)
            ? nullptr : new prime_field::field_element[msg_len * 2];

    timer_mark(enc_pre_t0);
    for(int j = 0; j < column_size; ++j)
    {
        const prime_field::field_element *col = nullptr;
        if(use_pair_matrix)
            col = pair_matrix + (long long)j * cw_len;
        else if(use_legacy_matrix)
            col = encoded_codeword[j];
        else
        {
            memset(col_scratch, 0,
                   sizeof(prime_field::field_element) * (size_t)(msg_len * 2));
            int enc_len = encode(coef[j], col_scratch, msg_len);
            assert(enc_len == cw_len);
            col = col_scratch;
        }
        for(long long t = 0; t < cw_len; ++t)
            combined_codeword[t] = combined_codeword[t] + r0[j] * col[t];
        for(int i = 0; i < query_count; ++i)
            queried_cols[(long long)i * column_size + j] = col[col_q[i]];
        for(long long t = 0; t < msg_len; ++t)
            combined_message[t] = combined_message[t] + r0[j] * coef[j][t];
    }
    timer_mark(enc_pre_t1);
    last_encode_preprocess_time = time_diff(enc_pre_t0, enc_pre_t1);
    printf("%s preprocess time %lf\n",
           (use_pair_matrix || use_legacy_matrix) ? "Encoded matrix" : "Encode",
           last_encode_preprocess_time);
    delete[] col_scratch;
    if(use_pair_matrix)
        free_pair_encoded(use_group1);
    else if(use_legacy_matrix)
        free_encoded_codeword();
    free_coef();

    __hhash_digest *combined_codeword_hash = new __hhash_digest[msg_len * 2];
    __hhash_digest *combined_codeword_mt = new __hhash_digest[msg_len * 4];
    prime_field::field_element zero;
    memset(&zero, 0, sizeof(zero));
    for(long long i = 0; i < msg_len * 2; ++i)
    {
        if(i < cw_len)
            combined_codeword_hash[i] = merkle_tree::hash_single_field_element(combined_codeword[i]);
        else
            combined_codeword_hash[i] = merkle_tree::hash_single_field_element(zero);
    }
    merkle_tree::merkle_tree_prover::create_tree(combined_codeword_hash, msg_len * 2, combined_codeword_mt, sizeof(__hhash_digest), false);
    delete[] combined_codeword_hash;
    combined_codeword_hash = nullptr;

    printf("query_count %lld \n", (long long)query_count);
    printf("sizeof(prime_field::field_element) %lld \n", (long long)sizeof(prime_field::field_element));
    printf("column_size %lld \n", (long long)column_size);
    timer_mark(v_t0);
    for(int i = 0; i < query_count; ++i)
    {
        int q = (int)col_q[i];
        prime_field::field_element *col = queried_cols + (long long)i * column_size;
        prime_field::field_element sum = prime_field::field_element(0ULL);
        for(int j = 0; j < column_size; ++j)
            sum = sum + r0[j] * col[j];
        proof_size += sizeof(prime_field::field_element) * column_size;

        __hhash_digest column_hash;
        memset(&column_hash, 0, sizeof(__hhash_digest));
        for(int j = 0; j < column_size / 2; ++j)
        {
            column_hash = merkle_tree::hash_double_field_element_merkle_damgard(col[2 * j], col[2 * j + 1], column_hash);
        }

        // verify_claim counts Merkle path hashes into proof_size. Keep the call
        // outside assert(): Release builds define NDEBUG and erase assert().
        if(!merkle_tree::merkle_tree_verifier::verify_claim(com_mt[1], com_mt, column_hash, q, msg_len * 2, visited_com, proof_size)
            || !merkle_tree::merkle_tree_verifier::verify_claim(combined_codeword_mt[1], combined_codeword_mt, merkle_tree::hash_single_field_element(combined_codeword[q]), q, msg_len * 2, visited_combined_com, proof_size))
        {
            fprintf(stderr, "TruePix: Merkle path verification failed\n");
            exit(1);
        }
        assert(sum == combined_codeword[q]);
    }
    timer_mark(v_t1);
    verification_time += time_diff(v_t0, v_t1);
    // Leaf hashes are already copied into the tree. Sibling lists for the NIZK
    // blob are taken now so the combined tree can be released before EC.
    __hhash_digest combined_root_copy = combined_codeword_mt[1];
    std::vector<uint32_t> early_com_idx, early_cmb_idx;
    std::vector<__hhash_digest> early_com_dig, early_cmb_dig;
    if(nizk)
    {
        truepix_orion::collect_merkle_siblings(
            com_mt, (int)(msg_len * 2), col_q, query_count, early_com_idx, early_com_dig);
        truepix_orion::collect_merkle_siblings(
            combined_codeword_mt, (int)(msg_len * 2), col_q, query_count,
            early_cmb_idx, early_cmb_dig);
    }
    delete[] combined_codeword_mt;
    combined_codeword_mt = nullptr;

    prime_field::field_element answer = prime_field::field_element(0ULL);
    for(long long i = 0; i < msg_len; ++i)
        answer = answer + r1[i] * combined_message[i];

    long long *q = new long long[query_count];
    for(int i = 0; i < query_count; ++i)
        q[i] = truepix_orion::orion_challenge_index(static_cast<int>(cw_len));

    if (nizk) {
        auto &fs = truepix_orion::global_fs();
        fs.absorb_label("combined-mt");
        fs.absorb_digest(combined_root_copy);
    }

    timer_mark(ec_y1_t0);
    generate_circuit(q, msg_len, query_count, combined_message);

    v.get_prover(&p);
    p.get_circuit(v.C);
    int max_bit_length = -1;
    for(int i = 0; i < v.C.total_depth; ++i)
        max_bit_length = max(max_bit_length, v.C.circuit[i].bit_length);
    p.init_array(max_bit_length);
    v.init_array(max_bit_length);
    p.get_witness(combined_message, msg_len);

    bool result = v.verify("log.txt");
    timer_mark(ec_y1_t1);
    double ec_y1_wall = time_diff(ec_y1_t0, ec_y1_t1);
    double ec_y1_prover = p.total_time;
    double ec_y1_verifier = v.v_time;
    timer_mark(sample_t0);
    for(int i = 0; i < query_count; ++i)
        assert(p.circuit_value[p.C -> total_depth - 1][i] == combined_codeword[q[i]]);
    timer_mark(sample_t1);
    verification_time += time_diff(sample_t0, sample_t1);
    verification_time += v.v_time;
    proof_size += query_count * sizeof(prime_field::field_element);
	p.delete_self();
	v.delete_self();
    release_ec_workspace();

    printf("EC(y1) code-switching time %lf\n", ec_y1_wall);
    printf("EC(y1) prover time %lf\n", ec_y1_prover);
    printf("EC(y1) verifier time %lf\n", ec_y1_verifier);
    printf("Proof size for tensor IOP %lld bytes\n", proof_size + v.proof_size);
    printf("Proof size for P %lld bytes\n", proof_size );
    printf("Proof size for V %lld bytes\n", v.proof_size );
    printf("Verification time %lf\n", verification_time);

    if (nizk && result) {
        truepix_orion::OpeningProof op;
        op.version = 2;
        op.use_group1 = use_group1 ? 1u : 0u;
        op.N = static_cast<uint64_t>(N);
        op.column_size = static_cast<uint64_t>(column_size);
        op.msg_len = static_cast<uint64_t>(msg_len);
        op.cw_len = static_cast<uint64_t>(cw_len);
        op.query_count = static_cast<uint32_t>(query_count);
        op.answer = answer;
        op.com_root = com_mt[1];
        op.combined_root = combined_root_copy;
        op.col_q.assign(col_q, col_q + query_count);
        op.queried_cols.assign(
            queried_cols, queried_cols + (long long)query_count * column_size);
        op.combined_codeword.assign(combined_codeword, combined_codeword + cw_len);
        op.combined_message.assign(combined_message, combined_message + msg_len);
        op.com_mt_idx.swap(early_com_idx);
        op.com_mt.swap(early_com_dig);
        op.combined_mt_idx.swap(early_cmb_idx);
        op.combined_mt.swap(early_cmb_dig);
        const std::string path = truepix_orion::default_proof_path();
        if (!op.write_file(path)) {
            fprintf(stderr, "TruePix: failed to write NIZK proof %s\n", path.c_str());
            result = false;
        } else {
            printf("ORION_NIZK_PROOF_BYTES %zu\n", op.byte_size());
            printf("ORION_NIZK_PROOF_FILE %s\n", path.c_str());
        }
    }

    delete[] group1;
    delete[] group2;
    delete[] combined_codeword;
    delete[] combined_message;
    delete[] visited_com;
    delete[] visited_combined_com;
    delete[] q;
    delete[] queried_cols;
    delete[] col_q;

    return std::make_pair(answer, result);
}

//open & verify

std::pair<prime_field::field_element, bool> open_and_verify(prime_field::field_element x, long long N, __hhash_digest *com_mt,bool use_group1)
{
    assert(N % column_size == 0);
    //tensor product of r0 otimes r1
    prime_field::field_element *r0, *r1;
    r0 = new prime_field::field_element[column_size];
    r1 = new prime_field::field_element[N / column_size];

    prime_field::field_element x_n = prime_field::fast_pow(x, N / column_size);
    r0[0] = prime_field::field_element(1ULL);
    for(long long j = 1; j < column_size; ++j)
    {
        r0[j] = r0[j - 1] * x_n;
    }
    r1[0] = prime_field::field_element(1ULL);
    for(long long j = 1; j < N / column_size; ++j)
    {
        r1[j] = r1[j - 1] * x;
    }

    auto answer = tensor_product_protocol(r0, r1, column_size, N / column_size, N, com_mt,use_group1);

    delete[] r0;
    delete[] r1;
    return answer;
}

void dfs(prime_field::field_element *dst, prime_field::field_element *r, int size, int depth, prime_field::field_element val)
{
    if(size == 1)
    {
        *dst = val;
    }
    else
    {
        dfs(dst, r, size / 2, depth + 1, val * (prime_field::field_element(1) - r[depth]));
        dfs(dst + (size / 2), r, size / 2, depth + 1, val * r[depth]);
    }
}

std::pair<prime_field::field_element, bool> open_and_verify(prime_field::field_element *r, int size_r, int N, __hhash_digest *com_mt, bool use_group1)
{
    assert(N % column_size == 0);
    prime_field::field_element *r0, *r1;

    r0 = new prime_field::field_element[column_size];
    r1 = new prime_field::field_element[N / column_size];
    int log_column_size = 0;
    while(true)
    {
        if((1 << log_column_size) == column_size)
        {
            break;
        }
        log_column_size++;
    }
    dfs(r0, r, column_size, 0, prime_field::field_element(1));
    dfs(r1, r + log_column_size, N / column_size, 0, prime_field::field_element(1));



    auto answer = tensor_product_protocol(r0, r1, column_size, N / column_size, N, com_mt,use_group1);
    delete[] r0;
    delete[] r1;
    return answer;
}

std::pair<prime_field::field_element, bool> verify_opening_proof(
    prime_field::field_element *r, int size_r, int N,
    const __hhash_digest &expected_root, bool use_group1,
    const char *proof_path)
{
    using namespace truepix_orion;
    if (orion_mode_from_env() != OrionMode::Nizk) {
        fprintf(stderr, "verify_opening_proof requires TRUEPIX_ORION_MODE=nizk\n");
        return {prime_field::field_element(0ULL), false};
    }
    OpeningProof op;
    if (!op.read_file(proof_path ? proof_path : default_proof_path())) {
        fprintf(stderr, "TruePix: cannot read NIZK proof\n");
        return {prime_field::field_element(0ULL), false};
    }
    if (op.N != static_cast<uint64_t>(N) ||
        op.column_size != static_cast<uint64_t>(column_size) ||
        op.use_group1 != (use_group1 ? 1u : 0u)) {
        fprintf(stderr, "TruePix: proof layout mismatch\n");
        return {prime_field::field_element(0ULL), false};
    }
    if (!equals(op.com_root, expected_root)) {
        fprintf(stderr, "TruePix: proof com_root != expected\n");
        return {prime_field::field_element(0ULL), false};
    }

    const long long msg_len = static_cast<long long>(op.msg_len);
    const long long cw_len = static_cast<long long>(op.cw_len);
    const int query_count = static_cast<int>(op.query_count);

    prime_field::field_element *r0 = new prime_field::field_element[column_size];
    prime_field::field_element *r1 = new prime_field::field_element[N / column_size];
    int log_column_size = 0;
    while ((1 << log_column_size) != column_size)
        log_column_size++;
    dfs(r0, r, column_size, 0, prime_field::field_element(1));
    dfs(r1, r + log_column_size, N / column_size, 0, prime_field::field_element(1));

    fs_reset_global();
    auto &fs = global_fs();
    fs.absorb_label("tensor-open");
    fs.absorb_digest(op.com_root);
    fs.absorb_u64(static_cast<uint64_t>(N));
    fs.absorb_u64(use_group1 ? 1ULL : 0ULL);
    for (int i = 0; i < column_size; ++i)
        fs.absorb_field(r0[i]);
    for (long long i = 0; i < N / column_size; ++i)
        fs.absorb_field(r1[i]);

    int *group1 = new int[(cw_len + 1) / 2];
    int *group2 = new int[cw_len / 2];
    int group1_size = 0, group2_size = 0;
    for (long long i = 0; i < cw_len; ++i) {
        if (i % 2 == 0)
            group1[group1_size++] = (int)i;
        else
            group2[group2_size++] = (int)i;
    }
    int *current_group = use_group1 ? group1 : group2;
    int current_group_size = use_group1 ? group1_size : group2_size;
    for (int i = 0; i < query_count; ++i) {
        long long expect = current_group[orion_challenge_index(current_group_size)];
        if (expect != op.col_q[i]) {
            fprintf(stderr, "TruePix: FS column query mismatch at %d\n", i);
            delete[] r0; delete[] r1; delete[] group1; delete[] group2;
            return {prime_field::field_element(0ULL), false};
        }
    }

    auto com_map = op.com_mt_map();
    auto cmb_map = op.combined_mt_map();
    std::unordered_map<uint32_t, bool> visited_com;
    std::unordered_map<uint32_t, bool> visited_combined_com;
    long long proof_size = 0;
    double verification_time = 0;
    timer_mark(v_t0);
    for (int i = 0; i < query_count; ++i) {
        int qidx = (int)op.col_q[i];
        const prime_field::field_element *col =
            op.queried_cols.data() + (long long)i * column_size;
        prime_field::field_element sum = prime_field::field_element(0ULL);
        for (int j = 0; j < column_size; ++j)
            sum = sum + r0[j] * col[j];
        if (sum != op.combined_codeword[qidx]) {
            fprintf(stderr, "TruePix: column linear combo mismatch\n");
            delete[] r0; delete[] r1; delete[] group1; delete[] group2;
            return {prime_field::field_element(0ULL), false};
        }
        __hhash_digest column_hash;
        memset(&column_hash, 0, sizeof(__hhash_digest));
        for (int j = 0; j < column_size / 2; ++j)
            column_hash = merkle_tree::hash_double_field_element_merkle_damgard(
                col[2 * j], col[2 * j + 1], column_hash);
        if (!truepix_orion::verify_claim_sparse(
                op.com_root, com_map, column_hash, qidx, (int)(msg_len * 2),
                visited_com, proof_size) ||
            !truepix_orion::verify_claim_sparse(
                op.combined_root, cmb_map,
                merkle_tree::hash_single_field_element(op.combined_codeword[qidx]),
                qidx, (int)(msg_len * 2), visited_combined_com, proof_size)) {
            fprintf(stderr, "TruePix: NIZK Merkle verify failed\n");
            delete[] r0; delete[] r1; delete[] group1; delete[] group2;
            return {prime_field::field_element(0ULL), false};
        }
        proof_size += (long long)sizeof(prime_field::field_element) * column_size;
    }
    timer_mark(v_t1);
    verification_time += time_diff(v_t0, v_t1);

    prime_field::field_element answer = prime_field::field_element(0ULL);
    for (long long i = 0; i < msg_len; ++i)
        answer = answer + r1[i] * op.combined_message[i];
    if (answer != op.answer) {
        fprintf(stderr, "TruePix: answer recomputation mismatch\n");
        delete[] r0; delete[] r1; delete[] group1; delete[] group2;
        return {prime_field::field_element(0ULL), false};
    }

    long long *q = new long long[query_count];
    for (int i = 0; i < query_count; ++i)
        q[i] = orion_challenge_index(static_cast<int>(cw_len));
    fs.absorb_label("combined-mt");
    fs.absorb_digest(op.combined_root);

    // Provide codeword_size for EC circuit helpers if needed.
    if (codeword_size == nullptr) {
        codeword_size = new long long[column_size];
        for (int i = 0; i < column_size; ++i)
            codeword_size[i] = cw_len;
    }

    timer_mark(ec_y1_t0);
    generate_circuit(q, msg_len, query_count, op.combined_message.data());
    v.get_prover(&p);
    p.get_circuit(v.C);
    int max_bit_length = -1;
    for (int i = 0; i < v.C.total_depth; ++i)
        max_bit_length = max(max_bit_length, v.C.circuit[i].bit_length);
    p.init_array(max_bit_length);
    v.init_array(max_bit_length);
    p.get_witness(op.combined_message.data(), msg_len);
    bool result = v.verify("log.txt");
    timer_mark(ec_y1_t1);
    // Match interactive open: only count EC verifier work in Verification time.
    // Do not add (wall - prover); that double-counts v.v_time / pulls prover slack
    // into Input Verify Time / TOTAL Verify Time.
    verification_time += v.v_time;
    proof_size += (long long)query_count * (long long)sizeof(prime_field::field_element);
    printf("EC(y1) code-switching time %lf\n", time_diff(ec_y1_t0, ec_y1_t1));
    printf("EC(y1) prover time %lf\n", p.total_time);
    printf("EC(y1) verifier time %lf\n", v.v_time);
    // Same PCS accounting as the prove-side tensor_product_protocol (not blob size).
    printf("Proof size for tensor IOP %lld bytes\n",
           proof_size + (long long)v.proof_size);
    printf("Verification time %lf\n", verification_time);
    p.delete_self();
    v.delete_self();
    release_ec_workspace();

    delete[] q;
    delete[] r0;
    delete[] r1;
    delete[] group1;
    delete[] group2;
    return {answer, result};
}
