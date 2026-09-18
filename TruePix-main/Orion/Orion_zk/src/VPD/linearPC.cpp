#include "infrastructure/merkle_tree.h"
#include "linear_code/linear_code_encode.h"
#include "linear_gkr/verifier.h"
#include "linear_gkr/prover.h"
#include <math.h>
#include <map>
#include "infrastructure/merkle_tree.h"
#include "infrastructure/my_hhash.h"
#include <algorithm>
#include <chrono>
#include "VPD/linearPC.h"
//commit
prime_field::field_element **encoded_codeword;
prime_field::field_element **coef;
long long *codeword_size;
__hhash_digest *mt;
zk_prover p;
zk_verifier v;
double last_encode_preprocess_time = 0.0;

static void free_encoded_codeword()
{
    if(encoded_codeword == nullptr)
        return;
    for(int i = 0; i < column_size; ++i)
        delete[] encoded_codeword[i];
    delete[] encoded_codeword;
    encoded_codeword = nullptr;
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


__hhash_digest* commit(const prime_field::field_element *src, long long N)
{
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

    for(int i = 0; i < N / column_size * 2; ++i)
    {
        memset(&stash[i], 0, sizeof(__hhash_digest));
        for(int j = 0; j < column_size / 2; ++j)
        {
            stash[i] = merkle_tree::hash_double_field_element_merkle_damgard(encoded_codeword[2 * j][i], encoded_codeword[2 * j + 1][i], stash[i]);
        }
    }

    merkle_tree::merkle_tree_prover::create_tree(stash, N / column_size * 2, mt, sizeof(__hhash_digest), true);
    return mt;
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

std::pair<prime_field::field_element, bool> tensor_product_protocol(prime_field::field_element *r0, prime_field::field_element *r1, long long size_r0, long long size_r1, long long N, __hhash_digest *com_mt,bool use_group1)
{
    double verification_time = 0;
    assert(size_r0 * size_r1 == N);
    assert(coef != nullptr);

    const long long msg_len = N / column_size;
    const long long cw_len = codeword_size[0];

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
        col_q[i] = current_group[rand() % current_group_size];

    // Drop commit-time encoding; stream one-column encodes from coef.
    // This re-encode is preprocess (memory trade-off), not counted in Open time.
    free_encoded_codeword();

    prime_field::field_element *combined_codeword = new prime_field::field_element[cw_len];
    memset(combined_codeword, 0, sizeof(prime_field::field_element) * cw_len);
    prime_field::field_element *queried_cols = new prime_field::field_element[(long long)query_count * column_size];
    prime_field::field_element *col_scratch = new prime_field::field_element[msg_len * 2];

    timer_mark(enc_pre_t0);
    for(int j = 0; j < column_size; ++j)
    {
        memset(col_scratch, 0, sizeof(prime_field::field_element) * (msg_len * 2));
        int enc_len = encode(coef[j], col_scratch, msg_len);
        assert(enc_len == cw_len);
        for(long long t = 0; t < cw_len; ++t)
            combined_codeword[t] = combined_codeword[t] + r0[j] * col_scratch[t];
        for(int i = 0; i < query_count; ++i)
            queried_cols[(long long)i * column_size + j] = col_scratch[col_q[i]];
    }
    timer_mark(enc_pre_t1);
    last_encode_preprocess_time = time_diff(enc_pre_t0, enc_pre_t1);
    printf("Encode preprocess time %lf\n", last_encode_preprocess_time);
    delete[] col_scratch;

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

    prime_field::field_element *combined_message = new prime_field::field_element[msg_len];
    memset(combined_message, 0, sizeof(prime_field::field_element) * msg_len);
    for(int i = 0; i < column_size; ++i)
    {
        for(long long j = 0; j < msg_len; ++j)
            combined_message[j] = combined_message[j] + r0[i] * coef[i][j];
    }
    free_coef();

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

        // Verify Merkle paths and count path hashes into reported proof_size.
        assert(merkle_tree::merkle_tree_verifier::verify_claim(com_mt[1], com_mt, column_hash, q, msg_len * 2, visited_com, proof_size));
        assert(merkle_tree::merkle_tree_verifier::verify_claim(combined_codeword_mt[1], combined_codeword_mt, merkle_tree::hash_single_field_element(combined_codeword[q]), q, msg_len * 2, visited_combined_com, proof_size));
        assert(sum == combined_codeword[q]);
    }
    timer_mark(v_t1);
    verification_time += time_diff(v_t0, v_t1);
    delete[] queried_cols;
    delete[] col_q;

    prime_field::field_element answer = prime_field::field_element(0ULL);
    for(long long i = 0; i < msg_len; ++i)
        answer = answer + r1[i] * combined_message[i];

    long long *q = new long long[query_count];
    for(int i = 0; i < query_count; ++i)
        q[i] = rand() % cw_len;

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

    printf("EC(y1) code-switching time %lf\n", ec_y1_wall);
    printf("EC(y1) prover time %lf\n", ec_y1_prover);
    printf("EC(y1) verifier time %lf\n", ec_y1_verifier);
    printf("Proof size for tensor IOP %lld bytes\n", proof_size + v.proof_size);
    printf("Proof size for P %lld bytes\n", proof_size );
    printf("Proof size for V %lld bytes\n", v.proof_size );
    printf("Verification time %lf\n", verification_time);

    delete[] group1;
    delete[] group2;
    delete[] combined_codeword;
    delete[] combined_message;
    delete[] visited_com;
    delete[] visited_combined_com;
    delete[] q;

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
