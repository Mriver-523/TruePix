#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <chrono>
#include <cstring>      // memory operations, e.g., memcpy
#include <random> 

#include "linear_code/linear_code_encode.h"
#include "VPD/linearPC.h"
#include "truepix/truepix_gkr.h"

#define timer_mark(x) auto x = std::chrono::high_resolution_clock::now()
#define time_diff(start, end) (std::chrono::duration_cast<std::chrono::duration<double>>(end - start).count())


// Write __hhash_digest array to file, including all parameters that need to be transmitted
void write_transmitted_data_commit(
    const __hhash_digest* h, int h_length,
    const std::string& filename) {

    std::ofstream outfile(filename, std::ios::trunc);
    if (!outfile) {
        fprintf(stderr, "Error: Cannot open file %s for writing\n", filename.c_str());
        exit(1);
    }

    // Write h array
    outfile << "[h_array]\n";
    for (int i = 0; i < h_length; ++i) {
        uint64_t h0_low = _mm_extract_epi64(h[i].h0, 0);
        uint64_t h0_high = _mm_extract_epi64(h[i].h0, 1);
        uint64_t h1_low = _mm_extract_epi64(h[i].h1, 0);
        uint64_t h1_high = _mm_extract_epi64(h[i].h1, 1);

        outfile << "Index " << i << ":\n";
        outfile << "h0(high): 0x" << std::hex << h0_high << " ";
        outfile << "h0(low): 0x" << std::hex << h0_low << " ";
        outfile << "h1(high): 0x" << std::hex << h1_high << " ";
        outfile << "h1(low): 0x" << std::hex << h1_low << "\n";
    }

}


// truepix: commit to one polynomial and report its Merkle root, which the
// prove and open phases are later required to reproduce.
static truepix::CommitReport truepix_commit_only(
    prime_field::field_element *poly,
    long long N,
    const std::string& transmitted_file,
    const char* label)
{
    truepix::CommitReport rep;
    rep.ok = 0;
    memset(rep.root, 0, sizeof(rep.root));

    timer_mark(commit_t0);
    auto h = commit(poly, N);
    timer_mark(commit_t1);
    // Keep the legacy metric names that run_fennel_signer.py greps for.
    printf("Commit time(%s): %lf\n", label, time_diff(commit_t0, commit_t1));
    printf("Commit time %lf\n", time_diff(commit_t0, commit_t1));

    const std::string root = truepix::root_hex(h[1]);
    memcpy(rep.root, root.c_str(), root.size());
    rep.ok = 1;

    long long size_after_padding = 1;
    while (size_after_padding < N / column_size * 2)
        size_after_padding *= 2;
    int h_length = size_after_padding * 2;
    write_transmitted_data_commit(h, h_length, transmitted_file);
    return rep;
}

// (Zero-knowledge) Added a function to define one commitment and corresponding opening, bool variable determines whether to commit to the masked polynomial or the mask polynomial, true for masked polynomial, false for mask polynomial
void run_commit_and_open(prime_field::field_element *data,prime_field::field_element *mask,int N, int lg_N, bool use_mask, prime_field::field_element* r) {
   
    if (use_mask) {
        // If using mask, add mask to data
        for (int i = 0; i < N; ++i) {
            data[i] = data[i] + mask[i];
        }
    // Commit data (same interface as previous commitment)
    timer_mark(commit_t0);
    auto h = commit(data, N);//Commitment
    timer_mark(commit_t1);
    printf("Commit time %lf\n", time_diff(commit_t0, commit_t1));
    
    // Calculate lengths of various arrays
    long long size_after_padding = 1;
    while (size_after_padding < N / column_size * 2)
        size_after_padding *= 2;
    int h_length = size_after_padding * 2; // Complete Merkle tree size
        
    // Write all data that needs to be transmitted to file
    write_transmitted_data_commit(
        h, h_length,
        "transmitted_data_mask.txt");

    // Free dynamically allocated memory
    //delete[] data;
    }

    else{
    timer_mark(commit_t0);
    auto h = commit(mask, N);
    timer_mark(commit_t1);
    printf("Commit time(mask): %lf\n", time_diff(commit_t0, commit_t1));
    
    // Calculate lengths of various arrays
    long long size_after_padding = 1;
    while (size_after_padding < N / column_size * 2)
        size_after_padding *= 2;
    int h_length = size_after_padding * 2; // Complete Merkle tree size
        
    // Write all data that needs to be transmitted to file
    write_transmitted_data_commit(
        h, h_length,
        "transmitted_data_masked.txt");
        

    // Free dynamically allocated memory
    //delete[] mask;
}
}
// (Zero-knowledge) Used to verify that the claimed value of the masked polynomial equals the claimed value of the original polynomial plus the mask polynomial, includes dfs1 function and evaluate_data_at_r function
void dfs1(prime_field::field_element *dst, prime_field::field_element *r, int size, int depth, prime_field::field_element val)//Generate r0 and r1 values when calculating polynomial value at r
{
    if(size == 1)
    {
        *dst = val;
    }
    else
    {
        dfs1(dst, r, size / 2, depth + 1, val * (prime_field::field_element(1) - r[depth]));
        dfs1(dst + (size / 2), r, size / 2, depth + 1, val * r[depth]);
    }
}
prime_field::field_element evaluate_data_at_r(prime_field::field_element *data, prime_field::field_element *r, int lg_N, int N)//Used to calculate polynomial value at r
{
    assert(N % column_size == 0);

    // Allocate and initialize r0 and r1
    prime_field::field_element *r0 = new prime_field::field_element[column_size];
    prime_field::field_element *r1 = new prime_field::field_element[N / column_size];

    int log_column_size = 0;
    while ((1 << log_column_size) != column_size)
    {
        log_column_size++;
    }

    // Use depth-first search to generate r0 and r1
    dfs1(r0, r, column_size, 0, prime_field::field_element(1));
    dfs1(r1, r + log_column_size, N / column_size, 0, prime_field::field_element(1));

    // Calculate combined_message
    prime_field::field_element *combined_message = new prime_field::field_element[N];
    memset(combined_message, 0, sizeof(prime_field::field_element) * N);

    for (int i = 0; i < column_size; ++i)
    {
        for (int j = 0; j < N / column_size; ++j)
        {
            combined_message[j] = combined_message[j] + r0[i] * data[i * (N / column_size) + j];
        }
    }

    // Calculate polynomial value at r
    prime_field::field_element answer = prime_field::field_element(0ULL);
    for (int i = 0; i < N / column_size; ++i)
    {
        answer = answer + r1[i] * combined_message[i];
    }
    // Clean up dynamically allocated memory
    delete[] r0;
    delete[] r1;
    delete[] combined_message;

    return answer;
}

// Read macroblock data (Y, Cb, Cr values) from file
void read_macroblock_data(const std::string& filename, std::vector<int>& y_values, 
                         std::vector<int>& cb_values, std::vector<int>& cr_values, 
                         long long macroblock_count) {
    std::ifstream infile(filename);
    if (!infile) {
        fprintf(stderr, "Error: Cannot open file %s for reading\n", filename.c_str());
        exit(1);
    }

    // Clear existing data
    y_values.clear();
    cb_values.clear();
    cr_values.clear();
    macroblock_count = 0;

    std::string line;
    while (std::getline(infile, line)) {
        std::istringstream iss(line);
        int value;
        std::vector<int> row_values;

        // Read all integer values from one line
        while (iss >> value) {
            row_values.push_back(value);
        }

        // Check data format: each line should contain data for 3 channels
        if (row_values.size() % 3 != 0) {
            fprintf(stderr, "Warning: Line %d does not contain multiples of 3 values\n", macroblock_count + 1);
        }

        // Distribute data to Y, Cb, Cr channels
        // Assume data arrangement: Y values, Cb values, Cr values
        int values_per_channel = row_values.size() / 3;
        
        for (int i = 0; i < values_per_channel; ++i) {
            y_values.push_back(row_values[i]);
            cb_values.push_back(row_values[i + values_per_channel]);
            cr_values.push_back(row_values[i + 2 * values_per_channel]);
        }

        macroblock_count++;
    }

    printf("Read %d macroblocks, total values per channel: %zu\n", 
           macroblock_count, y_values.size());
}


// Set random Y, Cb, and Cr values (range 0-255)
void read_random_values(std::vector<int>& y_values, std::vector<int>& cb_values, std::vector<int>& cr_values,int num_values) {
    // Initialize random number generator
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    // Clear existing data
    y_values.clear();
    cb_values.clear();
    cr_values.clear();
  
    
    // Generate random Y values
    for (int i = 0; i < num_values; ++i) {
        y_values.push_back(dis(gen));
    }
    
    // Generate random Cb values
    for (int i = 0; i < num_values; ++i) {
        cb_values.push_back(dis(gen));
    }
    
    // Generate random Cr values
    for (int i = 0; i < num_values; ++i) {
        cr_values.push_back(dis(gen));
    }
}

//Main function
int main(int argc, char* argv[]) {
    int lg_N,C,userandom;
    long long N,M,M_per;
    if (!truepix::parse_args(argc, argv, C, userandom)) {
        return 1;
    }

    if (truepix::enabled()) {
        // truepix: commit with the same packing the GKR circuit uses and
        // publish the resulting roots so prove/open can be pinned to them.
        if (userandom) {
            fprintf(stderr, "truepix requires shared input.txt (userandom=0)\n");
            return 1;
        }
        truepix::Layout lay;
        if (!truepix::make_layout(C, lay)) {
            return 1;
        }
        prime_field::field_element *coefs = nullptr;
        if (!truepix::load_coefs("input.txt", lay, coefs)) {
            return 1;
        }
        expander_init(lay.n / column_size);

        unsigned long long seed = 0;
        if (!truepix::mask_seed_create(seed)) {
            return 1;
        }

        // Build one polynomial at a time from the seed so masked and mask are
        // never both resident (~32MiB peak saving on large N).
        truepix::CommitReport rep_masked, rep_mask;
        {
            printf("Running with mask...\n");
            prime_field::field_element *poly =
                truepix::alloc_masked_from_seed(coefs, lay.n, seed);
            rep_masked = truepix_commit_only(
                poly, lay.n, "transmitted_data_mask.txt", "masked");
            delete[] poly;
        }
        {
            printf("Running without mask...\n");
            prime_field::field_element *poly =
                truepix::alloc_mask_from_seed(lay.n, seed);
            rep_mask = truepix_commit_only(
                poly, lay.n, "transmitted_data_masked.txt", "mask");
            delete[] poly;
        }

        bool ok = rep_masked.ok && rep_mask.ok;
        if (ok) {
            rep_masked.root[64] = '\0';
            rep_mask.root[64] = '\0';
            ok = truepix::write_manifest(lay, rep_masked.root, rep_mask.root, true);
        } else {
            fprintf(stderr, "TruePix: commit phase failed; no manifest written\n");
        }

        delete[] coefs;
        fflush(stdout);
        return ok ? 0 : 1;
    }

    int k = 8;
    M = C*3*(1LL << 8);
    M_per = C*(1LL << 8);
    while ((1LL << k) < M)  // Use 1LL to ensure 64-bit integer operations prevent overflow
    {
        k++;
    }
    
    lg_N= k;
    N = 1 << lg_N;

    // Initialize expander graph
    expander_init(N / column_size);
    
        // Read Y, Cb, and Cr values
    std::vector<int> y_values, cb_values, cr_values;
    if (userandom) {
        read_random_values(y_values, cb_values, cr_values, M_per);
    }
    else{
        read_macroblock_data("input.txt",y_values, cb_values, cr_values, M_per);
    }

    // Calculate total number of values read
    int total_values = y_values.size() + cb_values.size() + cr_values.size();

    // Check if total number of values read equals N, if not pad with zeros
    if (total_values > N) {
        fprintf(stderr, "Error: The total number of Y, Cb, and Cr values exceeds N.\n");
        return 1;
    }

    // Assign Y, Cb, and Cr values to coefs, and pad with zeros
    prime_field::field_element *coefs = new prime_field::field_element[N];
    int index = 0;

    // Assign Y values
    for (int y : y_values) {
        coefs[index++] = prime_field::field_element(y);
    }

    // Assign Cb values
    for (int cb : cb_values) {
        coefs[index++] = prime_field::field_element(cb);
    }

    // Assign Cr values
    for (int cr : cr_values) {
        coefs[index++] = prime_field::field_element(cr);
    }

    // Pad with zeros
    while (index < N) {
        coefs[index++] = prime_field::field_element(0);
    }

    prime_field::field_element *mask = new prime_field::field_element[N];  // Randomly generate mask polynomial
    prime_field::field_element *masked = new prime_field::field_element[N];// Calculate masked result
    for (int i = 0; i < N; ++i) {
        mask[i] = prime_field::random();//Mask
    }
    for (int i = 0; i < N; ++i) {
        masked[i] = coefs[i] + mask[i];//Masked result
    }

    // Generate random vector r, corresponding to r in the statement f(r)=y for the secret polynomial f to be proven in polynomial commitment
    prime_field::field_element *r = new prime_field::field_element[lg_N];
    for (int i = 0; i < lg_N; ++i) {
        r[i] = prime_field::random();
    }
    auto a=evaluate_data_at_r(coefs, r, lg_N, N);
    auto b=evaluate_data_at_r(mask, r, lg_N, N);
    auto c=evaluate_data_at_r(masked, r, lg_N, N);
    if(a == c - b)//Check if the claimed value of the masked polynomial equals the original polynomial plus the mask polynomial's claimed value
    {
        printf("check pass\n");
    }
    else
    {
        printf("check notpass\n");
    }

       // Sequential single-thread: masked then mask (no fork / CPU pinning).
    {
        printf("Running with mask...\n");
        prime_field::field_element *data_copy = new prime_field::field_element[N];
        prime_field::field_element *mask_copy = new prime_field::field_element[N];
        memcpy(data_copy, coefs, sizeof(prime_field::field_element) * N);
        memcpy(mask_copy, mask, sizeof(prime_field::field_element) * N);
        run_commit_and_open(data_copy, mask_copy, N, lg_N, true, r);
        delete[] data_copy;
        delete[] mask_copy;
    }
    {
        printf("Running without mask...\n");
        prime_field::field_element *data_copy = new prime_field::field_element[N];
        prime_field::field_element *mask_copy = new prime_field::field_element[N];
        memcpy(data_copy, coefs, sizeof(prime_field::field_element) * N);
        memcpy(mask_copy, mask, sizeof(prime_field::field_element) * N);
        run_commit_and_open(data_copy, mask_copy, N, lg_N, false, r);
        delete[] data_copy;
        delete[] mask_copy;
    }

    delete[] coefs;
    delete[] mask;
    delete[] r;

    return 0;
}
