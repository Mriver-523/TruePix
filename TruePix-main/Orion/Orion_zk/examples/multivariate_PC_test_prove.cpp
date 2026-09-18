#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <chrono>
#include <cstring>      // memory operations, e.g., memcpy
#include <unistd.h>
#include <sys/wait.h>
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

    // Open and verify data
    timer_mark(open_t0);
    auto result = open_and_verify(r, lg_N, N, h,use_mask);
    timer_mark(open_t1);

    // Output running results for masked polynomial
    printf("Open time(masked):: %lf\n", time_diff(open_t0, open_t1) - last_encode_preprocess_time);
    printf("Result: %s\n", result.second ? "succ" : "fail");

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
        
    // Open and verify data
    timer_mark(open_t0);
    auto result = open_and_verify(r, lg_N, N, h,use_mask);
    timer_mark(open_t1);

    // Output running results for mask polynomial
    printf("Open time(mask): %lf\n", time_diff(open_t0, open_t1) - last_encode_preprocess_time);
    printf("Result: %s\n", result.second ? "succ" : "fail");

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
// truepix: commit to one polynomial, require its Merkle root to match the
// root published by the commit phase, then open at the GKR point.
static truepix::OpenReport truepix_commit_and_open(
    prime_field::field_element *poly,
    long long N,
    int lg_N,
    prime_field::field_element *r_orion,
    bool use_group1,
    const std::string& expected_root,
    const std::string& transmitted_file,
    const char* label)
{
    truepix::OpenReport rep;
    rep.open_ok = 0;
    rep.root_ok = 0;
    rep.real = 0;
    rep.img = 0;

    timer_mark(commit_t0);
    auto h = commit(poly, N);
    timer_mark(commit_t1);
    printf("Commit time(%s) %lf\n", label, time_diff(commit_t0, commit_t1));

    const std::string root = truepix::root_hex(h[1]);
    rep.root_ok = (root == expected_root) ? 1 : 0;
    if (!rep.root_ok) {
        fprintf(stderr,
                "TruePix: %s Merkle root mismatch\n  committed: %s\n  manifest:  %s\n",
                label, root.c_str(), expected_root.c_str());
    }

    long long size_after_padding = 1;
    while (size_after_padding < N / column_size * 2)
        size_after_padding *= 2;
    int h_length = size_after_padding * 2;
    write_transmitted_data_commit(h, h_length, transmitted_file);

    timer_mark(open_t0);
    auto result = open_and_verify(r_orion, lg_N, N, h, use_group1);
    timer_mark(open_t1);
    printf("Open time(%s): %lf\n", label, time_diff(open_t0, open_t1) - last_encode_preprocess_time);
    printf("Result: %s\n", result.second ? "succ" : "fail");

    rep.open_ok = result.second ? 1 : 0;
    rep.real = result.first.real;
    rep.img = result.first.img;
    return rep;
}

int main(int argc, char* argv[]) {
    int lg_N,C,userandom;
    long long N,M,M_per;
    if (!truepix::parse_args(argc, argv, C, userandom)) {
        return 1;
    }

    if (truepix::enabled()) {
        // Same packing, same mask and same point as the commit and open phases;
        // before this the prove binary used the legacy Y/Cb/Cr packing and so
        // committed to a completely different polynomial.
        if (userandom) {
            fprintf(stderr, "truepix requires shared input.txt (userandom=0)\n");
            return 1;
        }
        truepix::Layout lay;
        truepix::Manifest manifest;
        if (!truepix::make_layout(C, lay) || !truepix::read_manifest(manifest)) {
            return 1;
        }
        if (!manifest.zk) {
            fprintf(stderr, "TruePix: ZK Orion cannot open a non-ZK commitment\n");
            return 1;
        }
        if (!truepix::layout_matches(lay, manifest.lay)) {
            fprintf(stderr, "TruePix: layout does not match the commit manifest\n");
            return 1;
        }
        prime_field::field_element *coefs = nullptr;
        if (!truepix::load_coefs("input.txt", lay, coefs)) {
            return 1;
        }
        expander_init(lay.n / column_size);

        unsigned long long seed = 0;
        if (!truepix::mask_seed_read(seed)) {
            return 1;
        }

        prime_field::field_element *r = new prime_field::field_element[lay.lg_n];
        prime_field::field_element *r_orion = new prime_field::field_element[lay.lg_n];
        if (!truepix::load_gkr_point(r, lay.lg_n)) {
            return 1;
        }
        truepix::reverse_point(r, r_orion, lay.lg_n);

        // Serial openings in isolated children. Parent keeps only coefs (+point);
        // each child regenerates mask/masked from the commit seed so the parent
        // never holds all three N-element polynomials at once (~32MiB saved).
        fflush(stdout);
        truepix::OpenReport rep_masked, rep_mask;
        memset(&rep_masked, 0, sizeof(rep_masked));
        memset(&rep_mask, 0, sizeof(rep_mask));
        bool children_ok = true;

        {
            int fd[2];
            if (pipe(fd) != 0) { perror("pipe"); return 1; }
            pid_t pid = fork();
            if (pid == 0) {
                close(fd[0]);
                printf("Running with mask...\n");
                prime_field::field_element *poly =
                    truepix::alloc_masked_from_seed(coefs, lay.n, seed);
                truepix::OpenReport rep = truepix_commit_and_open(
                    poly, lay.n, lay.lg_n, r_orion, true,
                    manifest.masked_root, "transmitted_data_mask.txt", "masked");
                delete[] poly;
                ssize_t wrote = write(fd[1], &rep, sizeof(rep));
                close(fd[1]);
                fflush(stdout);
                _exit(wrote == (ssize_t)sizeof(rep) ? 0 : 1);
            }
            close(fd[1]);
            bool got = read(fd[0], &rep_masked, sizeof(rep_masked)) == (ssize_t)sizeof(rep_masked);
            close(fd[0]);
            int st = 0;
            waitpid(pid, &st, 0);
            if (!got || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
                children_ok = false;
                fprintf(stderr, "TruePix: masked opening child failed\n");
            }
        }
        {
            int fd[2];
            if (pipe(fd) != 0) { perror("pipe"); return 1; }
            pid_t pid = fork();
            if (pid == 0) {
                close(fd[0]);
                printf("Running without mask...\n");
                prime_field::field_element *poly =
                    truepix::alloc_mask_from_seed(lay.n, seed);
                truepix::OpenReport rep = truepix_commit_and_open(
                    poly, lay.n, lay.lg_n, r_orion, false,
                    manifest.mask_root, "transmitted_data_masked.txt", "mask");
                delete[] poly;
                ssize_t wrote = write(fd[1], &rep, sizeof(rep));
                close(fd[1]);
                fflush(stdout);
                _exit(wrote == (ssize_t)sizeof(rep) ? 0 : 1);
            }
            close(fd[1]);
            bool got = read(fd[0], &rep_mask, sizeof(rep_mask)) == (ssize_t)sizeof(rep_mask);
            close(fd[0]);
            int st = 0;
            waitpid(pid, &st, 0);
            if (!got || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
                children_ok = false;
                fprintf(stderr, "TruePix: mask opening child failed\n");
            }
        }

        prime_field::field_element v_masked, v_mask;
        v_masked.real = rep_masked.real;
        v_masked.img = rep_masked.img;
        v_mask.real = rep_mask.real;
        v_mask.img = rep_mask.img;
        prime_field::field_element value = v_masked - v_mask;
        bool consistent = (value == truepix::mle_gkr(coefs, r, lay.lg_n, lay.n));

        bool ok = children_ok && rep_masked.open_ok && rep_mask.open_ok &&
                  rep_masked.root_ok && rep_mask.root_ok && consistent;
        printf("TruePix prove: open_masked=%d open_mask=%d root_masked=%d "
               "root_mask=%d mle_consistent=%d -> ok=%d\n",
               rep_masked.open_ok, rep_mask.open_ok, rep_masked.root_ok,
               rep_mask.root_ok, (int)consistent, (int)ok);
        printf(ok ? "check pass\n" : "check notpass\n");

        delete[] coefs;
        delete[] r;
        delete[] r_orion;
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

    // Serial legacy openings in isolated child processes.
    {
        pid_t pid = fork();
        if (pid == 0) {
            printf("Running with mask...\n");
            prime_field::field_element *data_copy = new prime_field::field_element[N];
            prime_field::field_element *mask_copy = new prime_field::field_element[N];
            memcpy(data_copy, coefs, sizeof(prime_field::field_element) * N);
            memcpy(mask_copy, mask, sizeof(prime_field::field_element) * N);
            run_commit_and_open(data_copy, mask_copy, N, lg_N, true, r);
            delete[] data_copy;
            delete[] mask_copy;
            _exit(0);
        }
        waitpid(pid, nullptr, 0);
    }
    {
        pid_t pid = fork();
        if (pid == 0) {
            printf("Running without mask...\n");
            prime_field::field_element *data_copy = new prime_field::field_element[N];
            prime_field::field_element *mask_copy = new prime_field::field_element[N];
            memcpy(data_copy, coefs, sizeof(prime_field::field_element) * N);
            memcpy(mask_copy, mask, sizeof(prime_field::field_element) * N);
            run_commit_and_open(data_copy, mask_copy, N, lg_N, false, r);
            delete[] data_copy;
            delete[] mask_copy;
            _exit(0);
        }
        waitpid(pid, nullptr, 0);
    }

    delete[] coefs;
    delete[] mask;
    delete[] r;

    return 0;
}
