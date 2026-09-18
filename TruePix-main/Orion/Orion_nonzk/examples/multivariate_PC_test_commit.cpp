#include <cstdio>
#include <fstream>
#include <sstream>
#include <chrono>
#include "linear_code/linear_code_encode.h"
#include "VPD/linearPC.h"
#include "truepix/truepix_gkr.h"
#include <random> 
#define timer_mark(x) auto x = std::chrono::high_resolution_clock::now()
#define time_diff(start, end) (std::chrono::duration_cast<std::chrono::duration<double>>(end - start).count())

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

int main(int argc, char* argv[]) {
    int lg_N,C,userandom;
    long long N,M,M_per;
    if (!truepix::parse_args(argc, argv, C, userandom)) {
        return 1;
    }

    if (truepix::enabled()) {
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

        timer_mark(commit_t0);
        auto h = commit(coefs, lay.n);
        timer_mark(commit_t1);
        printf("Commit time %lf\n", time_diff(commit_t0, commit_t1));

        const std::string root = truepix::root_hex(h[1]);
        long long size_after_padding = 1;
        while (size_after_padding < lay.n / column_size * 2)
            size_after_padding *= 2;
        int h_length = size_after_padding * 2;
        write_transmitted_data_commit(h, h_length, "transmitted_data.txt");
        bool ok = truepix::write_manifest(lay, root, "", false);
        delete[] coefs;
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

    timer_mark(commit_t0);
    auto h = commit(coefs, N);
    timer_mark(commit_t1);
    printf("Commit size %zu\n", sizeof(h));
    printf("Commit time %lf\n", time_diff(commit_t0, commit_t1));
    
    // Calculate lengths of various arrays
    long long size_after_padding = 1;
    while (size_after_padding < N / column_size * 2)
        size_after_padding *= 2;
    int h_length = size_after_padding * 2; // Full Merkle tree size
        
    // Write all data that needs to be transmitted to file
    write_transmitted_data_commit(
        h, h_length,
        "transmitted_data.txt");
    return 0;
}
