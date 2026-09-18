#pragma once
//
// TruePix protocol truepix: shared input layout, deterministic mask and
// commitment manifest.
//
// The commit / prove / open example binaries all include this header so that
// the three phases commit to *the same* polynomial. Previously each binary
// carried its own copy of the packing code and only the open binary had been
// updated, so the three phases were committing to different polynomials.
//
// Layout "copy-major-384-const128-pad512-v1":
//   flat index = copy * padded_copy_size + wire
//   wire  [0, copy_size)   <- values from one line of input.txt
//   wire  const_idx        <- circuit constant wire (skipped when const_idx < 0)
//   rest                   <- zero
//   copies [C, padded_copies) are all zero
// The variable order is LSB-first over the flat index, matching Fennel's
// VerifierIOMLExt / util.bit_is_set.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "linear_gkr/prime_field.h"
#include "infrastructure/merkle_tree.h"
#include "linear_code/parameter.h"

namespace truepix {

const char *const PROTOCOL_ID = "truepix";
const char *const LAYOUT_ID = "copy-major-384-const128-pad512-v1";
const int PADDED_COPY_SIZE = 512;

inline bool enabled()
{
    const char *e = getenv("TRUEPIX_PROTOCOL");
    return e != nullptr && std::string(e) == PROTOCOL_ID;
}

inline std::string env_or(const char *name, const char *fallback)
{
    const char *e = getenv(name);
    return (e != nullptr && *e != '\0') ? std::string(e) : std::string(fallback);
}

// argv[1] = number of copies, argv[2] = userandom. Callers used to pass
// Python's "None" here, which sscanf silently ignored and left the flag
// uninitialised.
inline bool parse_args(int argc, char *argv[], int &copies, int &userandom)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <copies> <userandom>\n", argv[0]);
        return false;
    }
    if (sscanf(argv[1], "%d", &copies) != 1 || copies <= 0) {
        fprintf(stderr, "invalid copies '%s': expected a positive integer\n", argv[1]);
        return false;
    }
    if (sscanf(argv[2], "%d", &userandom) != 1 ||
        (userandom != 0 && userandom != 1)) {
        fprintf(stderr, "invalid userandom '%s': expected 0 or 1\n", argv[2]);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------- layout ----

struct Layout {
    int copies = 0;
    int padded_copies = 0;
    int copy_size = 384;
    int padded_copy_size = PADDED_COPY_SIZE;
    int const_idx = 384;
    int const_val = 128;
    long long n = 0;
    int lg_n = 0;
};

inline int next_pow2_int(int x)
{
    if (x <= 1) return 1;
    int p = 1;
    while (p < x) p <<= 1;
    return p;
}

// Derive the layout from the environment. Returns false on inconsistent input.
inline bool make_layout(int copies, Layout &out)
{
    out = Layout();
    out.copies = copies;
    if (const char *e = getenv("TRUEPIX_COPY_SIZE")) out.copy_size = atoi(e);
    if (const char *e = getenv("TRUEPIX_CONST_IDX")) out.const_idx = atoi(e);
    if (const char *e = getenv("TRUEPIX_CONST_VAL")) out.const_val = atoi(e);

    if (copies <= 0) {
        fprintf(stderr, "TruePix: invalid copies=%d\n", copies);
        return false;
    }
    if (out.copy_size <= 0 || out.copy_size > out.padded_copy_size) {
        fprintf(stderr, "TruePix: invalid TRUEPIX_COPY_SIZE=%d (padded copy is %d)\n",
                out.copy_size, out.padded_copy_size);
        return false;
    }
    if (out.const_idx >= out.padded_copy_size) {
        fprintf(stderr, "TruePix: TRUEPIX_CONST_IDX=%d out of range\n", out.const_idx);
        return false;
    }
    // A constant wire inside the region filled from input.txt would be
    // overwritten by file data on one side and by the constant on the other,
    // which is exactly the silent GKR/Orion mismatch we want to rule out.
    if (out.const_idx >= 0 && out.const_idx < out.copy_size) {
        fprintf(stderr,
                "TruePix: TRUEPIX_CONST_IDX=%d overlaps the %d values read from "
                "input.txt; GKR and Orion would pack different polynomials\n",
                out.const_idx, out.copy_size);
        return false;
    }

    out.padded_copies = next_pow2_int(copies);
    out.n = (long long)out.padded_copies * out.padded_copy_size;
    out.lg_n = 0;
    while ((1LL << out.lg_n) < out.n) out.lg_n++;
    if ((1LL << out.lg_n) != out.n) {
        fprintf(stderr, "TruePix: N=%lld is not a power of two\n", out.n);
        return false;
    }
    if (out.n % column_size != 0) {
        fprintf(stderr, "TruePix: N=%lld not divisible by column_size=%d\n",
                out.n, column_size);
        return false;
    }
    return true;
}

// Load input.txt into a freshly allocated coefficient array of length lay.n.
inline bool load_coefs(const std::string &filename, const Layout &lay,
                       prime_field::field_element *&coefs)
{
    coefs = new prime_field::field_element[lay.n];
    for (long long i = 0; i < lay.n; ++i) {
        coefs[i] = prime_field::field_element(0ULL);
    }

    std::ifstream infile(filename);
    if (!infile) {
        fprintf(stderr, "TruePix: cannot open %s for reading\n", filename.c_str());
        return false;
    }

    int copy = 0;
    std::string line;
    while (std::getline(infile, line) && copy < lay.copies) {
        std::istringstream iss(line);
        long long value;
        int filled = 0;
        long long base = (long long)copy * lay.padded_copy_size;
        while (iss >> value && filled < lay.copy_size) {
            if (value < 0) {
                fprintf(stderr, "TruePix: negative value on line %d of %s\n",
                        copy + 1, filename.c_str());
                return false;
            }
            coefs[base + filled] = prime_field::field_element((unsigned long long)value);
            filled++;
        }
        if (filled != lay.copy_size) {
            fprintf(stderr, "TruePix: copy %d has %d values, expected %d\n",
                    copy, filled, lay.copy_size);
            return false;
        }
        if (lay.const_idx >= 0) {
            coefs[base + lay.const_idx] =
                prime_field::field_element((unsigned long long)lay.const_val);
        }
        copy++;
    }
    if (copy < lay.copies) {
        fprintf(stderr, "TruePix: %s has %d lines, expected %d\n",
                filename.c_str(), copy, lay.copies);
        return false;
    }
    printf("TruePix layout: C=%d padded_copies=%d N=%lld lg_N=%d copy_size=%d const[%d]=%d\n",
           lay.copies, lay.padded_copies, lay.n, lay.lg_n, lay.copy_size,
           lay.const_idx, lay.const_val);
    return true;
}

// ------------------------------------------------------------------- MLE ----

// MLE at r with LSB-first variable order (r[b] pairs with bit b of the index),
// evaluated by successive folding so the cost is O(N) rather than O(N lg N).
inline prime_field::field_element mle_gkr(const prime_field::field_element *data,
                                         const prime_field::field_element *r,
                                         int lg_n, long long n)
{
    std::vector<prime_field::field_element> buf(data, data + n);
    long long len = n;
    for (int bit = 0; bit < lg_n; ++bit) {
        const prime_field::field_element one = prime_field::field_element(1ULL);
        const prime_field::field_element rb = r[bit];
        const prime_field::field_element omb = one - rb;
        long long half = len / 2;
        for (long long i = 0; i < half; ++i) {
            buf[i] = buf[2 * i] * omb + buf[2 * i + 1] * rb;
        }
        len = half;
    }
    return buf[0];
}

// open_and_verify() builds its beta tables MSB-first over the flat index, so
// the GKR point has to be reversed before it is handed to the PC opening.
inline void reverse_point(const prime_field::field_element *src,
                          prime_field::field_element *dst, int lg_n)
{
    for (int i = 0; i < lg_n; ++i) {
        dst[i] = src[lg_n - 1 - i];
    }
}

// Load the Fp2 evaluation point written by Fennel. Returns false when the file
// is absent or has the wrong arity; callers must not fall back to a random
// point, since the resulting opening would say nothing about the GKR claim.
inline bool load_gkr_point(prime_field::field_element *r, int lg_n)
{
    const char *point_env = getenv("TRUEPIX_GKR_POINT_FILE");
    if (point_env == nullptr) {
        fprintf(stderr, "TruePix: TRUEPIX_GKR_POINT_FILE is not set\n");
        return false;
    }
    std::string txt_path(point_env);
    if (txt_path.size() >= 5 && txt_path.substr(txt_path.size() - 5) == ".json") {
        txt_path = txt_path.substr(0, txt_path.size() - 5) + ".txt";
    } else if (txt_path.size() < 4 || txt_path.substr(txt_path.size() - 4) != ".txt") {
        txt_path += ".txt";
    }
    std::ifstream in(txt_path);
    if (!in) {
        fprintf(stderr, "TruePix: cannot open GKR point file %s\n", txt_path.c_str());
        return false;
    }
    int ncoords = 0;
    if (!(in >> ncoords) || ncoords != lg_n) {
        fprintf(stderr, "TruePix: GKR point has %d coordinates, expected %d\n",
                ncoords, lg_n);
        return false;
    }
    for (int i = 0; i < lg_n; ++i) {
        unsigned long long re = 0, im = 0;
        if (!(in >> re >> im)) {
            fprintf(stderr, "TruePix: GKR point file %s truncated at %d\n",
                    txt_path.c_str(), i);
            return false;
        }
        if (re >= prime_field::mod || im >= prime_field::mod) {
            fprintf(stderr, "TruePix: GKR point coordinate %d is not reduced\n", i);
            return false;
        }
        r[i].real = re;
        r[i].img = im;
    }
    printf("TruePix: loaded GKR point from %s\n", txt_path.c_str());
    return true;
}

// ------------------------------------------------------------------ mask ----
//
// The mask polynomial has to be identical in the commit, prove and open
// phases, which run as separate processes. It is therefore derived from a
// seed instead of being sampled independently in each process. The seed is
// prover-side secret state (like the mask itself); only the resulting Merkle
// roots are published in the manifest.

inline std::string mask_seed_path()
{
    return env_or("TRUEPIX_MASK_SEED_FILE", "orion_mask_seed.txt");
}

inline bool mask_seed_read(unsigned long long &seed)
{
    std::ifstream in(mask_seed_path());
    if (!in) {
        fprintf(stderr, "TruePix: cannot open mask seed file %s; run the commit "
                        "phase (run_fennel_signer.py) first\n",
                mask_seed_path().c_str());
        return false;
    }
    if (!(in >> seed)) {
        fprintf(stderr, "TruePix: malformed mask seed file %s\n", mask_seed_path().c_str());
        return false;
    }
    return true;
}

inline bool mask_seed_create(unsigned long long &seed)
{
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (!urandom || !urandom.read(reinterpret_cast<char *>(&seed), sizeof(seed))) {
        fprintf(stderr, "TruePix: cannot read /dev/urandom for the mask seed\n");
        return false;
    }
    std::ofstream out(mask_seed_path(), std::ios::trunc);
    if (!out) {
        fprintf(stderr, "TruePix: cannot write mask seed file %s\n", mask_seed_path().c_str());
        return false;
    }
    out << seed << "\n";
    return true;
}

inline unsigned long long splitmix64(unsigned long long &state)
{
    state += 0x9E3779B97F4A7C15ULL;
    unsigned long long z = state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

inline void fill_mask(prime_field::field_element *mask, long long n,
                      unsigned long long seed)
{
    unsigned long long state = seed;
    for (long long i = 0; i < n; ++i) {
        mask[i].real = splitmix64(state) % prime_field::mod;
        mask[i].img = splitmix64(state) % prime_field::mod;
    }
}

// -------------------------------------------------------------- manifest ----

inline std::string root_hex(const __hhash_digest &d)
{
    unsigned long long parts[4] = {
        (unsigned long long)_mm_extract_epi64(d.h0, 1),
        (unsigned long long)_mm_extract_epi64(d.h0, 0),
        (unsigned long long)_mm_extract_epi64(d.h1, 1),
        (unsigned long long)_mm_extract_epi64(d.h1, 0),
    };
    char buf[65];
    for (int i = 0; i < 4; ++i) {
        snprintf(buf + i * 16, 17, "%016llx", parts[i]);
    }
    return std::string(buf, 64);
}

inline std::string manifest_path()
{
    return env_or("TRUEPIX_ORION_COMMIT_FILE", "orion_commit.json");
}

inline bool write_manifest(const Layout &lay, const std::string &masked_root,
                           const std::string &mask_root, bool zk = true)
{
    const std::string path = manifest_path();
    std::ofstream out(path, std::ios::trunc);
    if (!out) {
        fprintf(stderr, "TruePix: cannot write commit manifest %s\n", path.c_str());
        return false;
    }
    out << "{\n";
    out << "  \"protocol\": \"" << PROTOCOL_ID << "\",\n";
    out << "  \"layout\": \"" << LAYOUT_ID << "\",\n";
    out << "  \"zk\": " << (zk ? "true" : "false") << ",\n";
    out << "  \"copies\": " << lay.copies << ",\n";
    out << "  \"padded_copies\": " << lay.padded_copies << ",\n";
    out << "  \"copy_size\": " << lay.copy_size << ",\n";
    out << "  \"padded_copy_size\": " << lay.padded_copy_size << ",\n";
    out << "  \"const_idx\": " << lay.const_idx << ",\n";
    out << "  \"const_val\": " << lay.const_val << ",\n";
    out << "  \"n\": " << lay.n << ",\n";
    out << "  \"lg_n\": " << lay.lg_n << ",\n";
    out << "  \"masked_root\": \"" << masked_root << "\",\n";
    out << "  \"mask_root\": \"" << mask_root << "\"\n";
    out << "}\n";
    printf("TruePix: wrote commit manifest %s (zk=%s masked_root=%s mask_root=%s)\n",
           path.c_str(), zk ? "true" : "false", masked_root.c_str(), mask_root.c_str());
    return true;
}

struct Manifest {
    Layout lay;
    std::string masked_root;
    std::string mask_root;
    bool zk = true;
};

// Minimal reader for the flat JSON produced by write_manifest().
inline bool read_manifest(Manifest &out)
{
    const std::string path = manifest_path();
    std::ifstream in(path);
    if (!in) {
        fprintf(stderr, "TruePix: cannot open commit manifest %s; run the commit "
                        "phase (run_fennel_signer.py) first\n", path.c_str());
        return false;
    }
    std::string body((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());

    auto find_str = [&](const char *key, std::string &dst) -> bool {
        std::string pat = std::string("\"") + key + "\"";
        size_t k = body.find(pat);
        if (k == std::string::npos) return false;
        size_t colon = body.find(':', k + pat.size());
        if (colon == std::string::npos) return false;
        size_t q1 = body.find('"', colon);
        if (q1 == std::string::npos) return false;
        size_t q2 = body.find('"', q1 + 1);
        if (q2 == std::string::npos) return false;
        dst = body.substr(q1 + 1, q2 - q1 - 1);
        return true;
    };
    auto find_int = [&](const char *key, long long &dst) -> bool {
        std::string pat = std::string("\"") + key + "\"";
        size_t k = body.find(pat);
        if (k == std::string::npos) return false;
        size_t colon = body.find(':', k + pat.size());
        if (colon == std::string::npos) return false;
        dst = strtoll(body.c_str() + colon + 1, nullptr, 10);
        return true;
    };

    auto find_bool = [&](const char *key, bool &dst) -> bool {
        std::string pat = std::string("\"") + key + "\"";
        size_t k = body.find(pat);
        if (k == std::string::npos) return false;
        size_t colon = body.find(':', k + pat.size());
        if (colon == std::string::npos) return false;
        size_t p = colon + 1;
        while (p < body.size() && (body[p] == ' ' || body[p] == '\t' || body[p] == '\n')) p++;
        if (body.compare(p, 4, "true") == 0) { dst = true; return true; }
        if (body.compare(p, 5, "false") == 0) { dst = false; return true; }
        return false;
    };

    std::string protocol, layout;
    long long copies = 0, padded_copies = 0, copy_size = 0, padded_copy = 0;
    long long const_idx = 0, const_val = 0, n = 0, lg_n = 0;
    out.zk = true;
    if (!find_str("protocol", protocol) || !find_str("layout", layout) ||
        !find_str("masked_root", out.masked_root) ||
        !find_str("mask_root", out.mask_root) ||
        !find_int("copies", copies) || !find_int("padded_copies", padded_copies) ||
        !find_int("copy_size", copy_size) || !find_int("padded_copy_size", padded_copy) ||
        !find_int("const_idx", const_idx) || !find_int("const_val", const_val) ||
        !find_int("n", n) || !find_int("lg_n", lg_n)) {
        fprintf(stderr, "TruePix: commit manifest %s is missing fields\n", path.c_str());
        return false;
    }
    find_bool("zk", out.zk);
    if (protocol != PROTOCOL_ID || layout != LAYOUT_ID) {
        fprintf(stderr, "TruePix: commit manifest %s has protocol=%s layout=%s\n",
                path.c_str(), protocol.c_str(), layout.c_str());
        return false;
    }
    out.lay.copies = (int)copies;
    out.lay.padded_copies = (int)padded_copies;
    out.lay.copy_size = (int)copy_size;
    out.lay.padded_copy_size = (int)padded_copy;
    out.lay.const_idx = (int)const_idx;
    out.lay.const_val = (int)const_val;
    out.lay.n = n;
    out.lay.lg_n = (int)lg_n;
    return true;
}

inline bool layout_matches(const Layout &a, const Layout &b)
{
    return a.copies == b.copies && a.padded_copies == b.padded_copies &&
           a.copy_size == b.copy_size && a.padded_copy_size == b.padded_copy_size &&
           a.const_idx == b.const_idx && a.const_val == b.const_val &&
           a.n == b.n && a.lg_n == b.lg_n;
}

// Report a child's commit/open outcome back to the parent over a pipe.
struct OpenReport {
    int open_ok;   // open_and_verify() accepted
    int root_ok;   // recomputed Merkle root matched the manifest
    unsigned long long real;
    unsigned long long img;
};

struct CommitReport {
    int ok;
    char root[65];
};

} // namespace truepix
