#include "truepix/orion_fs.h"
#include <cstdlib>
#include <cstring>

namespace truepix_orion {

OrionMode orion_mode_from_env() {
    const char *m = std::getenv("TRUEPIX_ORION_MODE");
    if (m && (std::strcmp(m, "interactive") == 0 ||
              std::strcmp(m, "INTERACTIVE") == 0 ||
              std::strcmp(m, "interact") == 0))
        return OrionMode::Interactive;
    return OrionMode::Nizk;
}

const char *orion_mode_name(OrionMode m) {
    return m == OrionMode::Nizk ? "nizk" : "interactive";
}

FsTranscript::FsTranscript() { reset(); }

void FsTranscript::reset() {
    std::memset(state_, 0, sizeof(state_));
    // Domain separator
    static const char kDom[] = "truepix/orion-fs/v1";
    absorb(kDom, sizeof(kDom) - 1);
    pool_used_ = 32; // force refill on first squeeze
}

void FsTranscript::absorb(const void *data, size_t n) {
    const uint8_t *p = static_cast<const uint8_t *>(data);
    while (n > 0) {
        uint8_t block[64];
        std::memset(block, 0, sizeof(block));
        std::memcpy(block, state_, 32);
        size_t take = n < 32 ? n : 32;
        std::memcpy(block + 32, p, take);
        __hhash_digest out;
        my_hhash(block, &out);
        std::memcpy(state_, &out, 32);
        p += take;
        n -= take;
    }
    pool_used_ = 32;
}

void FsTranscript::absorb_u64(uint64_t x) { absorb(&x, sizeof(x)); }

void FsTranscript::absorb_label(const char *label) {
    absorb(label, std::strlen(label));
}

void FsTranscript::absorb_digest(const __hhash_digest &d) {
    absorb(&d, sizeof(d));
}

void FsTranscript::absorb_field(const prime_field::field_element &fe) {
    absorb(&fe.real, sizeof(fe.real));
    absorb(&fe.img, sizeof(fe.img));
}

void FsTranscript::refill() {
    uint8_t block[64];
    std::memset(block, 0, sizeof(block));
    std::memcpy(block, state_, 32);
    block[32] = 0x01; // squeeze domain
    __hhash_digest out;
    my_hhash(block, &out);
    std::memcpy(pool_, &out, 32);
    // advance state
    block[32] = 0x02;
    my_hhash(block, &out);
    std::memcpy(state_, &out, 32);
    pool_used_ = 0;
}

uint64_t FsTranscript::squeeze_u64() {
    if (pool_used_ + 8 > 32)
        refill();
    uint64_t v = 0;
    std::memcpy(&v, pool_ + pool_used_, 8);
    pool_used_ += 8;
    return v;
}

prime_field::field_element FsTranscript::squeeze_field() {
    prime_field::field_element fe;
    fe.real = squeeze_u64() % prime_field::mod;
    fe.img = squeeze_u64() % prime_field::mod;
    return fe;
}

int FsTranscript::squeeze_index(int bound) {
    if (bound <= 0)
        return 0;
    return static_cast<int>(squeeze_u64() % static_cast<uint64_t>(bound));
}

static FsTranscript g_fs;

FsTranscript &global_fs() { return g_fs; }

void fs_reset_global() { g_fs.reset(); }

prime_field::field_element orion_challenge_field() {
    if (orion_mode_from_env() == OrionMode::Nizk)
        return global_fs().squeeze_field();
    return prime_field::random();
}

prime_field::field_element *orion_challenge_fields(unsigned int size) {
    auto *ret = new prime_field::field_element[size];
    for (unsigned int i = 0; i < size; ++i)
        ret[i] = orion_challenge_field();
    return ret;
}

int orion_challenge_index(int bound) {
    if (orion_mode_from_env() == OrionMode::Nizk)
        return global_fs().squeeze_index(bound);
    if (bound <= 0)
        return 0;
    return rand() % bound;
}

} // namespace truepix_orion
