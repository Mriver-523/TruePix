#pragma once
/**
 * Fiat--Shamir transcript for Orion TruePix NIZK mode.
 *
 * TRUEPIX_ORION_MODE:
 *   nizk (default)        — challenges from this transcript (Fiat--Shamir)
 *   interactive           — legacy rand()/prime_field::random()
 */
#include "infrastructure/my_hhash.h"
#include "linear_gkr/prime_field.h"
#include <cstddef>
#include <cstdint>
#include <vector>

namespace truepix_orion {

enum class OrionMode {
    Interactive = 0,
    Nizk = 1,
};

OrionMode orion_mode_from_env();
const char *orion_mode_name(OrionMode m);

class FsTranscript {
public:
    FsTranscript();
    void reset();
    void absorb(const void *data, size_t n);
    void absorb_u64(uint64_t x);
    void absorb_label(const char *label);
    void absorb_digest(const __hhash_digest &d);
    void absorb_field(const prime_field::field_element &fe);

    uint64_t squeeze_u64();
    prime_field::field_element squeeze_field();
    /** Uniform in [0, bound). bound must be > 0. */
    int squeeze_index(int bound);

private:
    uint8_t state_[32];
    uint8_t pool_[32];
    int pool_used_;
    void refill();
};

/** Global FS used when mode == Nizk. */
FsTranscript &global_fs();
void fs_reset_global();

/** Challenge helpers: FS when Nizk, else legacy RNG. */
prime_field::field_element orion_challenge_field();
prime_field::field_element *orion_challenge_fields(unsigned int size);
int orion_challenge_index(int bound);

} // namespace truepix_orion
