#include <stddef.h>
#include <stdint.h>

#include "api.h"
#include "rng.h"

void less_rs_init_rng(
    const unsigned char *seed,
    uint32_t seed_len,
    uint16_t dsc
) {
    initialize_csprng_ds(&platform_csprng_state, seed, seed_len, dsc);
}

size_t less_rs_public_key_bytes(void) {
    return CRYPTO_PUBLICKEYBYTES;
}

size_t less_rs_secret_key_bytes(void) {
    return CRYPTO_SECRETKEYBYTES;
}

size_t less_rs_signature_bytes(void) {
    return CRYPTO_BYTES;
}
