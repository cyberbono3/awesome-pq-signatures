#include <stddef.h>
#include <stdint.h>

#include "api.h"
#include "csprng_hash.h"

static CSPRNG_STATE_T platform_csprng_state;

void cross_rs_init_rng(
    const unsigned char *seed,
    uint32_t seed_len,
    uint16_t dsc
) {
    csprng_initialize(&platform_csprng_state, seed, seed_len, dsc);
}

void randombytes(unsigned char *x, unsigned long long xlen) {
    csprng_randombytes(x, xlen, &platform_csprng_state);
}

size_t cross_rs_public_key_bytes(void) {
    return CRYPTO_PUBLICKEYBYTES;
}

size_t cross_rs_secret_key_bytes(void) {
    return CRYPTO_SECRETKEYBYTES;
}

size_t cross_rs_signature_bytes(void) {
    return CRYPTO_BYTES;
}
