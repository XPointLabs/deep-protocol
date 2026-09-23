/* Reproduces the pinned upstream gen_KAT.c ML-DSA-65 transcript.
 * All keys below are deterministic public test vectors, never account keys.
 * Upstream source: pq-code-package/mldsa-native v2.0.0, test/src/gen_KAT.c.
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
#include <stdint.h>
#include <stdio.h>

#include "mldsa_native.h"
#include "src/fips202/fips202.h"

#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#endif

#define KAT_MAX_MESSAGE 2048
#define KAT_PUBLIC_BYTES 1952
#define KAT_SECRET_BYTES 4032
#define KAT_SIGNATURE_BYTES 3309
#define KAT_SEED_BYTES 32
#define KAT_RANDOM_BYTES 32

#define KAT_CALL(name) MLD_API_CONCAT_UNDERSCORE(MLD_CONFIG_NAMESPACE_PREFIX, name)

static void print_hex(const uint8_t *data, size_t length)
{
    size_t index;
    for (index = 0; index < length; index++) printf("%02x", data[index]);
    putchar('\n');
}

int main(void)
{
    uint8_t seed[64];
    uint8_t coins[KAT_SEED_BYTES + KAT_RANDOM_BYTES + KAT_MAX_MESSAGE];
    uint8_t public_key[KAT_PUBLIC_BYTES];
    uint8_t secret_key[KAT_SECRET_BYTES];
    uint8_t signature[KAT_SIGNATURE_BYTES];
    const uint8_t empty_context_prefix[2] = {0, 0};
    size_t index;
    size_t message_length;

#if defined(_WIN32)
    if (_setmode(_fileno(stdout), _O_BINARY) == -1) return 2;
#endif
    for (index = 0; index < sizeof(seed); index++) seed[index] = (uint8_t)(32 + index);
    mld_shake256(coins, sizeof(coins), seed, sizeof(seed));

    for (message_length = 0; message_length < KAT_MAX_MESSAGE;
         message_length = message_length == 0 ? 1 : message_length << 2) {
        const uint8_t *message = coins + KAT_SEED_BYTES + KAT_RANDOM_BYTES;
        mld_shake256(coins, sizeof(coins), coins, sizeof(coins));
        if (KAT_CALL(keypair_internal)(public_key, secret_key, coins) != 0) return 3;
        print_hex(public_key, sizeof(public_key));
        print_hex(secret_key, sizeof(secret_key));
        if (KAT_CALL(signature_internal)(
                signature, message, message_length, empty_context_prefix,
                sizeof(empty_context_prefix), coins + KAT_SEED_BYTES,
                secret_key, 0) != 0) return 4;
        print_hex(signature, sizeof(signature));
        if (KAT_CALL(verify)(signature, message, message_length, NULL, 0,
                             public_key) != 0) return 5;
    }
    return 0;
}
