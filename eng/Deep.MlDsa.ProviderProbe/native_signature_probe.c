/* Public deterministic interoperability fixture. The fixed 00..1f seed must
 * never be used for an account. Writes only its signature to stdout. */
#include <stdint.h>
#include <stdio.h>
#include "deep_mldsa_v1.h"

int main(void)
{
    uint8_t seed[32];
    uint8_t rnd[32] = {0};
    uint8_t signature[3309];
    uint8_t empty_context = 0;
    const uint8_t message[] = "Deep/PQRoot/signature-differential/v1";
    int32_t result;
    size_t written;
    size_t index;

    for (index = 0; index < sizeof(seed); index++) seed[index] = (uint8_t)index;
    result = deep_mldsa_v1_sign_from_seed(
        seed, sizeof(seed), rnd, sizeof(rnd),
        &empty_context, 0, message, sizeof(message) - 1,
        signature, sizeof(signature));
    (void)deep_mldsa_v1_zero(seed, sizeof(seed));
    (void)deep_mldsa_v1_zero(rnd, sizeof(rnd));
    if (result != DEEP_MLDSA_V1_OK) {
        (void)deep_mldsa_v1_zero(signature, sizeof(signature));
        return 2;
    }
    written = fwrite(signature, 1, sizeof(signature), stdout);
    (void)deep_mldsa_v1_zero(signature, sizeof(signature));
    return written == 3309 ? 0 : 3;
}
