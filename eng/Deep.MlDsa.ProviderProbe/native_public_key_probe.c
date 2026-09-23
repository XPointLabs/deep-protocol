/* Test-only ML-DSA-65 differential fixture against mldsa-native v2.0.0.
 * Writes only the public key to stdout. Never use this fixed seed for accounts.
 */
#include <stdint.h>
#include <stdio.h>
#include "mldsa_native.h"

_Static_assert(MLD_CONFIG_PARAMETER_SET == 65, "This probe requires ML-DSA-65");

static void wipe(void *value, size_t length)
{
    volatile uint8_t *cursor = (volatile uint8_t *)value;
    while (length-- != 0) *cursor++ = 0;
}

int main(void)
{
    uint8_t seed[MLDSA_SEEDBYTES];
    uint8_t public_key[MLDSA65_PUBLICKEYBYTES];
    uint8_t secret_key[MLDSA65_SECRETKEYBYTES];
    int status;
    size_t written;

    for (size_t index = 0; index < sizeof(seed); index++)
        seed[index] = (uint8_t)index;

    status = MLD_API_CONCAT_UNDERSCORE(MLD_CONFIG_NAMESPACE_PREFIX,
                                        keypair_internal)(public_key, secret_key, seed);
    wipe(seed, sizeof(seed));
    if (status != 0)
    {
        wipe(secret_key, sizeof(secret_key));
        wipe(public_key, sizeof(public_key));
        return 2;
    }

    written = fwrite(public_key, 1, sizeof(public_key), stdout);
    wipe(secret_key, sizeof(secret_key));
    wipe(public_key, sizeof(public_key));
    return written == MLDSA65_PUBLICKEYBYTES ? 0 : 3;
}
