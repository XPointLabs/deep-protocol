/* Test-only bridge for public, fixed Deep ID vectors. Reads a 32-byte seed,
 * a big-endian 16-bit length and that many message bytes from stdin; writes the 1952-byte
 * public key followed by its deterministic 3309-byte pure ML-DSA signature.
 * Never feed production account material to this executable. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#endif
#include "deep_mldsa_v1.h"

static int verify_mode(void)
{
    uint8_t public_key[1952];
    uint8_t length_bytes[2];
    uint8_t message[512];
    uint8_t signature[3309];
    static const uint8_t context[] = "Deep/DAB2/V2/root";
    size_t message_length;
    int result = 1;
    if (fread(public_key, 1, sizeof(public_key), stdin) != sizeof(public_key) ||
        fread(length_bytes, 1, sizeof(length_bytes), stdin) != sizeof(length_bytes))
        goto done;
    message_length = ((size_t)length_bytes[0] << 8) | length_bytes[1];
    if (message_length == 0 || message_length > sizeof(message) ||
        fread(message, 1, message_length, stdin) != message_length ||
        fread(signature, 1, sizeof(signature), stdin) != sizeof(signature) ||
        fgetc(stdin) != EOF)
        goto done;
    result = deep_mldsa_v1_verify(
        public_key, sizeof(public_key), context, sizeof(context) - 1,
        message, message_length, signature, sizeof(signature)) == DEEP_MLDSA_V1_OK
        ? 0 : 3;
done:
    (void)deep_mldsa_v1_zero(public_key, sizeof(public_key));
    (void)deep_mldsa_v1_zero(length_bytes, sizeof(length_bytes));
    (void)deep_mldsa_v1_zero(message, sizeof(message));
    (void)deep_mldsa_v1_zero(signature, sizeof(signature));
    return result;
}

int main(int argc, char **argv)
{
    uint8_t seed[32];
    uint8_t length_bytes[2];
    uint8_t message[512];
    size_t message_length;
    uint8_t public_key[1952];
    uint8_t signature[3309];
    uint8_t deterministic_random[32] = {0};
    static const uint8_t context[] = "Deep/DAB2/V2/root";
    int result = 1;

#if defined(_WIN32)
    if (_setmode(_fileno(stdin), _O_BINARY) == -1 ||
        _setmode(_fileno(stdout), _O_BINARY) == -1)
        goto done;
#endif
    if (argc == 2 && strcmp(argv[1], "--verify") == 0)
        return verify_mode();
    if (argc != 1)
        goto done;
    if (fread(seed, 1, sizeof(seed), stdin) != sizeof(seed) ||
        fread(length_bytes, 1, sizeof(length_bytes), stdin) != sizeof(length_bytes))
        goto done;
    message_length = ((size_t)length_bytes[0] << 8) | length_bytes[1];
    if (message_length == 0 || message_length > sizeof(message) ||
        fread(message, 1, message_length, stdin) != message_length ||
        fgetc(stdin) != EOF)
        goto done;
    if (deep_mldsa_v1_public_from_seed(seed, sizeof(seed),
            public_key, sizeof(public_key)) != DEEP_MLDSA_V1_OK)
        goto done;
    if (deep_mldsa_v1_sign_from_seed(
            seed, sizeof(seed), deterministic_random, sizeof(deterministic_random),
            context, sizeof(context) - 1, message, message_length,
            signature, sizeof(signature)) != DEEP_MLDSA_V1_OK)
        goto done;
    if (fwrite(public_key, 1, sizeof(public_key), stdout) != sizeof(public_key) ||
        fwrite(signature, 1, sizeof(signature), stdout) != sizeof(signature))
        goto done;
    result = 0;

done:
    (void)deep_mldsa_v1_zero(seed, sizeof(seed));
    (void)deep_mldsa_v1_zero(length_bytes, sizeof(length_bytes));
    (void)deep_mldsa_v1_zero(message, sizeof(message));
    (void)deep_mldsa_v1_zero(deterministic_random, sizeof(deterministic_random));
    (void)deep_mldsa_v1_zero(signature, sizeof(signature));
    (void)deep_mldsa_v1_zero(public_key, sizeof(public_key));
    return result;
}
