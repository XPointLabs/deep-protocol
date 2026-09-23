#include "deep_mldsa_v1.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "Deep ML-DSA native test failed at line %d\n", __LINE__); \
        return 1; \
    } \
} while (0)

int main(void)
{
    uint8_t seed[32];
    uint8_t random_bytes[32];
    uint8_t public_key[1952];
    uint8_t restored_public_key[1952];
    uint8_t signature[3309];
    uint8_t second_signature[3309];
    uint8_t context[] = {'D', 'e', 'e', 'p', '/', 'R', 'o', 'o', 't'};
    uint8_t message[] = {'c', 'a', 'n', 'o', 'n', 'i', 'c', 'a', 'l'};
    size_t index;

    CHECK(deep_mldsa_v1_seed_size() == sizeof(seed));
    CHECK(deep_mldsa_v1_public_key_size() == sizeof(public_key));
    CHECK(deep_mldsa_v1_signature_size() == sizeof(signature));
    CHECK(deep_mldsa_v1_sign_random_size() == sizeof(random_bytes));

    for (index = 0; index < sizeof(seed); index++) {
        seed[index] = (uint8_t)index;
        random_bytes[index] = (uint8_t)(0xa0 + index);
    }
    CHECK(deep_mldsa_v1_public_from_seed(
        seed, sizeof(seed), public_key, sizeof(public_key)) == DEEP_MLDSA_V1_OK);
    CHECK(deep_mldsa_v1_public_from_seed(
        seed, sizeof(seed), restored_public_key, sizeof(restored_public_key)) ==
        DEEP_MLDSA_V1_OK);
    CHECK(memcmp(public_key, restored_public_key, sizeof(public_key)) == 0);

    CHECK(deep_mldsa_v1_sign_from_seed(
        seed, sizeof(seed), random_bytes, sizeof(random_bytes),
        context, sizeof(context), message, sizeof(message),
        signature, sizeof(signature)) == DEEP_MLDSA_V1_OK);
    CHECK(deep_mldsa_v1_verify(
        public_key, sizeof(public_key), context, sizeof(context),
        message, sizeof(message), signature, sizeof(signature)) == DEEP_MLDSA_V1_OK);

    message[0] ^= 1;
    CHECK(deep_mldsa_v1_verify(
        public_key, sizeof(public_key), context, sizeof(context),
        message, sizeof(message), signature, sizeof(signature)) ==
        DEEP_MLDSA_V1_INVALID_SIGNATURE);
    message[0] ^= 1;
    context[0] ^= 1;
    CHECK(deep_mldsa_v1_verify(
        public_key, sizeof(public_key), context, sizeof(context),
        message, sizeof(message), signature, sizeof(signature)) ==
        DEEP_MLDSA_V1_INVALID_SIGNATURE);
    context[0] ^= 1;
    signature[0] ^= 1;
    CHECK(deep_mldsa_v1_verify(
        public_key, sizeof(public_key), context, sizeof(context),
        message, sizeof(message), signature, sizeof(signature)) ==
        DEEP_MLDSA_V1_INVALID_SIGNATURE);
    signature[0] ^= 1;

    random_bytes[0] ^= 1;
    CHECK(deep_mldsa_v1_sign_from_seed(
        seed, sizeof(seed), random_bytes, sizeof(random_bytes),
        context, sizeof(context), message, sizeof(message),
        second_signature, sizeof(second_signature)) == DEEP_MLDSA_V1_OK);
    CHECK(memcmp(signature, second_signature, sizeof(signature)) != 0);
    CHECK(deep_mldsa_v1_verify(
        public_key, sizeof(public_key), context, sizeof(context),
        message, sizeof(message), second_signature, sizeof(second_signature)) ==
        DEEP_MLDSA_V1_OK);

    memset(restored_public_key, 0xa5, sizeof(restored_public_key));
    CHECK(deep_mldsa_v1_public_from_seed(
        seed, sizeof(seed) - 1, restored_public_key, sizeof(restored_public_key)) ==
        DEEP_MLDSA_V1_INVALID_LENGTH);
    CHECK(restored_public_key[0] == 0xa5);
    CHECK(deep_mldsa_v1_public_from_seed(
        seed, sizeof(seed), restored_public_key, sizeof(restored_public_key) - 1) ==
        DEEP_MLDSA_V1_INVALID_LENGTH);
    CHECK(restored_public_key[0] == 0xa5);
    CHECK(deep_mldsa_v1_public_from_seed(
        NULL, sizeof(seed), restored_public_key, sizeof(restored_public_key)) ==
        DEEP_MLDSA_V1_NULL_POINTER);
    CHECK(restored_public_key[0] == 0xa5);
    CHECK(deep_mldsa_v1_public_from_seed(
        restored_public_key, sizeof(seed), restored_public_key,
        sizeof(restored_public_key)) == DEEP_MLDSA_V1_OVERLAPPING_BUFFERS);
    CHECK(restored_public_key[0] == 0xa5);

    CHECK(deep_mldsa_v1_sign_from_seed(
        seed, sizeof(seed), random_bytes, sizeof(random_bytes),
        context, sizeof(context), message, sizeof(message),
        signature, sizeof(signature) - 1) == DEEP_MLDSA_V1_INVALID_LENGTH);
    CHECK(deep_mldsa_v1_sign_from_seed(
        seed, sizeof(seed), random_bytes, sizeof(random_bytes),
        context, 256, message, sizeof(message),
        signature, sizeof(signature)) == DEEP_MLDSA_V1_INVALID_LENGTH);
    CHECK(deep_mldsa_v1_verify(
        public_key, sizeof(public_key) - 1, context, sizeof(context),
        message, sizeof(message), signature, sizeof(signature)) ==
        DEEP_MLDSA_V1_INVALID_LENGTH);

    CHECK(deep_mldsa_v1_zero(seed, sizeof(seed)) == DEEP_MLDSA_V1_OK);
    CHECK(deep_mldsa_v1_zero(random_bytes, sizeof(random_bytes)) == DEEP_MLDSA_V1_OK);
    for (index = 0; index < sizeof(seed); index++) {
        CHECK(seed[index] == 0);
        CHECK(random_bytes[index] == 0);
    }
    CHECK(deep_mldsa_v1_zero(NULL, sizeof(seed)) == DEEP_MLDSA_V1_NULL_POINTER);
    CHECK(deep_mldsa_v1_zero(seed, 0) == DEEP_MLDSA_V1_INVALID_LENGTH);
    puts("Deep ML-DSA-65 native ABI checks passed");
    return 0;
}
