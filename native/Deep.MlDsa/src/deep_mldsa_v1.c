#include "deep_mldsa_v1.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "mldsa_native.h"

#if defined(_MSC_VER)
#include <intrin.h>
#pragma intrinsic(_ReadWriteBarrier)
#define DEEP_NOINLINE __declspec(noinline)
#else
#define DEEP_NOINLINE __attribute__((noinline))
#endif

#define DEEP_SEED_BYTES ((size_t)32)
#define DEEP_PUBLIC_BYTES ((size_t)1952)
#define DEEP_SECRET_BYTES ((size_t)4032)
#define DEEP_SIGNATURE_BYTES ((size_t)3309)
#define DEEP_RANDOM_BYTES ((size_t)32)
#define DEEP_MESSAGE_MAX ((size_t)65535)
#define DEEP_CONTEXT_MAX ((size_t)255)

_Static_assert(MLD_CONFIG_PARAMETER_SET == 65, "Deep provider requires ML-DSA-65");
_Static_assert(MLDSA65_PUBLICKEYBYTES == 1952, "Unexpected public key size");
_Static_assert(MLDSA65_SECRETKEYBYTES == 4032, "Unexpected secret key size");
_Static_assert(MLDSA65_BYTES == 3309, "Unexpected signature size");

typedef struct deep_region {
    const uint8_t *pointer;
    size_t length;
} deep_region;

DEEP_NOINLINE static void deep_wipe(void *pointer, size_t length)
{
    volatile uint8_t *cursor = (volatile uint8_t *)pointer;
    while (length-- != 0) *cursor++ = 0;
#if defined(_MSC_VER)
    _ReadWriteBarrier();
#else
    __asm__ __volatile__("" : : "r"(pointer) : "memory");
#endif
}

static int32_t deep_validate_regions(const deep_region *regions, size_t count)
{
    size_t left;
    size_t right;
    for (left = 0; left < count; left++) {
        uintptr_t start;
        if (regions[left].pointer == NULL) return DEEP_MLDSA_V1_NULL_POINTER;
        start = (uintptr_t)regions[left].pointer;
        if (regions[left].length > UINTPTR_MAX - start)
            return DEEP_MLDSA_V1_INVALID_LENGTH;
    }
    for (left = 0; left < count; left++) {
        const uintptr_t left_start = (uintptr_t)regions[left].pointer;
        const uintptr_t left_end = left_start + regions[left].length;
        for (right = left + 1; right < count; right++) {
            const uintptr_t right_start = (uintptr_t)regions[right].pointer;
            const uintptr_t right_end = right_start + regions[right].length;
            if (left_start < right_end && right_start < left_end)
                return DEEP_MLDSA_V1_OVERLAPPING_BUFFERS;
        }
    }
    return DEEP_MLDSA_V1_OK;
}

size_t deep_mldsa_v1_seed_size(void) { return DEEP_SEED_BYTES; }
size_t deep_mldsa_v1_public_key_size(void) { return DEEP_PUBLIC_BYTES; }
size_t deep_mldsa_v1_signature_size(void) { return DEEP_SIGNATURE_BYTES; }
size_t deep_mldsa_v1_sign_random_size(void) { return DEEP_RANDOM_BYTES; }

int32_t deep_mldsa_v1_public_from_seed(
    const uint8_t *seed32, size_t seed_len,
    uint8_t *public1952, size_t public_len)
{
    const deep_region regions[] = {{seed32, seed_len}, {public1952, public_len}};
    uint8_t public_local[MLDSA65_PUBLICKEYBYTES];
    uint8_t secret_local[MLDSA65_SECRETKEYBYTES];
    int provider_status;
    int32_t status;

    if (seed_len != DEEP_SEED_BYTES || public_len != DEEP_PUBLIC_BYTES)
        return DEEP_MLDSA_V1_INVALID_LENGTH;
    status = deep_validate_regions(regions, 2);
    if (status != DEEP_MLDSA_V1_OK) return status;

    provider_status = MLD_API_CONCAT_UNDERSCORE(
        MLD_CONFIG_NAMESPACE_PREFIX, keypair_internal)(
            public_local, secret_local, seed32);
    deep_wipe(secret_local, sizeof(secret_local));
    if (provider_status != 0) {
        deep_wipe(public_local, sizeof(public_local));
        deep_wipe(public1952, public_len);
        return DEEP_MLDSA_V1_INTERNAL_ERROR;
    }
    memcpy(public1952, public_local, public_len);
    deep_wipe(public_local, sizeof(public_local));
    return DEEP_MLDSA_V1_OK;
}

int32_t deep_mldsa_v1_sign_from_seed(
    const uint8_t *seed32, size_t seed_len,
    const uint8_t *random32, size_t random_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *message, size_t message_len,
    uint8_t *signature3309, size_t signature_len)
{
    const deep_region regions[] = {
        {seed32, seed_len}, {random32, random_len},
        {context, context_len}, {message, message_len},
        {signature3309, signature_len}};
    uint8_t public_local[MLDSA65_PUBLICKEYBYTES];
    uint8_t secret_local[MLDSA65_SECRETKEYBYTES];
    uint8_t signature_local[MLDSA65_BYTES];
    uint8_t prefix[MLD_DOMAIN_SEPARATION_MAX_BYTES];
    size_t prefix_len;
    int provider_status;
    int32_t status;

    if (seed_len != DEEP_SEED_BYTES || random_len != DEEP_RANDOM_BYTES ||
        context_len > DEEP_CONTEXT_MAX || message_len > DEEP_MESSAGE_MAX ||
        signature_len != DEEP_SIGNATURE_BYTES)
        return DEEP_MLDSA_V1_INVALID_LENGTH;
    status = deep_validate_regions(regions, 5);
    if (status != DEEP_MLDSA_V1_OK) return status;

    prefix_len = MLD_API_CONCAT_UNDERSCORE(
        MLD_CONFIG_NAMESPACE_PREFIX, prepare_domain_separation_prefix)(
            prefix, NULL, 0, context, context_len, MLD_PREHASH_NONE);
    if (prefix_len == 0) {
        deep_wipe(prefix, sizeof(prefix));
        deep_wipe(signature3309, signature_len);
        return DEEP_MLDSA_V1_INTERNAL_ERROR;
    }
    provider_status = MLD_API_CONCAT_UNDERSCORE(
        MLD_CONFIG_NAMESPACE_PREFIX, keypair_internal)(
            public_local, secret_local, seed32);
    if (provider_status == 0) {
        provider_status = MLD_API_CONCAT_UNDERSCORE(
            MLD_CONFIG_NAMESPACE_PREFIX, signature_internal)(
                signature_local, message, message_len, prefix, prefix_len,
                random32, secret_local, 0);
    }
    deep_wipe(secret_local, sizeof(secret_local));
    deep_wipe(public_local, sizeof(public_local));
    deep_wipe(prefix, sizeof(prefix));
    if (provider_status != 0) {
        deep_wipe(signature_local, sizeof(signature_local));
        deep_wipe(signature3309, signature_len);
        return DEEP_MLDSA_V1_INTERNAL_ERROR;
    }
    memcpy(signature3309, signature_local, signature_len);
    deep_wipe(signature_local, sizeof(signature_local));
    return DEEP_MLDSA_V1_OK;
}

int32_t deep_mldsa_v1_verify(
    const uint8_t *public1952, size_t public_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *signature3309, size_t signature_len)
{
    const deep_region regions[] = {
        {public1952, public_len}, {context, context_len},
        {message, message_len}, {signature3309, signature_len}};
    int32_t status;
    int provider_status;

    if (public_len != DEEP_PUBLIC_BYTES || context_len > DEEP_CONTEXT_MAX ||
        message_len > DEEP_MESSAGE_MAX || signature_len != DEEP_SIGNATURE_BYTES)
        return DEEP_MLDSA_V1_INVALID_LENGTH;
    status = deep_validate_regions(regions, 4);
    if (status != DEEP_MLDSA_V1_OK) return status;

    provider_status = MLD_API_CONCAT_UNDERSCORE(
        MLD_CONFIG_NAMESPACE_PREFIX, verify)(
            signature3309, message, message_len, context, context_len,
            public1952);
    if (provider_status == 0) return DEEP_MLDSA_V1_OK;
    if (provider_status == MLD_ERR_INVALID_SIGNATURE)
        return DEEP_MLDSA_V1_INVALID_SIGNATURE;
    return DEEP_MLDSA_V1_INTERNAL_ERROR;
}

int32_t deep_mldsa_v1_zero(uint8_t *buffer, size_t buffer_len)
{
    if (buffer == NULL) return DEEP_MLDSA_V1_NULL_POINTER;
    if (buffer_len == 0 || buffer_len > DEEP_MESSAGE_MAX)
        return DEEP_MLDSA_V1_INVALID_LENGTH;
    deep_wipe(buffer, buffer_len);
    return DEEP_MLDSA_V1_OK;
}
