#ifndef DEEP_MLDSA_V1_H
#define DEEP_MLDSA_V1_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#if defined(DEEP_MLDSA_BUILD_SHARED)
#define DEEP_MLDSA_API __declspec(dllexport)
#elif defined(DEEP_MLDSA_USE_SHARED)
#define DEEP_MLDSA_API __declspec(dllimport)
#else
#define DEEP_MLDSA_API
#endif
#define DEEP_MLDSA_CALL __cdecl
#elif defined(__GNUC__) || defined(__clang__)
#define DEEP_MLDSA_API __attribute__((visibility("default")))
#define DEEP_MLDSA_CALL
#else
#define DEEP_MLDSA_API
#define DEEP_MLDSA_CALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define DEEP_MLDSA_V1_OK ((int32_t)0)
#define DEEP_MLDSA_V1_NULL_POINTER ((int32_t)1)
#define DEEP_MLDSA_V1_INVALID_LENGTH ((int32_t)2)
#define DEEP_MLDSA_V1_OVERLAPPING_BUFFERS ((int32_t)3)
#define DEEP_MLDSA_V1_INVALID_SIGNATURE ((int32_t)4)
#define DEEP_MLDSA_V1_INTERNAL_ERROR ((int32_t)5)

DEEP_MLDSA_API size_t DEEP_MLDSA_CALL deep_mldsa_v1_seed_size(void);
DEEP_MLDSA_API size_t DEEP_MLDSA_CALL deep_mldsa_v1_public_key_size(void);
DEEP_MLDSA_API size_t DEEP_MLDSA_CALL deep_mldsa_v1_signature_size(void);
DEEP_MLDSA_API size_t DEEP_MLDSA_CALL deep_mldsa_v1_sign_random_size(void);

/* Every pointer must be non-null, even for an empty message/context. Every
 * pair of input/output buffers must be disjoint. An invalid argument leaves
 * output untouched; a provider failure clears it. */
DEEP_MLDSA_API int32_t DEEP_MLDSA_CALL deep_mldsa_v1_public_from_seed(
    const uint8_t *seed32, size_t seed_len,
    uint8_t *public1952, size_t public_len);

/* The caller supplies fresh, independent 32-byte hedging randomness for each
 * signature. Context is the FIPS 204 context (0..255 bytes), not a prehash.
 * The caller owns and must clear seed and random after use. */
DEEP_MLDSA_API int32_t DEEP_MLDSA_CALL deep_mldsa_v1_sign_from_seed(
    const uint8_t *seed32, size_t seed_len,
    const uint8_t *random32, size_t random_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *message, size_t message_len,
    uint8_t *signature3309, size_t signature_len);

DEEP_MLDSA_API int32_t DEEP_MLDSA_CALL deep_mldsa_v1_verify(
    const uint8_t *public1952, size_t public_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *signature3309, size_t signature_len);

DEEP_MLDSA_API int32_t DEEP_MLDSA_CALL deep_mldsa_v1_zero(
    uint8_t *buffer, size_t buffer_len);

#ifdef __cplusplus
}
#endif

#endif
