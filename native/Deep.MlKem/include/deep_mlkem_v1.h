#ifndef DEEP_MLKEM_V1_H
#define DEEP_MLKEM_V1_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#if defined(DEEP_MLKEM_BUILD_SHARED)
#define DEEP_MLKEM_API __declspec(dllexport)
#elif defined(DEEP_MLKEM_USE_SHARED)
#define DEEP_MLKEM_API __declspec(dllimport)
#else
#define DEEP_MLKEM_API
#endif
#define DEEP_MLKEM_CALL __cdecl
#elif defined(__GNUC__) || defined(__clang__)
#define DEEP_MLKEM_API __attribute__((visibility("default")))
#define DEEP_MLKEM_CALL
#else
#define DEEP_MLKEM_API
#define DEEP_MLKEM_CALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Closed status-code set. These are integer constants, not an ABI enum. */
#define DEEP_MLKEM_V1_OK ((int32_t)0)
#define DEEP_MLKEM_V1_NULL_POINTER ((int32_t)1)
#define DEEP_MLKEM_V1_INVALID_LENGTH ((int32_t)2)
#define DEEP_MLKEM_V1_OVERLAPPING_BUFFERS ((int32_t)3)
#define DEEP_MLKEM_V1_INVALID_PUBLIC_KEY ((int32_t)4)
#define DEEP_MLKEM_V1_INTERNAL_ERROR ((int32_t)5)

DEEP_MLKEM_API size_t DEEP_MLKEM_CALL deep_mlkem_v1_keygen_random_size(void);
DEEP_MLKEM_API size_t DEEP_MLKEM_CALL deep_mlkem_v1_decapsulation_key_size(void);
DEEP_MLKEM_API size_t DEEP_MLKEM_CALL deep_mlkem_v1_encapsulation_key_size(void);
DEEP_MLKEM_API size_t DEEP_MLKEM_CALL deep_mlkem_v1_encapsulation_random_size(void);
DEEP_MLKEM_API size_t DEEP_MLKEM_CALL deep_mlkem_v1_ciphertext_size(void);
DEEP_MLKEM_API size_t DEEP_MLKEM_CALL deep_mlkem_v1_shared_secret_size(void);

/*
 * random64 is uniformly random FIPS 203 d || z. On success dk_seed64 is the
 * Deep compact key seed and is byte-identical to random64. It is an internal
 * seed-backed representation, not the 2400-byte FIPS 203 dk serialization.
 * No output is modified on failure.
 */
DEEP_MLKEM_API int32_t DEEP_MLKEM_CALL deep_mlkem_v1_keypair_from_random(
    const uint8_t *random64,
    size_t random64_len,
    uint8_t *ek1184,
    size_t ek1184_len,
    uint8_t *dk_seed64,
    size_t dk_seed64_len);

/* No output is modified on failure. */
DEEP_MLKEM_API int32_t DEEP_MLKEM_CALL deep_mlkem_v1_encapsulate(
    const uint8_t *ek1184,
    size_t ek1184_len,
    const uint8_t *random32,
    size_t random32_len,
    uint8_t *ct1088,
    size_t ct1088_len,
    uint8_t *shared32,
    size_t shared32_len);

/*
 * ML-KEM implicit rejection means every exact-size ciphertext returns a
 * shared secret. Authentication of that secret belongs to the caller's
 * transcript/AEAD layer. No output is modified on argument failure.
 */
DEEP_MLKEM_API int32_t DEEP_MLKEM_CALL deep_mlkem_v1_decapsulate(
    const uint8_t *dk_seed64,
    size_t dk_seed64_len,
    const uint8_t *ct1088,
    size_t ct1088_len,
    uint8_t *shared32,
    size_t shared32_len);

/* Volatile zeroing for any non-empty writable caller-owned buffer. */
DEEP_MLKEM_API int32_t DEEP_MLKEM_CALL deep_mlkem_v1_zero(
    uint8_t *buffer, size_t buffer_len);

#ifdef __cplusplus
}
#endif

#endif
