#ifndef DEEP_MLKEM_BRAID_V1_H
#define DEEP_MLKEM_BRAID_V1_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#if defined(DEEP_MLKEM_BRAID_BUILD_SHARED)
#define DEEP_MLKEM_BRAID_API __declspec(dllexport)
#else
#define DEEP_MLKEM_BRAID_API __declspec(dllimport)
#endif
#else
#define DEEP_MLKEM_BRAID_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t deep_mlkem_braid_v1_state_handle;

enum deep_mlkem_braid_v1_status {
  DEEP_MLKEM_BRAID_V1_OK = 0,
  DEEP_MLKEM_BRAID_V1_INVALID_ARGUMENT = 1,
  DEEP_MLKEM_BRAID_V1_INVALID_LENGTH = 2,
  DEEP_MLKEM_BRAID_V1_OVERLAP = 3,
  DEEP_MLKEM_BRAID_V1_INVALID_HANDLE = 4,
  DEEP_MLKEM_BRAID_V1_INVALID_PUBLIC_KEY = 5,
  DEEP_MLKEM_BRAID_V1_ENTROPY_FAILURE = 6,
  DEEP_MLKEM_BRAID_V1_INTERNAL_ERROR = 7
};

DEEP_MLKEM_BRAID_API size_t deep_mlkem_braid_v1_keygen_random_size(void);
DEEP_MLKEM_BRAID_API size_t deep_mlkem_braid_v1_decapsulation_key_size(void);
DEEP_MLKEM_BRAID_API size_t deep_mlkem_braid_v1_encapsulation_key_seed_size(void);
DEEP_MLKEM_BRAID_API size_t deep_mlkem_braid_v1_encapsulation_key_hash_size(void);
DEEP_MLKEM_BRAID_API size_t deep_mlkem_braid_v1_encapsulation_key_vector_size(void);
DEEP_MLKEM_BRAID_API size_t deep_mlkem_braid_v1_encapsulation_random_size(void);
DEEP_MLKEM_BRAID_API size_t deep_mlkem_braid_v1_ciphertext1_size(void);
DEEP_MLKEM_BRAID_API size_t deep_mlkem_braid_v1_ciphertext2_size(void);
DEEP_MLKEM_BRAID_API size_t deep_mlkem_braid_v1_shared_secret_size(void);

DEEP_MLKEM_BRAID_API int32_t deep_mlkem_braid_v1_keypair_from_random(
    const uint8_t *random64,
    size_t random64_len,
    uint8_t *dk2400,
    size_t dk2400_len,
    uint8_t *ek_vector1152,
    size_t ek_vector1152_len,
    uint8_t *ek_seed32,
    size_t ek_seed32_len,
    uint8_t *ek_hash32,
    size_t ek_hash32_len);

DEEP_MLKEM_BRAID_API int32_t deep_mlkem_braid_v1_keypair_generate(
    uint8_t *dk2400,
    size_t dk2400_len,
    uint8_t *ek_vector1152,
    size_t ek_vector1152_len,
    uint8_t *ek_seed32,
    size_t ek_seed32_len,
    uint8_t *ek_hash32,
    size_t ek_hash32_len);

DEEP_MLKEM_BRAID_API int32_t deep_mlkem_braid_v1_encaps1_from_random(
    const uint8_t *ek_seed32,
    size_t ek_seed32_len,
    const uint8_t *ek_hash32,
    size_t ek_hash32_len,
    const uint8_t *random32,
    size_t random32_len,
    uint8_t *ct1_960,
    size_t ct1_960_len,
    deep_mlkem_braid_v1_state_handle *owned_state);

DEEP_MLKEM_BRAID_API int32_t deep_mlkem_braid_v1_encaps1_generate(
    const uint8_t *ek_seed32,
    size_t ek_seed32_len,
    const uint8_t *ek_hash32,
    size_t ek_hash32_len,
    uint8_t *ct1_960,
    size_t ct1_960_len,
    deep_mlkem_braid_v1_state_handle *owned_state);

/* Consumes owned_state on every call after successful argument validation. */
DEEP_MLKEM_BRAID_API int32_t deep_mlkem_braid_v1_encaps2(
    deep_mlkem_braid_v1_state_handle owned_state,
    const uint8_t *ek_seed32,
    size_t ek_seed32_len,
    const uint8_t *ek_vector1152,
    size_t ek_vector1152_len,
    uint8_t *ct2_128,
    size_t ct2_128_len,
    uint8_t *shared_secret32,
    size_t shared_secret32_len);

DEEP_MLKEM_BRAID_API int32_t deep_mlkem_braid_v1_decapsulate(
    const uint8_t *dk2400,
    size_t dk2400_len,
    const uint8_t *ct1_960,
    size_t ct1_960_len,
    const uint8_t *ct2_128,
    size_t ct2_128_len,
    uint8_t *shared_secret32,
    size_t shared_secret32_len);

DEEP_MLKEM_BRAID_API int32_t deep_mlkem_braid_v1_state_free(
    deep_mlkem_braid_v1_state_handle owned_state);

DEEP_MLKEM_BRAID_API int32_t deep_mlkem_braid_v1_zero(uint8_t *buffer, size_t length);

#ifdef __cplusplus
}
#endif

#endif

