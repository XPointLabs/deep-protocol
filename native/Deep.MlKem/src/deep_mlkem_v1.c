#include "deep_mlkem_v1.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

#if !defined(MLK_CONFIG_FILE)
#define MLK_CONFIG_FILE "deep_mlkem_provider_config.h"
#endif
#include "mlkem_native.h"

#if defined(_MSC_VER)
#include <intrin.h>
#pragma intrinsic(_ReadWriteBarrier)
#define DEEP_NOINLINE __declspec(noinline)
#else
#define DEEP_NOINLINE __attribute__((noinline))
#endif

#define DEEP_KEYGEN_RANDOM_BYTES ((size_t)64)
#define DEEP_DECAPSULATION_KEY_BYTES ((size_t)64)
#define DEEP_ENCAPSULATION_KEY_BYTES ((size_t)1184)
#define DEEP_ENCAPSULATION_RANDOM_BYTES ((size_t)32)
#define DEEP_CIPHERTEXT_BYTES ((size_t)1088)
#define DEEP_SHARED_SECRET_BYTES ((size_t)32)
#define DEEP_EXPANDED_SECRET_BYTES ((size_t)2400)

typedef struct deep_region
{
  const uint8_t *pointer;
  size_t length;
} deep_region;

DEEP_NOINLINE void deep_mlkem_provider_zeroize(void *pointer, size_t length)
{
  volatile uint8_t *cursor = (volatile uint8_t *)pointer;
  while (length != 0)
  {
    *cursor = 0;
    cursor++;
    length--;
  }
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

  for (left = 0; left < count; left++)
  {
    uintptr_t start;
    if (regions[left].pointer == NULL)
    {
      return DEEP_MLKEM_V1_NULL_POINTER;
    }
    start = (uintptr_t)regions[left].pointer;
    if (regions[left].length > UINTPTR_MAX - start)
    {
      return DEEP_MLKEM_V1_NULL_POINTER;
    }
  }

  for (left = 0; left < count; left++)
  {
    const uintptr_t left_start = (uintptr_t)regions[left].pointer;
    const uintptr_t left_end = left_start + regions[left].length;
    for (right = left + 1; right < count; right++)
    {
      const uintptr_t right_start = (uintptr_t)regions[right].pointer;
      const uintptr_t right_end = right_start + regions[right].length;
      if (left_start < right_end && right_start < left_end)
      {
        return DEEP_MLKEM_V1_OVERLAPPING_BUFFERS;
      }
    }
  }

  return DEEP_MLKEM_V1_OK;
}

static int32_t deep_map_provider_status(int provider_status)
{
  if (provider_status == MLK_ERR_INVALID_PK)
  {
    return DEEP_MLKEM_V1_INVALID_PUBLIC_KEY;
  }
  return DEEP_MLKEM_V1_INTERNAL_ERROR;
}

size_t deep_mlkem_v1_keygen_random_size(void)
{
  return DEEP_KEYGEN_RANDOM_BYTES;
}

size_t deep_mlkem_v1_decapsulation_key_size(void)
{
  return DEEP_DECAPSULATION_KEY_BYTES;
}

size_t deep_mlkem_v1_encapsulation_key_size(void)
{
  return DEEP_ENCAPSULATION_KEY_BYTES;
}

size_t deep_mlkem_v1_encapsulation_random_size(void)
{
  return DEEP_ENCAPSULATION_RANDOM_BYTES;
}

size_t deep_mlkem_v1_ciphertext_size(void)
{
  return DEEP_CIPHERTEXT_BYTES;
}

size_t deep_mlkem_v1_shared_secret_size(void)
{
  return DEEP_SHARED_SECRET_BYTES;
}

int32_t deep_mlkem_v1_keypair_from_random(
    const uint8_t *random64,
    size_t random64_len,
    uint8_t *ek1184,
    size_t ek1184_len,
    uint8_t *dk_seed64,
    size_t dk_seed64_len)
{
  int provider_status;
  int32_t status;
  uint8_t local_public[1184];
  uint8_t local_expanded_secret[2400];
  const deep_region regions[] = {
      {random64, random64_len},
      {ek1184, ek1184_len},
      {dk_seed64, dk_seed64_len}};

  if (random64_len != DEEP_KEYGEN_RANDOM_BYTES ||
      ek1184_len != DEEP_ENCAPSULATION_KEY_BYTES ||
      dk_seed64_len != DEEP_DECAPSULATION_KEY_BYTES)
  {
    return DEEP_MLKEM_V1_INVALID_LENGTH;
  }
  status = deep_validate_regions(regions, sizeof(regions) / sizeof(regions[0]));
  if (status != DEEP_MLKEM_V1_OK)
  {
    return status;
  }

  provider_status = deep_vendor_mlkem768_keypair_derand(
      local_public, local_expanded_secret, random64);
  if (provider_status == 0)
  {
    memcpy(ek1184, local_public, sizeof(local_public));
    memcpy(dk_seed64, random64, DEEP_DECAPSULATION_KEY_BYTES);
    status = DEEP_MLKEM_V1_OK;
  }
  else
  {
    status = deep_map_provider_status(provider_status);
  }

  deep_mlkem_provider_zeroize(local_expanded_secret, sizeof(local_expanded_secret));
  deep_mlkem_provider_zeroize(local_public, sizeof(local_public));
  return status;
}

int32_t deep_mlkem_v1_encapsulate(
    const uint8_t *ek1184,
    size_t ek1184_len,
    const uint8_t *random32,
    size_t random32_len,
    uint8_t *ct1088,
    size_t ct1088_len,
    uint8_t *shared32,
    size_t shared32_len)
{
  int provider_status;
  int32_t status;
  uint8_t local_ciphertext[1088];
  uint8_t local_shared[32];
  const deep_region regions[] = {
      {ek1184, ek1184_len},
      {random32, random32_len},
      {ct1088, ct1088_len},
      {shared32, shared32_len}};

  if (ek1184_len != DEEP_ENCAPSULATION_KEY_BYTES ||
      random32_len != DEEP_ENCAPSULATION_RANDOM_BYTES ||
      ct1088_len != DEEP_CIPHERTEXT_BYTES ||
      shared32_len != DEEP_SHARED_SECRET_BYTES)
  {
    return DEEP_MLKEM_V1_INVALID_LENGTH;
  }
  status = deep_validate_regions(regions, sizeof(regions) / sizeof(regions[0]));
  if (status != DEEP_MLKEM_V1_OK)
  {
    return status;
  }

  provider_status = deep_vendor_mlkem768_enc_derand(
      local_ciphertext, local_shared, ek1184, random32);
  if (provider_status == 0)
  {
    memcpy(ct1088, local_ciphertext, sizeof(local_ciphertext));
    memcpy(shared32, local_shared, sizeof(local_shared));
    status = DEEP_MLKEM_V1_OK;
  }
  else
  {
    status = deep_map_provider_status(provider_status);
  }

  deep_mlkem_provider_zeroize(local_shared, sizeof(local_shared));
  deep_mlkem_provider_zeroize(local_ciphertext, sizeof(local_ciphertext));
  return status;
}

int32_t deep_mlkem_v1_decapsulate(
    const uint8_t *dk_seed64,
    size_t dk_seed64_len,
    const uint8_t *ct1088,
    size_t ct1088_len,
    uint8_t *shared32,
    size_t shared32_len)
{
  int provider_status;
  int32_t status;
  uint8_t local_public[1184];
  uint8_t local_expanded_secret[2400];
  uint8_t local_shared[32];
  const deep_region regions[] = {
      {dk_seed64, dk_seed64_len},
      {ct1088, ct1088_len},
      {shared32, shared32_len}};

  if (dk_seed64_len != DEEP_DECAPSULATION_KEY_BYTES ||
      ct1088_len != DEEP_CIPHERTEXT_BYTES ||
      shared32_len != DEEP_SHARED_SECRET_BYTES)
  {
    return DEEP_MLKEM_V1_INVALID_LENGTH;
  }
  status = deep_validate_regions(regions, sizeof(regions) / sizeof(regions[0]));
  if (status != DEEP_MLKEM_V1_OK)
  {
    return status;
  }

  provider_status = deep_vendor_mlkem768_keypair_derand(
      local_public, local_expanded_secret, dk_seed64);
  if (provider_status == 0)
  {
    provider_status = deep_vendor_mlkem768_dec(
        local_shared, ct1088, local_expanded_secret);
  }
  if (provider_status == 0)
  {
    memcpy(shared32, local_shared, sizeof(local_shared));
    status = DEEP_MLKEM_V1_OK;
  }
  else
  {
    status = deep_map_provider_status(provider_status);
  }

  deep_mlkem_provider_zeroize(local_shared, sizeof(local_shared));
  deep_mlkem_provider_zeroize(local_expanded_secret, sizeof(local_expanded_secret));
  deep_mlkem_provider_zeroize(local_public, sizeof(local_public));
  return status;
}

int32_t deep_mlkem_v1_zero(uint8_t *buffer, size_t buffer_len)
{
  const uintptr_t start = (uintptr_t)buffer;
  if (buffer_len == 0)
  {
    return DEEP_MLKEM_V1_INVALID_LENGTH;
  }
  if (buffer == NULL || buffer_len > UINTPTR_MAX - start)
  {
    return DEEP_MLKEM_V1_NULL_POINTER;
  }
  deep_mlkem_provider_zeroize(buffer, buffer_len);
  return DEEP_MLKEM_V1_OK;
}
