#include "deep_mlkem_v1.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MLK_CONFIG_PARAMETER_SET 768
#include "expected_test_vectors.h"

#define CHECK(condition)                                                       \
  do                                                                           \
  {                                                                            \
    if (!(condition))                                                          \
    {                                                                          \
      fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition);    \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static int is_filled(const uint8_t *buffer, size_t length, uint8_t value)
{
  size_t index;
  for (index = 0; index < length; index++)
  {
    if (buffer[index] != value)
    {
      return 0;
    }
  }
  return 1;
}

static void make_seed(uint8_t seed[64])
{
  memcpy(seed, test_vector_d, 32);
  memcpy(seed + 32, test_vector_z, 32);
}

static int test_sizes(void)
{
  CHECK(deep_mlkem_v1_keygen_random_size() == 64);
  CHECK(deep_mlkem_v1_decapsulation_key_size() == 64);
  CHECK(deep_mlkem_v1_encapsulation_key_size() == 1184);
  CHECK(deep_mlkem_v1_encapsulation_random_size() == 32);
  CHECK(deep_mlkem_v1_ciphertext_size() == 1088);
  CHECK(deep_mlkem_v1_shared_secret_size() == 32);
  return 0;
}

static int test_upstream_known_answer(void)
{
  uint8_t seed[64];
  uint8_t public_key[1184];
  uint8_t compact_secret[64];
  uint8_t ciphertext[1088];
  uint8_t encapsulated[32];
  uint8_t decapsulated[32];

  make_seed(seed);
  CHECK(deep_mlkem_v1_keypair_from_random(
            seed, sizeof(seed), public_key, sizeof(public_key), compact_secret,
            sizeof(compact_secret)) == DEEP_MLKEM_V1_OK);
  CHECK(memcmp(public_key, test_vector_pk, sizeof(public_key)) == 0);
  CHECK(memcmp(compact_secret, seed, sizeof(seed)) == 0);

  CHECK(deep_mlkem_v1_encapsulate(
            public_key, sizeof(public_key), test_vector_m,
            sizeof(test_vector_m), ciphertext, sizeof(ciphertext), encapsulated,
            sizeof(encapsulated)) == DEEP_MLKEM_V1_OK);
  CHECK(memcmp(ciphertext, test_vector_ct, sizeof(ciphertext)) == 0);
  CHECK(memcmp(encapsulated, test_vector_ss, sizeof(encapsulated)) == 0);

  CHECK(deep_mlkem_v1_decapsulate(
            compact_secret, sizeof(compact_secret), ciphertext,
            sizeof(ciphertext), decapsulated, sizeof(decapsulated)) ==
        DEEP_MLKEM_V1_OK);
  CHECK(memcmp(decapsulated, test_vector_ss, sizeof(decapsulated)) == 0);
  return 0;
}

static int test_deterministic_roundtrip_and_implicit_rejection(void)
{
  static const uint8_t expected_rejection_secret[32] = {
      0x7c, 0x1f, 0xb9, 0x3a, 0x17, 0x53, 0x30, 0x23,
      0x68, 0x8d, 0xf8, 0x3e, 0x88, 0x42, 0xab, 0xc5,
      0x5a, 0x8a, 0xc0, 0xe6, 0xb8, 0xff, 0x7c, 0x85,
      0xdb, 0xd3, 0xd0, 0xa6, 0x7d, 0x82, 0x55, 0xb4};
  uint8_t seed[64];
  uint8_t public_key_a[1184];
  uint8_t public_key_b[1184];
  uint8_t compact_a[64];
  uint8_t compact_b[64];
  uint8_t ciphertext_a[1088];
  uint8_t ciphertext_b[1088];
  uint8_t rejected_ciphertext[1088];
  uint8_t shared_a[32];
  uint8_t shared_b[32];
  uint8_t shared_decapsulated[32];
  uint8_t shared_rejected[32];

  make_seed(seed);
  CHECK(deep_mlkem_v1_keypair_from_random(
            seed, sizeof(seed), public_key_a, sizeof(public_key_a), compact_a,
            sizeof(compact_a)) == DEEP_MLKEM_V1_OK);
  CHECK(deep_mlkem_v1_keypair_from_random(
            seed, sizeof(seed), public_key_b, sizeof(public_key_b), compact_b,
            sizeof(compact_b)) == DEEP_MLKEM_V1_OK);
  CHECK(memcmp(public_key_a, public_key_b, sizeof(public_key_a)) == 0);
  CHECK(memcmp(compact_a, compact_b, sizeof(compact_a)) == 0);

  CHECK(deep_mlkem_v1_encapsulate(
            public_key_a, sizeof(public_key_a), test_vector_m,
            sizeof(test_vector_m), ciphertext_a, sizeof(ciphertext_a), shared_a,
            sizeof(shared_a)) == DEEP_MLKEM_V1_OK);
  CHECK(deep_mlkem_v1_encapsulate(
            public_key_a, sizeof(public_key_a), test_vector_m,
            sizeof(test_vector_m), ciphertext_b, sizeof(ciphertext_b), shared_b,
            sizeof(shared_b)) == DEEP_MLKEM_V1_OK);
  CHECK(memcmp(ciphertext_a, ciphertext_b, sizeof(ciphertext_a)) == 0);
  CHECK(memcmp(shared_a, shared_b, sizeof(shared_a)) == 0);

  CHECK(deep_mlkem_v1_decapsulate(
            compact_a, sizeof(compact_a), ciphertext_a, sizeof(ciphertext_a),
            shared_decapsulated, sizeof(shared_decapsulated)) ==
        DEEP_MLKEM_V1_OK);
  CHECK(memcmp(shared_a, shared_decapsulated, sizeof(shared_a)) == 0);

  memcpy(rejected_ciphertext, ciphertext_a, sizeof(rejected_ciphertext));
  rejected_ciphertext[0] ^= 0x80;
  CHECK(deep_mlkem_v1_decapsulate(
            compact_a, sizeof(compact_a), rejected_ciphertext,
            sizeof(rejected_ciphertext), shared_rejected,
            sizeof(shared_rejected)) == DEEP_MLKEM_V1_OK);
  CHECK(memcmp(shared_rejected, expected_rejection_secret,
               sizeof(shared_rejected)) == 0);
  return 0;
}

static int test_lengths_nulls_and_unchanged_outputs(void)
{
  uint8_t seed[64];
  uint8_t public_key[1184];
  uint8_t compact_secret[64];
  uint8_t ciphertext[1088];
  uint8_t shared[32];

  make_seed(seed);
  memset(public_key, 0xa5, sizeof(public_key));
  memset(compact_secret, 0xa5, sizeof(compact_secret));
  CHECK(deep_mlkem_v1_keypair_from_random(
            seed, sizeof(seed) - 1, public_key, sizeof(public_key),
            compact_secret, sizeof(compact_secret)) ==
        DEEP_MLKEM_V1_INVALID_LENGTH);
  CHECK(is_filled(public_key, sizeof(public_key), 0xa5));
  CHECK(is_filled(compact_secret, sizeof(compact_secret), 0xa5));

  CHECK(deep_mlkem_v1_keypair_from_random(
            NULL, sizeof(seed), public_key, sizeof(public_key), compact_secret,
            sizeof(compact_secret)) == DEEP_MLKEM_V1_NULL_POINTER);
  CHECK(deep_mlkem_v1_keypair_from_random(
            seed, sizeof(seed), NULL, sizeof(public_key), compact_secret,
            sizeof(compact_secret)) == DEEP_MLKEM_V1_NULL_POINTER);
  CHECK(deep_mlkem_v1_keypair_from_random(
            seed, sizeof(seed), public_key, sizeof(public_key), NULL,
            sizeof(compact_secret)) == DEEP_MLKEM_V1_NULL_POINTER);

  CHECK(deep_mlkem_v1_keypair_from_random(
            seed, sizeof(seed), public_key, sizeof(public_key), compact_secret,
            sizeof(compact_secret)) == DEEP_MLKEM_V1_OK);
  memset(ciphertext, 0xa5, sizeof(ciphertext));
  memset(shared, 0xa5, sizeof(shared));
  CHECK(deep_mlkem_v1_encapsulate(
            public_key, sizeof(public_key) - 1, test_vector_m,
            sizeof(test_vector_m), ciphertext, sizeof(ciphertext), shared,
            sizeof(shared)) == DEEP_MLKEM_V1_INVALID_LENGTH);
  CHECK(is_filled(ciphertext, sizeof(ciphertext), 0xa5));
  CHECK(is_filled(shared, sizeof(shared), 0xa5));

  CHECK(deep_mlkem_v1_encapsulate(
            NULL, sizeof(public_key), test_vector_m, sizeof(test_vector_m),
            ciphertext, sizeof(ciphertext), shared, sizeof(shared)) ==
        DEEP_MLKEM_V1_NULL_POINTER);
  CHECK(deep_mlkem_v1_encapsulate(
            public_key, sizeof(public_key), NULL, sizeof(test_vector_m),
            ciphertext, sizeof(ciphertext), shared, sizeof(shared)) ==
        DEEP_MLKEM_V1_NULL_POINTER);
  CHECK(deep_mlkem_v1_encapsulate(
            public_key, sizeof(public_key), test_vector_m, sizeof(test_vector_m),
            NULL, sizeof(ciphertext), shared, sizeof(shared)) ==
        DEEP_MLKEM_V1_NULL_POINTER);
  CHECK(deep_mlkem_v1_encapsulate(
            public_key, sizeof(public_key), test_vector_m, sizeof(test_vector_m),
            ciphertext, sizeof(ciphertext), NULL, sizeof(shared)) ==
        DEEP_MLKEM_V1_NULL_POINTER);

  CHECK(deep_mlkem_v1_encapsulate(
            public_key, sizeof(public_key), test_vector_m, sizeof(test_vector_m),
            ciphertext, sizeof(ciphertext), shared, sizeof(shared)) ==
        DEEP_MLKEM_V1_OK);
  memset(shared, 0xa5, sizeof(shared));
  CHECK(deep_mlkem_v1_decapsulate(
            compact_secret, sizeof(compact_secret), ciphertext,
            sizeof(ciphertext) - 1, shared, sizeof(shared)) ==
        DEEP_MLKEM_V1_INVALID_LENGTH);
  CHECK(is_filled(shared, sizeof(shared), 0xa5));

  CHECK(deep_mlkem_v1_decapsulate(
            NULL, sizeof(compact_secret), ciphertext, sizeof(ciphertext), shared,
            sizeof(shared)) == DEEP_MLKEM_V1_NULL_POINTER);
  CHECK(deep_mlkem_v1_decapsulate(
            compact_secret, sizeof(compact_secret), NULL, sizeof(ciphertext),
            shared, sizeof(shared)) == DEEP_MLKEM_V1_NULL_POINTER);
  CHECK(deep_mlkem_v1_decapsulate(
            compact_secret, sizeof(compact_secret), ciphertext,
            sizeof(ciphertext), NULL, sizeof(shared)) ==
        DEEP_MLKEM_V1_NULL_POINTER);
  return 0;
}

static int test_pairwise_overlap_rejection(void)
{
  uint8_t arena[4096];
  size_t left;
  size_t right;

  for (left = 0; left < 3; left++)
  {
    for (right = left + 1; right < 3; right++)
    {
      uint8_t *regions[] = {arena, arena + 128, arena + 1400};
      regions[right] = regions[left] + 1;
      CHECK(deep_mlkem_v1_keypair_from_random(
                regions[0], 64, regions[1], 1184, regions[2], 64) ==
            DEEP_MLKEM_V1_OVERLAPPING_BUFFERS);
    }
  }

  for (left = 0; left < 4; left++)
  {
    for (right = left + 1; right < 4; right++)
    {
      uint8_t *regions[] = {arena, arena + 1200, arena + 1300, arena + 2500};
      regions[right] = regions[left] + 1;
      CHECK(deep_mlkem_v1_encapsulate(
                regions[0], 1184, regions[1], 32, regions[2], 1088,
                regions[3], 32) == DEEP_MLKEM_V1_OVERLAPPING_BUFFERS);
    }
  }

  for (left = 0; left < 3; left++)
  {
    for (right = left + 1; right < 3; right++)
    {
      uint8_t *regions[] = {arena, arena + 128, arena + 1300};
      regions[right] = regions[left] + 1;
      CHECK(deep_mlkem_v1_decapsulate(
                regions[0], 64, regions[1], 1088, regions[2], 32) ==
            DEEP_MLKEM_V1_OVERLAPPING_BUFFERS);
    }
  }
  return 0;
}

static int test_noncanonical_public_key_keeps_outputs(void)
{
  uint8_t seed[64];
  uint8_t public_key[1184];
  uint8_t compact_secret[64];
  uint8_t ciphertext[1088];
  uint8_t shared[32];

  make_seed(seed);
  CHECK(deep_mlkem_v1_keypair_from_random(
            seed, sizeof(seed), public_key, sizeof(public_key), compact_secret,
            sizeof(compact_secret)) == DEEP_MLKEM_V1_OK);
  public_key[0] = 0xff;
  public_key[1] = (uint8_t)((public_key[1] & 0xf0U) | 0x0fU);
  memset(ciphertext, 0xa5, sizeof(ciphertext));
  memset(shared, 0xa5, sizeof(shared));
  CHECK(deep_mlkem_v1_encapsulate(
            public_key, sizeof(public_key), test_vector_m, sizeof(test_vector_m),
            ciphertext, sizeof(ciphertext), shared, sizeof(shared)) ==
        DEEP_MLKEM_V1_INVALID_PUBLIC_KEY);
  CHECK(is_filled(ciphertext, sizeof(ciphertext), 0xa5));
  CHECK(is_filled(shared, sizeof(shared), 0xa5));
  return 0;
}

static int test_explicit_zero(void)
{
  uint8_t buffer[73];
  memset(buffer, 0xa5, sizeof(buffer));
  CHECK(deep_mlkem_v1_zero(buffer, sizeof(buffer)) == DEEP_MLKEM_V1_OK);
  CHECK(is_filled(buffer, sizeof(buffer), 0));
  CHECK(deep_mlkem_v1_zero(NULL, sizeof(buffer)) ==
        DEEP_MLKEM_V1_NULL_POINTER);
  CHECK(deep_mlkem_v1_zero(buffer, 0) == DEEP_MLKEM_V1_INVALID_LENGTH);
  return 0;
}

int main(void)
{
  CHECK(test_sizes() == 0);
  CHECK(test_upstream_known_answer() == 0);
  CHECK(test_deterministic_roundtrip_and_implicit_rejection() == 0);
  CHECK(test_lengths_nulls_and_unchanged_outputs() == 0);
  CHECK(test_pairwise_overlap_rejection() == 0);
  CHECK(test_noncanonical_public_key_keeps_outputs() == 0);
  CHECK(test_explicit_zero() == 0);
  printf("Deep ML-KEM v1 native tests passed.\n");
  return 0;
}
