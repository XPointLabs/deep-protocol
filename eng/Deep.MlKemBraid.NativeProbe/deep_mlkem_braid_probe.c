#include "deep_mlkem_braid_v1.h"

#include <stdio.h>
#include <string.h>

static int require(int condition, const char *message)
{
  if (!condition)
  {
    fprintf(stderr, "Deep ML-KEM Braid probe failed: %s\n", message);
    return 0;
  }
  return 1;
}

int main(void)
{
  uint8_t keygen_random[64];
  uint8_t encaps_random[32];
  uint8_t dk[2400];
  uint8_t vector[1152];
  uint8_t seed[32];
  uint8_t hash[32];
  uint8_t ct1[960];
  uint8_t ct2[128];
  uint8_t sender_secret[32];
  uint8_t recipient_secret[32];
  uint8_t rejected_ct2[128];
  uint8_t rejected_secret[32];
  deep_mlkem_braid_v1_state_handle state = 0;
  deep_mlkem_braid_v1_state_handle rejected_state = 0;
  size_t i;
  int32_t status;

  if (!require(deep_mlkem_braid_v1_keygen_random_size() == sizeof(keygen_random), "keygen size") ||
      !require(deep_mlkem_braid_v1_decapsulation_key_size() == sizeof(dk), "dk size") ||
      !require(deep_mlkem_braid_v1_encapsulation_key_seed_size() == sizeof(seed), "seed size") ||
      !require(deep_mlkem_braid_v1_encapsulation_key_hash_size() == sizeof(hash), "hash size") ||
      !require(deep_mlkem_braid_v1_encapsulation_key_vector_size() == sizeof(vector), "vector size") ||
      !require(deep_mlkem_braid_v1_ciphertext1_size() == sizeof(ct1), "ct1 size") ||
      !require(deep_mlkem_braid_v1_ciphertext2_size() == sizeof(ct2), "ct2 size") ||
      !require(deep_mlkem_braid_v1_shared_secret_size() == sizeof(sender_secret), "secret size"))
  {
    return 1;
  }

  for (i = 0; i < sizeof(keygen_random); ++i)
  {
    keygen_random[i] = (uint8_t)i;
  }
  for (i = 0; i < sizeof(encaps_random); ++i)
  {
    encaps_random[i] = (uint8_t)(0xA0u ^ (uint8_t)i);
  }

  status = deep_mlkem_braid_v1_keypair_from_random(
      keygen_random, sizeof(keygen_random), dk, sizeof(dk), vector, sizeof(vector),
      seed, sizeof(seed), hash, sizeof(hash));
  if (!require(status == DEEP_MLKEM_BRAID_V1_OK, "deterministic keygen"))
  {
    return 1;
  }

  status = deep_mlkem_braid_v1_encaps1_from_random(
      seed, sizeof(seed), hash, sizeof(hash), encaps_random, sizeof(encaps_random),
      ct1, sizeof(ct1), &state);
  if (!require(status == DEEP_MLKEM_BRAID_V1_OK && state != 0, "deterministic Encaps1"))
  {
    return 1;
  }

  status = deep_mlkem_braid_v1_encaps2(
      state, seed, sizeof(seed), vector, sizeof(vector), ct2, sizeof(ct2),
      sender_secret, sizeof(sender_secret));
  if (!require(status == DEEP_MLKEM_BRAID_V1_OK, "Encaps2"))
  {
    return 1;
  }
  if (!require(deep_mlkem_braid_v1_state_free(state) == DEEP_MLKEM_BRAID_V1_INVALID_HANDLE,
               "Encaps2 consumes state"))
  {
    return 1;
  }

  status = deep_mlkem_braid_v1_decapsulate(
      dk, sizeof(dk), ct1, sizeof(ct1), ct2, sizeof(ct2),
      recipient_secret, sizeof(recipient_secret));
  if (!require(status == DEEP_MLKEM_BRAID_V1_OK, "decapsulation") ||
      !require(memcmp(sender_secret, recipient_secret, sizeof(sender_secret)) == 0,
               "shared-secret agreement"))
  {
    return 1;
  }

  status = deep_mlkem_braid_v1_encaps1_from_random(
      seed, sizeof(seed), hash, sizeof(hash), encaps_random, sizeof(encaps_random),
      ct1, sizeof(ct1), &rejected_state);
  if (!require(status == DEEP_MLKEM_BRAID_V1_OK, "second Encaps1"))
  {
    return 1;
  }
  seed[0] ^= 1u;
  memset(rejected_ct2, 0x55, sizeof(rejected_ct2));
  memset(rejected_secret, 0x55, sizeof(rejected_secret));
  status = deep_mlkem_braid_v1_encaps2(
      rejected_state, seed, sizeof(seed), vector, sizeof(vector),
      rejected_ct2, sizeof(rejected_ct2), rejected_secret, sizeof(rejected_secret));
  if (!require(status == DEEP_MLKEM_BRAID_V1_INVALID_PUBLIC_KEY, "wrong seed rejection") ||
      !require(deep_mlkem_braid_v1_state_free(rejected_state) == DEEP_MLKEM_BRAID_V1_INVALID_HANDLE,
               "rejected state is consumed"))
  {
    return 1;
  }
  for (i = 0; i < sizeof(rejected_secret); ++i)
  {
    if (!require(rejected_secret[i] == 0, "secret zero on error"))
    {
      return 1;
    }
  }
  for (i = 0; i < sizeof(rejected_ct2); ++i)
  {
    if (!require(rejected_ct2[i] == 0, "ct2 zero on error"))
    {
      return 1;
    }
  }

  if (!require(deep_mlkem_braid_v1_state_free(0) == DEEP_MLKEM_BRAID_V1_INVALID_HANDLE,
               "null handle rejection") ||
      !require(deep_mlkem_braid_v1_zero(sender_secret, sizeof(sender_secret)) == DEEP_MLKEM_BRAID_V1_OK,
               "explicit zero"))
  {
    return 1;
  }

  puts("Deep ML-KEM Braid native C ABI probe passed.");
  return 0;
}

