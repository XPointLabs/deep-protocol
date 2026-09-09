#include "deep_mlkem_braid_v1.h"

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct deep_mlkem_braid_api {
  void *library;
  size_t (*keygen_random_size)(void);
  size_t (*decapsulation_key_size)(void);
  size_t (*encapsulation_key_seed_size)(void);
  size_t (*encapsulation_key_hash_size)(void);
  size_t (*encapsulation_key_vector_size)(void);
  size_t (*encapsulation_random_size)(void);
  size_t (*ciphertext1_size)(void);
  size_t (*ciphertext2_size)(void);
  size_t (*shared_secret_size)(void);
  int32_t (*keypair_generate)(uint8_t *, size_t, uint8_t *, size_t, uint8_t *,
                              size_t, uint8_t *, size_t);
  int32_t (*encaps1_generate)(const uint8_t *, size_t, const uint8_t *, size_t,
                              uint8_t *, size_t,
                              deep_mlkem_braid_v1_state_handle *);
  int32_t (*encaps2)(deep_mlkem_braid_v1_state_handle, const uint8_t *, size_t,
                     const uint8_t *, size_t, uint8_t *, size_t, uint8_t *,
                     size_t);
  int32_t (*decapsulate)(const uint8_t *, size_t, const uint8_t *, size_t,
                         const uint8_t *, size_t, uint8_t *, size_t);
  int32_t (*state_free)(deep_mlkem_braid_v1_state_handle);
  int32_t (*zero)(uint8_t *, size_t);
} deep_mlkem_braid_api;

static int fail(const char *stage, int32_t status)
{
  fprintf(stderr,
          "{\"schema\":\"deep-mlkem-braid-android-probe-v1\","
          "\"result\":\"fail\",\"stage\":\"%s\",\"status\":%d}\n",
          stage, status);
  return 0;
}

static int load_symbol(void *library, const char *name, void *destination,
                       size_t destination_size)
{
  void *symbol;
  const char *error;

  dlerror();
  symbol = dlsym(library, name);
  error = dlerror();
  if (error != NULL || symbol == NULL || destination_size != sizeof(symbol)) {
    return 0;
  }
  memcpy(destination, &symbol, sizeof(symbol));
  return 1;
}

#define LOAD(api, field, symbol_name)                                           \
  do {                                                                          \
    if (!load_symbol((api)->library, (symbol_name), &(api)->field,              \
                     sizeof((api)->field))) {                                   \
      return fail("dlsym", DEEP_MLKEM_BRAID_V1_INTERNAL_ERROR);                \
    }                                                                           \
  } while (0)

static int load_api(deep_mlkem_braid_api *api)
{
  memset(api, 0, sizeof(*api));
  api->library = dlopen("./libdeep_mlkem_braid.so", RTLD_NOW | RTLD_LOCAL);
  if (api->library == NULL) {
    return fail("dlopen", DEEP_MLKEM_BRAID_V1_INTERNAL_ERROR);
  }

  LOAD(api, keygen_random_size, "deep_mlkem_braid_v1_keygen_random_size");
  LOAD(api, decapsulation_key_size,
       "deep_mlkem_braid_v1_decapsulation_key_size");
  LOAD(api, encapsulation_key_seed_size,
       "deep_mlkem_braid_v1_encapsulation_key_seed_size");
  LOAD(api, encapsulation_key_hash_size,
       "deep_mlkem_braid_v1_encapsulation_key_hash_size");
  LOAD(api, encapsulation_key_vector_size,
       "deep_mlkem_braid_v1_encapsulation_key_vector_size");
  LOAD(api, encapsulation_random_size,
       "deep_mlkem_braid_v1_encapsulation_random_size");
  LOAD(api, ciphertext1_size, "deep_mlkem_braid_v1_ciphertext1_size");
  LOAD(api, ciphertext2_size, "deep_mlkem_braid_v1_ciphertext2_size");
  LOAD(api, shared_secret_size, "deep_mlkem_braid_v1_shared_secret_size");
  LOAD(api, keypair_generate, "deep_mlkem_braid_v1_keypair_generate");
  LOAD(api, encaps1_generate, "deep_mlkem_braid_v1_encaps1_generate");
  LOAD(api, encaps2, "deep_mlkem_braid_v1_encaps2");
  LOAD(api, decapsulate, "deep_mlkem_braid_v1_decapsulate");
  LOAD(api, state_free, "deep_mlkem_braid_v1_state_free");
  LOAD(api, zero, "deep_mlkem_braid_v1_zero");
  return 1;
}

static void wipe_material(deep_mlkem_braid_api *api, uint8_t *dk,
                          uint8_t *vector, uint8_t *seed, uint8_t *hash,
                          uint8_t *ct1, uint8_t *ct2, uint8_t *sender_secret,
                          uint8_t *recipient_secret)
{
  (void)api->zero(dk, 2400);
  (void)api->zero(vector, 1152);
  (void)api->zero(seed, 32);
  (void)api->zero(hash, 32);
  (void)api->zero(ct1, 960);
  (void)api->zero(ct2, 128);
  (void)api->zero(sender_secret, 32);
  (void)api->zero(recipient_secret, 32);
}

static int run_roundtrip(deep_mlkem_braid_api *api)
{
  uint8_t dk[2400] = {0};
  uint8_t vector[1152] = {0};
  uint8_t seed[32] = {0};
  uint8_t hash[32] = {0};
  uint8_t ct1[960] = {0};
  uint8_t ct2[128] = {0};
  uint8_t sender_secret[32] = {0};
  uint8_t recipient_secret[32] = {0};
  uint8_t replay_ct2[128];
  uint8_t replay_secret[32];
  deep_mlkem_braid_v1_state_handle state = 0;
  deep_mlkem_braid_v1_state_handle disposable_state = 0;
  int32_t status;
  int ok = 0;

  if (api->keygen_random_size() != 64 ||
      api->decapsulation_key_size() != sizeof(dk) ||
      api->encapsulation_key_seed_size() != sizeof(seed) ||
      api->encapsulation_key_hash_size() != sizeof(hash) ||
      api->encapsulation_key_vector_size() != sizeof(vector) ||
      api->encapsulation_random_size() != 32 ||
      api->ciphertext1_size() != sizeof(ct1) ||
      api->ciphertext2_size() != sizeof(ct2) ||
      api->shared_secret_size() != sizeof(sender_secret)) {
    fail("abi-sizes", DEEP_MLKEM_BRAID_V1_INVALID_LENGTH);
    goto cleanup;
  }

  status = api->keypair_generate(dk, sizeof(dk), vector, sizeof(vector), seed,
                                 sizeof(seed), hash, sizeof(hash));
  if (status != DEEP_MLKEM_BRAID_V1_OK) {
    fail("keygen", status);
    goto cleanup;
  }
  status = api->encaps1_generate(seed, sizeof(seed), hash, sizeof(hash), ct1,
                                 sizeof(ct1), &state);
  if (status != DEEP_MLKEM_BRAID_V1_OK || state == 0) {
    fail("encaps1", status);
    goto cleanup;
  }
  status = api->encaps2(state, seed, sizeof(seed), vector, sizeof(vector), ct2,
                        sizeof(ct2), sender_secret, sizeof(sender_secret));
  if (status != DEEP_MLKEM_BRAID_V1_OK) {
    fail("encaps2", status);
    state = 0;
    goto cleanup;
  }

  memset(replay_ct2, 0x55, sizeof(replay_ct2));
  memset(replay_secret, 0x55, sizeof(replay_secret));
  status = api->encaps2(state, seed, sizeof(seed), vector, sizeof(vector),
                        replay_ct2, sizeof(replay_ct2), replay_secret,
                        sizeof(replay_secret));
  if (status != DEEP_MLKEM_BRAID_V1_INVALID_HANDLE) {
    fail("replay-status", status);
    goto cleanup;
  }
  if (memcmp(replay_ct2, (uint8_t[128]){0}, sizeof(replay_ct2)) != 0 ||
      memcmp(replay_secret, (uint8_t[32]){0}, sizeof(replay_secret)) != 0) {
    fail("replay-zeroization", DEEP_MLKEM_BRAID_V1_INTERNAL_ERROR);
    goto cleanup;
  }
  state = 0;

  status = api->decapsulate(dk, sizeof(dk), ct1, sizeof(ct1), ct2,
                            sizeof(ct2), recipient_secret,
                            sizeof(recipient_secret));
  if (status != DEEP_MLKEM_BRAID_V1_OK ||
      memcmp(sender_secret, recipient_secret, sizeof(sender_secret)) != 0) {
    fail("decapsulation", status);
    goto cleanup;
  }

  status = api->encaps1_generate(seed, sizeof(seed), hash, sizeof(hash), ct1,
                                 sizeof(ct1), &disposable_state);
  if (status != DEEP_MLKEM_BRAID_V1_OK || disposable_state == 0) {
    fail("dispose-setup", status);
    goto cleanup;
  }
  status = api->state_free(disposable_state);
  if (status != DEEP_MLKEM_BRAID_V1_OK) {
    fail("dispose", status);
    disposable_state = 0;
    goto cleanup;
  }
  status = api->state_free(disposable_state);
  if (status != DEEP_MLKEM_BRAID_V1_INVALID_HANDLE) {
    fail("double-dispose", status);
    disposable_state = 0;
    goto cleanup;
  }
  disposable_state = 0;
  ok = 1;

cleanup:
  if (state != 0) {
    (void)api->state_free(state);
  }
  if (disposable_state != 0) {
    (void)api->state_free(disposable_state);
  }
  (void)api->zero(replay_ct2, sizeof(replay_ct2));
  (void)api->zero(replay_secret, sizeof(replay_secret));
  wipe_material(api, dk, vector, seed, hash, ct1, ct2, sender_secret,
                recipient_secret);
  return ok;
}

static int unload_api(deep_mlkem_braid_api *api)
{
  int status = dlclose(api->library);
  memset(api, 0, sizeof(*api));
  return status == 0;
}

int main(void)
{
  deep_mlkem_braid_api api;

  if (!load_api(&api) || !run_roundtrip(&api)) {
    return 1;
  }
  if (!unload_api(&api)) {
    return fail("dlclose-1", DEEP_MLKEM_BRAID_V1_INTERNAL_ERROR) ? 0 : 1;
  }
  if (!load_api(&api) || !run_roundtrip(&api)) {
    return 1;
  }
  if (!unload_api(&api)) {
    return fail("dlclose-2", DEEP_MLKEM_BRAID_V1_INTERNAL_ERROR) ? 0 : 1;
  }

  puts("{\"schema\":\"deep-mlkem-braid-android-probe-v1\","
       "\"result\":\"pass\",\"roundTrips\":2,"
       "\"replayRejected\":true,\"doubleDisposeRejected\":true,"
       "\"reloadPassed\":true,\"secretsEmitted\":false}");
  return 0;
}
