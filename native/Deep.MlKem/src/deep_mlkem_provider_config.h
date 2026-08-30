#ifndef DEEP_MLKEM_PROVIDER_CONFIG_H
#define DEEP_MLKEM_PROVIDER_CONFIG_H

#include <stddef.h>

/* Deep-owned fixed configuration; upstream vendored files remain byte-exact. */
#define MLK_CONFIG_PARAMETER_SET 768
#define MLK_CONFIG_NAMESPACE_PREFIX deep_vendor_mlkem768
#define MLK_CONFIG_NO_RANDOMIZED_API
#define MLK_CONFIG_NO_ASM
#define MLK_CONFIG_CUSTOM_ZEROIZE

#if defined(__cplusplus)
extern "C" {
#endif

void deep_mlkem_provider_zeroize(void *pointer, size_t length);

#if defined(__cplusplus)
}
#endif

#define mlk_zeroize deep_mlkem_provider_zeroize

#endif
