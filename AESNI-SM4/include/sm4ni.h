#ifndef SM4NI_H
#define SM4NI_H

#include "sm4_ref.h"

// AES-NI / SSE3 implementation, encrypt 4 blocks at once
void sm4_encrypt4(const uint32_t rk[32], void *src, const void *dst);

#endif // SM4NI_H