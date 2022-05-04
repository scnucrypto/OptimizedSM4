/*
 * @Descripttion : 
 * @Version      : 
 * @Autor        : one30
 * @Date         : 2022-04-19 22:44:27
 * @LastEditTime : 2022-04-24 21:49:06
 * @FilePath     : /BS-SM4/include/sm4_bs256.h
 */
#ifndef SM4_BS256_H
#define SM4_BS256_H

#include <string.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <immintrin.h>
#include "utils.h"
#include "mode_gcm.h"
#define BLOCK_SIZE          128
#define WORD_SIZE           256
#define BS_BLOCK_SIZE       4096
#define _mm256_set_m128i(v0, v1)  _mm256_insertf128_si256(_mm256_castsi128_si256(v1), (v0), 1)
#define _mm256_setr_m128i(v0, v1) _mm256_set_m128i((v1), (v0))
typedef __m256i DATATYPE;
#define AND(a,b)  _mm256_and_si256(a,b)
#define OR(a,b)   _mm256_or_si256(a,b)
#define XOR(a,b)  _mm256_xor_si256(a,b)
#define ANDN(a,b) _mm256_andnot_si256(a,b)
#define NOT(a)    _mm256_xor_si256(ONES,a)
typedef struct {
  __m256i b0;
  __m256i b1;
  __m256i b2;
  __m256i b3;
  __m256i b4;
  __m256i b5;
  __m256i b6;
  __m256i b7;
} bits_256;

#ifdef __cplusplus
extern "C" {
#endif

void hi();
void benchmark_sm4_bs_ecb_encrypt(uint8_t *plain, uint8_t *cipher,int size,__m256i (*rk)[32]);
void benchmark_sm4_bs_ctr_encrypt(uint8_t *plain, uint8_t *cipher,int size,__m256i (*rk)[32],uint8_t * iv);
void benchmark_sm4_bs_gcm_encrypt(uint8_t *plain, uint8_t *cipher,int size,__m256i (*rk)[32],
    uint8_t * iv, int iv_len, uint8_t *add ,int add_len,
    uint8_t *tag, int tag_len, uint8_t T[][256][16]);
void sm4_bs256_ecb_encrypt(uint8_t* outputb,uint8_t* inputb,int size,__m256i (*rk)[32]);
void sm4_bs256_ctr_encrypt(uint8_t * outputb, uint8_t * inputb, int size, __m256i (*rk)[32], uint8_t * iv);
void sm4_bs256_gcm_encrypt(uint8_t *outputb, uint8_t *inputb, int size,
    __m256i (*rk)[32], uint8_t *iv, int iv_len, uint8_t *add ,int add_len,
    uint8_t *tag, int tag_len, gcm_context *ctx);
void sm4_bs256_gcm_init(gcm_context *context, unsigned char *key,
__m256i (*BS_RK_256)[32], unsigned char *iv);
void sm4_bs256_key_schedule(uint8_t* key, __m256i (*BS_RK_256)[32]);
void Sm4_BS256_BoolFun(bits_256 in, __m256i *out0, __m256i *out1, __m256i *out2, __m256i *out3, __m256i *out4, __m256i *out5, __m256i *out6, __m256i *out7);
void BS256_iteration(__m256i* N,__m256i (*BS_RK_256)[32]);
void Sbox_BS256(int round,__m256i (*buf_256)[32]);
void BS_TRANS_128x128(__m128i* M,__m128i* N);
void BS_TRANS_128x256(__m128i* M,__m256i* N);
void BS_TRANS_inv();
void BS_TRANS_VER_128x256(__m256i* N,__m128i* M);
unsigned long sm4CalciRK(unsigned long ka);
static unsigned char sm4Sbox(unsigned char inch);

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
        | ( (unsigned long) (b)[(i) + 1] << 16 )        \
        | ( (unsigned long) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

/*
 *rotate shift left marco definition
 *
 */
#define  SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))

#define SWAP(a,b) { uint64_t t = a; a = b; b = t; t = 0; }

#ifdef __cplusplus
}
#endif

#endif // SM4_BS256_H