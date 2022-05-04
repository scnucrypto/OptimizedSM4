/*
 * @Descripttion : 
 * @Version      : 
 * @Autor        : one30
 * @Date         : 2022-04-24 15:52:06
 * @LastEditTime : 2022-04-24 21:37:04
 * @FilePath     : /BS-SM4/include/sm4_bs512.h
 */
#ifndef SM4_BS512_H
#define SM4_BS512_H

#include <string.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <immintrin.h>
#include "utils.h"
#include "mode_gcm.h"
#include "sm4_bs256.h"

#define BS512_BLOCK_SIZE       8192
typedef struct {
  __m512i b0;
  __m512i b1;
  __m512i b2;
  __m512i b3;
  __m512i b4;
  __m512i b5;
  __m512i b6;
  __m512i b7;
} bits_512;

#ifdef __cplusplus
extern "C" {
#endif

void benchmark_sm4_bs512_ecb_encrypt(uint8_t *plain, uint8_t *cipher,int size,__m512i (*rk)[32]);
void benchmark_sm4_bs512_ctr_encrypt(uint8_t *plain, uint8_t *cipher,int size,__m512i (*rk)[32],uint8_t * iv);
void benchmark_sm4_bs512_gcm_encrypt(uint8_t *plain, uint8_t *cipher,int size,__m512i (*rk)[32],
    uint8_t * iv, int iv_len, uint8_t *add ,int add_len,
    uint8_t *tag, int tag_len, uint8_t T[][256][16]);
void sm4_bs512_ecb_encrypt(uint8_t* outputb,uint8_t* inputb,int size,__m512i (*rk)[32]);
void sm4_bs512_ctr_encrypt(uint8_t * outputb, uint8_t * inputb, int size, __m512i (*rk)[32], uint8_t * iv);
void sm4_bs512_gcm_encrypt(uint8_t *outputb, uint8_t *inputb, int size,
    __m512i (*rk)[32], uint8_t *iv, int iv_len, uint8_t *add ,int add_len,
    uint8_t *tag, int tag_len, gcm_context *ctx);
void sm4_bs512_gcm_init(gcm_context *context, unsigned char *key,
__m512i (*BS_RK_512)[32], unsigned char *iv);
void sm4_bs512_key_schedule(uint8_t* key, __m512i (*BS_RK_512)[32]);
void Sm4_BS512_BoolFun(bits_512 in, __m512i *out0, __m512i *out1, __m512i *out2, __m512i *out3, __m512i *out4, __m512i *out5, __m512i *out6, __m512i *out7);
void BS512_iteration(__m512i* N, __m512i BS_RK_512[32][32]);
void Sbox_BS512(int round,__m512i buf_512[36][32]);
void BS_TRANS2_128x512(__m128i* M,__m512i* N);
void BS_TRANS2_VER_128x512(__m512i* N,__m128i* M);

#ifdef __cplusplus
}
#endif

#endif // SM4_BS512_H