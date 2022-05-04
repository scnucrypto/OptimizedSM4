/*
 * @Descripttion : 
 * @Version      : 
 * @Autor        : one30
 * @Date         : 2022-04-23 22:31:39
 * @LastEditTime : 2022-04-23 22:34:40
 * @FilePath     : /BS-SM4/include/mode_gcm.h
 */
#ifndef MODE_GCM_H
#define MODE_GCM_H

#include <stdio.h>
#include <stdint.h>
#define GCM_BLOCK_SIZE  16       /* block size in bytes, AES 128-128 */
#define GCM_DEFAULT_IV_LEN (12)              /* default iv length in bytes */
#define GCM_FIELD_CONST (0xe100000000000000) /* the const value in filed */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * basic functions of a block cipher
 */
typedef int (*block_key_schedule_p)(const uint8_t *key, uint8_t *roundkeys);
typedef int (*block_encrypt_p)(const uint8_t *roundkeys, const uint8_t *input, uint8_t *output);
typedef int (*block_decrypt_p)(const uint8_t *roundkeys, const uint8_t *input, uint8_t *output);

/*
 * block cipher context structure
 */
typedef struct {
    // rounds keys of block cipher
    //__m256i rk[32][32];
    // block cipher encryption
    // block_encrypt_p block_encrypt;
    uint8_t H[GCM_BLOCK_SIZE];
    uint8_t Enc_y0[GCM_BLOCK_SIZE];//Enc(y0);y0 = iv||0
    uint8_t buff[GCM_BLOCK_SIZE];
    uint8_t T[GCM_BLOCK_SIZE][256][GCM_BLOCK_SIZE];
} gcm_context;

/**
 * @par purpose
 *    Initialize GCM context (just makes references valid)
 *    Makes the context ready for gcm_setkey() or
 *    gcm_free().
 */
void *gcm_init();


void gcm_free( void *ctx );

/**
 * compute T1, T2, ... , and T15
 * suppose 0^n is a string with n bit zeros, s1||s2 is a jointed string of s1 and s2
 * 
 * T1 = T0 . P^8
 * 	where P^8 = 0^8 || 1 || 0^119
 * T2 = T1 . P^8 = T0 . P^16
 * 	where P^16 = 0^16 || 1 || 0^111
 * T3 = T2 . P^8 = T0 . P^24
 * ...
 * T15 = T14 . P^8 = T0 . P^120
 * 	where P^120 = 0^120 || 1 || 0^7
 *
 */
 void otherT(uint8_t T[][256][16]);

/**
 * @purpose
 * compute table T0 = X0 . H
 * only the first byte of X0 is nonzero, other bytes are all 0
 * @T
 * the final tables: 16 tables in total, each has 256 elements, the value of which is 16 bytes
 * @H
 * 128-bit, H = E(K, 0^128)
 * the leftmost(most significant) bit of H[0] is bit-0 of H(in GCM)
 * the rightmost(least significant) bit of H[15] is bit-127 of H(in GCM)
 */
void computeTable(uint8_t T[][256][16], uint8_t H[]);

/*
 * a: additional authenticated data
 * c: the cipher text or initial vector
 */
void ghash(uint8_t T[][256][16],
		const uint8_t *add, 
		size_t add_len,
		const uint8_t *cipher,
		size_t length,
		uint8_t *output);

/**
 * return the value of (output.H) by looking up tables
 */
 static void multi(uint8_t T[][256][16], uint8_t *output);

#ifdef __cplusplus
}
#endif

#endif // MODE_GCM_H