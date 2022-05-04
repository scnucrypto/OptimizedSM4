/*
 * @Descripttion : 
 * @Version      : 
 * @Autor        : one30
 * @Date         : 2022-04-23 22:51:43
 * @LastEditTime : 2022-04-23 22:51:44
 * @FilePath     : /BS-SM4/src/mode_gcm.c
 */
#include <stdint.h>
#include <stdlib.h>
#include <immintrin.h>

#include "mode_gcm.h"

void *gcm_init() {
    return malloc(sizeof(gcm_context));
}

void gcm_free( void *ctx ) {
    if ( ctx ) {
        gcm_context *temp_ctx = (gcm_context*)ctx;
        // if ( temp_ctx->rk ) {
        //     free(temp_ctx->rk);
        // }
        free(ctx);
    }
}

 void otherT(uint8_t T[][256][16]) {
	int i = 0, j = 0, k = 0;
	uint64_t vh, vl;
	uint64_t zh, zl;
	for ( i = 0; i < 256; i++ ) {
		vh = ((uint64_t)T[0][i][0]<<56) ^ ((uint64_t)T[0][i][1]<<48) ^ ((uint64_t)T[0][i][2]<<40) ^ ((uint64_t)T[0][i][3]<<32) ^
			((uint64_t)T[0][i][4]<<24) ^ ((uint64_t)T[0][i][5]<<16) ^ ((uint64_t)T[0][i][6]<<8) ^ ((uint64_t)T[0][i][7]);
		vl = ((uint64_t)T[0][i][8]<<56) ^ ((uint64_t)T[0][i][9]<<48) ^ ((uint64_t)T[0][i][10]<<40) ^ ((uint64_t)T[0][i][11]<<32) ^
			((uint64_t)T[0][i][12]<<24) ^ ((uint64_t)T[0][i][13]<<16) ^ ((uint64_t)T[0][i][14]<<8) ^ ((uint64_t)T[0][i][15]);
		zh = zl = 0;
		for ( j = 0; j <= 120; j++ ) {
			if ( (j > 0) && (0 == j%8) ) {
				zh ^= vh;
				zl ^= vl;
				for ( k = 1; k <= GCM_BLOCK_SIZE/2; k++ ) {
					T[j/8][i][GCM_BLOCK_SIZE/2-k] = (uint8_t)zh;
					zh = zh >> 8;
					T[j/8][i][GCM_BLOCK_SIZE-k] = (uint8_t)zl;
					zl = zl >> 8;
				}
				zh = zl = 0;
			}
			if ( vl & 0x1 ) {
				vl = vl >> 1;
				if ( vh & 0x1) { vl ^= 0x8000000000000000;}
				vh = vh >> 1;
				vh ^= GCM_FIELD_CONST;
			} else {
				vl = vl >> 1;
				if ( vh & 0x1) { vl ^= 0x8000000000000000;}
				vh = vh >> 1;
			}
		}
	}
}

void computeTable(uint8_t T[][256][16], uint8_t H[]) {

	// zh is the higher 64-bit, zl is the lower 64-bit
	uint64_t zh = 0, zl = 0;
	// vh is the higher 64-bit, vl is the lower 64-bit
	uint64_t vh = ((uint64_t)H[0]<<56) ^ ((uint64_t)H[1]<<48) ^ ((uint64_t)H[2]<<40) ^ ((uint64_t)H[3]<<32) ^
			((uint64_t)H[4]<<24) ^ ((uint64_t)H[5]<<16) ^ ((uint64_t)H[6]<<8) ^ ((uint64_t)H[7]);
	uint64_t vl = ((uint64_t)H[8]<<56) ^ ((uint64_t)H[9]<<48) ^ ((uint64_t)H[10]<<40) ^ ((uint64_t)H[11]<<32) ^
			((uint64_t)H[12]<<24) ^ ((uint64_t)H[13]<<16) ^ ((uint64_t)H[14]<<8) ^ ((uint64_t)H[15]);
	uint8_t temph;

	uint64_t tempvh = vh;
	uint64_t tempvl = vl;
	int i = 0, j = 0;
	for ( i = 0; i < 256; i++ ) {
		temph = (uint8_t)i;
		vh = tempvh;
		vl = tempvl;
		zh = zl = 0;

		for ( j = 0; j < 8; j++ ) {
			if ( 0x80 & temph ) {
				zh ^= vh;
				zl ^= vl;
			}
			if ( vl & 0x1 ) {
				vl = vl >> 1;
				if ( vh & 0x1) { vl ^= 0x8000000000000000;}
				vh = vh >> 1;
				vh ^= GCM_FIELD_CONST;
			} else {
				vl = vl >> 1;
				if ( vh & 0x1) { vl ^= 0x8000000000000000;}
				vh = vh >> 1;
			}
			temph = temph << 1;
		}
		// get result
		for ( j = 1; j <= GCM_BLOCK_SIZE/2; j++ ) {
			T[0][i][GCM_BLOCK_SIZE/2-j] = (uint8_t)zh;
			zh = zh >> 8;
			T[0][i][GCM_BLOCK_SIZE-j] = (uint8_t)zl;
			zl = zl >> 8;
		}
	}
	otherT(T);
}

static void multi(uint8_t T[][256][16], uint8_t *output) {
	uint8_t i, j;
	uint8_t temp[16];
	for ( i = 0; i < 16; i++ ) {
		temp[i] = output[i];
		output[i] = 0;
	}
	for ( i = 0; i < 16; i++ ) {
		for ( j = 0; j < 16; j++ ) {
			output[j] ^= T[i][*(temp+i)][j];
		}
	}


	// __m128i Temp = _mm_load_si128((__m128i *)output);
	// __m128i out = _mm_setzero_si128();
	// for ( i = 0; i < 16; i++ ) {
	// 	// for ( j = 0; j < 16; j++ ) {
	// 	// 	output[j] ^= T[i][*(temp+i)][j];
	// 	// }
	// 	out ^= 
	// }

	
	
}

void ghash(uint8_t T[][256][16],
		const uint8_t *add, 
		size_t add_len,
		const uint8_t *cipher,
		size_t length,
		uint8_t *output) {
	/* x0 = 0 */
	*(uint64_t *)output = 0;
	*((uint64_t *)output+1) = 0;

	/* compute with add */
	int i = 0;
	for ( i = 0; i < add_len/GCM_BLOCK_SIZE; i++ ) {
		*(uint64_t *)output ^= *(uint64_t *)add;
		*((uint64_t *)output+1) ^= *((uint64_t *)add+1);
		add += GCM_BLOCK_SIZE;
		multi(T, output);
	}

	if ( add_len % GCM_BLOCK_SIZE ) {
		// the remaining add
		for ( i = 0; i < add_len%GCM_BLOCK_SIZE; i++ ) {
			*(output+i) ^= *(add+i);
		}
		multi(T, output);
	}

	/* compute with cipher text */
	for ( i = 0; i < length/GCM_BLOCK_SIZE; i++ ) {
		*(uint64_t *)output ^= *(uint64_t *)cipher;
		*((uint64_t *)output+1) ^= *((uint64_t *)cipher+1);
		cipher += GCM_BLOCK_SIZE;
		multi(T, output);
	}
	if ( length % GCM_BLOCK_SIZE ) {
		// the remaining cipher
		for ( i = 0; i < length%GCM_BLOCK_SIZE; i++ ) {
			*(output+i) ^= *(cipher+i);
		}
		multi(T, output);
	}

	/* eor (len(A)||len(C)) */
	uint64_t temp_len = (uint64_t)(add_len*8); // len(A) = (uint64_t)(add_len*8)
	for ( i = 1; i <= GCM_BLOCK_SIZE/2; i++ ) {
		output[GCM_BLOCK_SIZE/2-i] ^= (uint8_t)temp_len;
		temp_len = temp_len >> 8;
	}
	temp_len = (uint64_t)(length*8); // len(C) = (uint64_t)(length*8)
	for ( i = 1; i <= GCM_BLOCK_SIZE/2; i++ ) {
		output[GCM_BLOCK_SIZE-i] ^= (uint8_t)temp_len;
		temp_len = temp_len >> 8;
	}
	multi(T, output);
}

#define xor_state(output, input, buff, size) \
    for (t = 0; t < size; ++t) {             \
        output[t] = input[t] ^ buff[t];      \
    }

#define copy_state(output, input, size) \
    for (t = 0; t < size; ++t) {        \
        output[t] = input[t];           \
    }