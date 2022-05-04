#include "sm4_bs256.h"

static const unsigned char SboxTable[16][16] = 
{
    {0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05},
    {0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99},
    {0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62},
    {0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6},
    {0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8},
    {0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35},
    {0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87},
    {0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e},
    {0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1},
    {0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3},
    {0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f},
    {0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51},
    {0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8},
    {0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0},
    {0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84},
    {0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48}
};

void hi()
{
    printf("hello world\n");
}


void benchmark_sm4_bs_ecb_encrypt(uint8_t *plain, uint8_t *cipher,int size,__m256i (*rk)[32])
{
    // int turns = 10000;
    int turns = 10000;
    clock_t t = clock();
    for(int i=0; i<turns; i++)
    {
        sm4_bs256_ecb_encrypt(cipher,plain,size,rk);
    }
    double tt = (double)(clock() - t) / (CLOCKS_PER_SEC*turns);
	double speed = (double) size / (1024 * 1024 * tt);
    printf("SM4_encrypt>>> blocks: %d, time: %f s, speed: %f Mb/s\n", size/16, tt, speed*8);
}

void benchmark_sm4_bs_ctr_encrypt(uint8_t *plain, uint8_t *cipher,int size,__m256i (*rk)[32],uint8_t * iv)
{
    // int turns = 10000;
    int turns = 10000;
    clock_t t = clock();
    for(int i=0; i<turns; i++)
    {
        sm4_bs256_ctr_encrypt(cipher,plain,size,rk,iv);
    }
    double tt = (double)(clock() - t) / (CLOCKS_PER_SEC*turns);
	double speed = (double) size / (1024 * 1024 * tt);
    printf("SM4_encrypt>>> blocks: %d, time: %f s, speed: %f Mb/s\n", size/16, tt, speed*8);
}

void benchmark_sm4_bs_gcm_encrypt(uint8_t *plain, uint8_t *cipher,int size,__m256i (*rk)[32],
    uint8_t * iv, int iv_len, uint8_t *add ,int add_len,
    uint8_t *tag, int tag_len, uint8_t T[][256][16])
{
    // int turns = 10000;
    int turns = 10000;
    clock_t t = clock();
    for(int i=0; i<turns; i++)
    {
        sm4_bs256_gcm_encrypt(cipher,plain,size,rk,iv,iv_len,add,add_len,
            tag,tag_len,T);
    }
    double tt = (double)(clock() - t) / (CLOCKS_PER_SEC*turns);
	double speed = (double) size / (1024 * 1024 * tt);
    printf("SM4_encrypt>>> blocks: %d, time: %f s, speed: %f Mb/s\n", size/16, tt, speed*8);
}

void sm4_bs256_ecb_encrypt(uint8_t* outputb,uint8_t* inputb,int size,__m256i (*rk)[32])
{
    __m256i output_space[BLOCK_SIZE];
    __m128i input_space[BLOCK_SIZE*2];
    __m128i state[256];
    __m128i t;
    __m256i t2;

    //the masking for shuffle the data
    __m128i vindex_swap = _mm_setr_epi8(
		7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8
	);
    __m256i vindex_swap2 = _mm256_setr_epi8(
		7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8,
        7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8
	);

    memset(outputb,0,size);
    __m256i* out = (__m256i*)outputb;
    __m128i* in = (__m128i*)inputb;
    
    // sm4_bs256_key_schedule(key,rk);

    while(size > 0)
    {
        if(size < BS_BLOCK_SIZE)
        {
            memset(input_space,0,BS_BLOCK_SIZE);
            for(int i=0; i<size/16; i++)
            {
                t = _mm_shuffle_epi8(in[i],vindex_swap);
                _mm_storeu_si128(input_space+i,t);
            }

            sm4_bs256_enc(input_space,output_space,rk);

            __m128i* out_t = (__m128i*)out;
            for(int i=0; i<size/16; i++)
            {
                t = _mm_shuffle_epi8(input_space[i],vindex_swap);
                _mm_storeu_si128(out_t,t);
                out_t++;
            }
            size = 0;
            // out += size;
        }
        else
        {
            memmove(state,inputb,BS_BLOCK_SIZE);
            for(int i=0; i<BLOCK_SIZE*2; i++){
                t = _mm_shuffle_epi8(in[i],vindex_swap);
                _mm_storeu_si128(input_space+i,t);
            }
            sm4_bs256_enc(input_space,output_space,rk);
            __m256i* out_256 = (__m256i*)out;
            for(int i=0; i<BLOCK_SIZE; i++)
            {
                t2 = _mm256_shuffle_epi8(output_space[i],vindex_swap2);
                _mm256_storeu_si256(out_256,t2);   
                out_256++;       
            }
            size -= BS_BLOCK_SIZE;
            out += BLOCK_SIZE;
            in += BLOCK_SIZE*2;
        }
        
    }
}


static void INC_CTR(uint8_t * ctr, uint8_t i)
{
    ctr += BLOCK_SIZE/8 - 1;
    uint8_t n = *(ctr);
    *ctr += i;
    while(*ctr < n)
    {
        ctr--;
        n = *ctr;
        (*ctr)++;
    }
}

static void ctr128_inc(unsigned char *counter)
{
    uint32_t n = 16, c = 1;

    do {
        --n;
        c += counter[n];
        counter[n] = (uint8_t)c;
        c >>= 8;
    } while (n);
}

/**
 * @description: ctr mode of bitslice 256-slice of sm4
 * @param {uint8_t} *
 * @param {uint8_t} *
 * @param {int} size
 * @param {uint8_t} *
 * @return {*}
 * @Date: 2021-01-08 22:35:42
 * @author: one30
 */
void sm4_bs256_ctr_encrypt(uint8_t * outputb, uint8_t * inputb, int size, __m256i (*rk)[32], uint8_t * iv)
{
    __m128i ctr[BLOCK_SIZE*2];
    __m256i output_space[BLOCK_SIZE];
    __m128i iv_copy;
    __m128i t,t2;
    __m128i count = _mm_setzero_si128();
    //uint64_t count = 0;
    uint64_t op[2] = {0,1};
    __m128i cnt = _mm_loadu_si128((__m128i*)op);
    __m128i vindex_swap = _mm_setr_epi8(
		7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8
	);
    __m256i vindex_swap2 = _mm256_setr_epi8(
		7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8,
        7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8
	);

    memset(outputb,0,size);
    memset(ctr,0,sizeof(ctr));
    t = _mm_load_si128((__m128i *)iv);
    iv_copy = _mm_shuffle_epi8(t,vindex_swap);

    __m256i * state = (__m256i *)outputb;

    while(size)
    {
        int chunk = MIN(size, BS_BLOCK_SIZE);
        int blocks = chunk / (BLOCK_SIZE/8);

        int i;
        for (i = 0; i < blocks; i++)
        {
            //memmove(ctr + (i * WORDS_PER_BLOCK), iv_copy, BLOCK_SIZE/8);
            // Attention: the ctr mode iv counter from 0 while gcm is from 1
            //count = _mm_add_epi64(count,cnt);
            ctr[i] = iv_copy + count;
            count = _mm_add_epi64(count,cnt);
        }

        //bs_cipher(ctr, rk);
        sm4_bs256_enc(ctr,output_space,rk);
        for(i=0; i<blocks; i++)
        {
            ctr[i] = _mm_shuffle_epi8(ctr[i],vindex_swap);     
        }
        size -= chunk;

        uint8_t * ctr_p = (uint8_t *) ctr;
        for(i=0; i<chunk; i++)
        {
            outputb[i] = *ctr_p++ ^ inputb[i];
        }
    }
}


/**
 * @description: gcm mode of bitslice 256-slice of sm4
 * @param {uint8_t} *
 * @param {uint8_t} *
 * @param {int} size
 * @param {uint8_t} *
 * @return {*}
 * @Date: 2021-01-09 21:08:48
 * @author: one30
 */
void sm4_bs256_gcm_encrypt(uint8_t *outputb, uint8_t *inputb, int size,
    __m256i (*rk)[32], uint8_t *iv, int iv_len, uint8_t *add ,int add_len,
    uint8_t *tag, int tag_len, gcm_context *ctx)
{
    __m128i ctr[BLOCK_SIZE*2];
    __m256i output_space[BLOCK_SIZE];
    __m128i iv_copy;
    __m128i t,t2;
    __m128i count = _mm_setzero_si128();
    ctr[0] = count;//gcm mode 
    //uint64_t count = 0;
    uint64_t op[2] = {0,1};
    __m128i cnt = _mm_loadu_si128((__m128i*)op);
    __m128i vindex_swap = _mm_setr_epi8(
		7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8
	);
    __m256i vindex_swap2 = _mm256_setr_epi8(
		7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8,
        7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8
	);
    int length = size, flag = 1;

    memset(outputb,0,size);
    memset(ctr,0,sizeof(ctr));
    t = _mm_load_si128((__m128i *)iv);
    iv_copy = _mm_shuffle_epi8(t,vindex_swap);

    __m256i * state = (__m256i *)outputb;

    while(size)
    {
        int chunk = MIN(size, BS_BLOCK_SIZE);
        int blocks = chunk / (BLOCK_SIZE/8);

        count = _mm_add_epi64(count,cnt);
        int i;
        for (i = 0; i < blocks; i++)//gcm mode need more 1 block
        {
            //gcm mode iv from 0x02!
            count = _mm_add_epi64(count,cnt);
            ctr[i] = iv_copy + count;
        }

        //bs_cipher(ctr, rk);
        sm4_bs256_enc(ctr,output_space,rk);

        //shuffle the data because of the transforming Little-Endian to Big-Endian
        for(i=0; i<blocks; i++)
        {
            ctr[i] = _mm_shuffle_epi8(ctr[i],vindex_swap);

        }
        size -= chunk;

        uint8_t * ctr_p = (uint8_t *) ctr ;
        for(i=0; i<chunk; i++)
        {
            outputb[i] = *ctr_p++ ^ inputb[i];
        }
    }
    
    //Auth tag test
    //compute tag
    ghash(ctx->T,add,add_len, outputb, length , ctx->buff);
    //uint8_t *ency1 = (uint8_t *) ctr + 16;
    for (int i = 0; i < tag_len; ++i ) {
        tag[i] = ctx->buff[i] ^ ctx->Enc_y0[i];
    }

    //gcm_free(context);

}

//from usuba sse.h
void Ortho_128x128(__m128i data[]) {

  __m128i mask_l[7] = {
    _mm_set1_epi64x(0xaaaaaaaaaaaaaaaaUL),
    _mm_set1_epi64x(0xccccccccccccccccUL),
    _mm_set1_epi64x(0xf0f0f0f0f0f0f0f0UL),
    _mm_set1_epi64x(0xff00ff00ff00ff00UL),
    _mm_set1_epi64x(0xffff0000ffff0000UL),
    _mm_set1_epi64x(0xffffffff00000000UL),
    _mm_set_epi64x(0x0000000000000000UL,0xffffffffffffffffUL),

  };

  __m128i mask_r[7] = {
    _mm_set1_epi64x(0x5555555555555555UL),
    _mm_set1_epi64x(0x3333333333333333UL),
    _mm_set1_epi64x(0x0f0f0f0f0f0f0f0fUL),
    _mm_set1_epi64x(0x00ff00ff00ff00ffUL),
    _mm_set1_epi64x(0x0000ffff0000ffffUL),
    _mm_set1_epi64x(0x00000000ffffffffUL),
    _mm_set_epi64x(0xffffffffffffffffUL,0x0000000000000000UL),
  };

  for (int i = 0; i < 7; i ++) {
    int n = (1UL << i);
    for (int j = 0; j < 128; j += (2 * n))
      for (int k = 0; k < n; k ++) {
        __m128i u = _mm_and_si128(data[j + k], mask_l[i]);
        __m128i v = _mm_and_si128(data[j + k], mask_r[i]);
        __m128i x = _mm_and_si128(data[j + n + k], mask_l[i]);
        __m128i y = _mm_and_si128(data[j + n + k], mask_r[i]);
        if (i <= 5) {
          data[j + k] = _mm_or_si128(u, _mm_srli_epi64(x, n));
          data[j + n + k] = _mm_or_si128(_mm_slli_epi64(v, n), y);
        } else {
          /* Note the "inversion" of srli and slli. */
          data[j + k] = _mm_or_si128(u, _mm_slli_si128(x, 8));
          data[j + n + k] = _mm_or_si128(_mm_srli_si128(v, 8), y);
        }
      }
  }
}

void BS_TRANS_128x128(__m128i data[],__m128i N[]) {

  for(int i=0; i<128; i++)
  {
      N[i] = data[i];
  }
  __m128i mask_l[7] = {
    _mm_set1_epi64x(0xaaaaaaaaaaaaaaaaUL),
    _mm_set1_epi64x(0xccccccccccccccccUL),
    _mm_set1_epi64x(0xf0f0f0f0f0f0f0f0UL),
    _mm_set1_epi64x(0xff00ff00ff00ff00UL),
    _mm_set1_epi64x(0xffff0000ffff0000UL),
    _mm_set1_epi64x(0xffffffff00000000UL),
    _mm_set_epi64x(0x0000000000000000UL,0xffffffffffffffffUL),

  };

  __m128i mask_r[7] = {
    _mm_set1_epi64x(0x5555555555555555UL),
    _mm_set1_epi64x(0x3333333333333333UL),
    _mm_set1_epi64x(0x0f0f0f0f0f0f0f0fUL),
    _mm_set1_epi64x(0x00ff00ff00ff00ffUL),
    _mm_set1_epi64x(0x0000ffff0000ffffUL),
    _mm_set1_epi64x(0x00000000ffffffffUL),
    _mm_set_epi64x(0xffffffffffffffffUL,0x0000000000000000UL),
  };

  for (int i = 0; i < 7; i ++) {
    int n = (1UL << i);
    for (int j = 0; j < 128; j += (2 * n))
      for (int k = 0; k < n; k ++) {
        __m128i u = _mm_and_si128(N[j + k], mask_l[i]);
        __m128i v = _mm_and_si128(N[j + k], mask_r[i]);
        __m128i x = _mm_and_si128(N[j + n + k], mask_l[i]);
        __m128i y = _mm_and_si128(N[j + n + k], mask_r[i]);
        if (i <= 5) {
          N[j + k] = _mm_or_si128(u, _mm_srli_epi64(x, n));
          N[j + n + k] = _mm_or_si128(_mm_slli_epi64(v, n), y);
        } else {
          /* Note the "inversion" of srli and slli. */
          N[j + k] = _mm_or_si128(u, _mm_slli_si128(x, 8));
          N[j + n + k] = _mm_or_si128(_mm_srli_si128(v, 8), y);
        }
      }
  }
}
void BS_TRANS_128x256(__m128i* M,__m256i* N){
    Ortho_128x128(M);  
    Ortho_128x128(&M[128]);
    for(int i=0; i<128; i++)
        N[i] = _mm256_set_m128i(M[i], M[128+i]);
}

void BS_TRANS_VER_128x256(__m256i* N,__m128i* M){
    __m128i t[2];
    for(int i=0; i<128; i++)
    {
        _mm256_store_si256((__m256i*)t, N[i]);
        M[i] = t[1];
        M[128+i] = t[0];
    }
    Ortho_128x128(M);
    Ortho_128x128(&(M[128]));
}

/*
 * private function:
 * look up in SboxTable and get the related value.
 * args:    [in] inch: 0x00~0xFF (8 bits unsigned value).
 */
static unsigned char sm4Sbox(unsigned char inch)
{
    unsigned char *pTable = (unsigned char *)SboxTable;
    unsigned char retVal = (unsigned char)(pTable[inch]);
    return retVal;
}

/* private function:
 * Calculating round encryption key.
 * args:    [in] a: a is a 32 bits unsigned value;
 * return: sk[i]: i{0,1,2,3,...31}.
 */
unsigned long sm4CalciRK(unsigned long ka)
{
    unsigned long bb = 0;
    unsigned long rk = 0;
    unsigned char a[4];
    unsigned char b[4];
    PUT_ULONG_BE(ka,a,0)
    b[0] = sm4Sbox(a[0]);
    b[1] = sm4Sbox(a[1]);
    b[2] = sm4Sbox(a[2]);
    b[3] = sm4Sbox(a[3]);
	GET_ULONG_BE(bb,b,0)
    rk = bb^(ROTL(bb, 13))^(ROTL(bb, 23));
    return rk;
}

void sm4_bs256_key_schedule(uint8_t* key, __m256i (*BS_RK_256)[32])
{
    uint32_t rkey[32];
    uint64_t BS_RK[32][32][4];
	// System parameter or family key
	const uint32_t FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

	const uint32_t CK[32] = {
	0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
	0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
	0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
	0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
	0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
	0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
	0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
	0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
	};

	uint32_t K[36];
    uint32_t MK[4];
    GET_ULONG_BE( MK[0], key, 0 );
    GET_ULONG_BE( MK[1], key, 4 );
    GET_ULONG_BE( MK[2], key, 8 );
    GET_ULONG_BE( MK[3], key, 12 );

	K[0] = MK[0] ^ FK[0];
	K[1] = MK[1] ^ FK[1];
	K[2] = MK[2] ^ FK[2];
	K[3] = MK[3] ^ FK[3];

	// for(int i=0; i<32; i++)
	// {
	// 	K[i % 4] ^= SM4_Tp(K[(i+1)%4] ^ K[(i+2)%4] ^ K[(i+3)%4] ^ CK[i]);
	// 	rkey[i] = K[i % 4];
	// }

    for(int i = 0; i<32; i++)
    {
        K[i+4] = K[i] ^ (sm4CalciRK(K[i+1]^K[i+2]^K[i+3]^CK[i]));
        rkey[i] = K[i+4];
        //printf("rkey[%d]=%08x\n",i,rkey[i]);
	}

    //rkey[] 
    for(int i = 0; i<32; i++)
    {
        // printf("rkey[%d]=%08x\n",i,rkey[i]);
        uint64_t t = 0x1;
        for(int j = 0; j < 32; j++)
        {
            for(int k = 0; k < 4; k++)
            {
                if(rkey[i] & t)
                    BS_RK[i][31-j][k] = ~0;
                else
                {
                    BS_RK[i][31-j][k] = 0;
                }
            }
            t = t << 1;
        }
    }

    for(int i = 0; i < 32; i++)//load data
    {
        for(int j = 0; j < 32; j++)
        {
            BS_RK_256[i][j] = _mm256_loadu_si256((__m256i*)BS_RK[i][j]);
        }
    }
    
}

void sm4_bs256_gcm_init(gcm_context *context, unsigned char *key,
__m256i (*BS_RK_256)[32], unsigned char *iv)
{
    //key_schedule
    sm4_bs256_key_schedule(key,BS_RK_256);
    //compute table, init h and E(y0)
    uint8_t p_h[32],c_h[32];
    memset(p_h, 0, 32);//all 0
    memcpy(p_h+16, iv, 16);//iv||counter0
    memset(p_h+31, 1, 1);
    sm4_bs256_ecb_encrypt(c_h,p_h,32,BS_RK_256);
    computeTable(context->T, c_h);
    memcpy(context->H, c_h, 16);
    memcpy(context->Enc_y0, c_h+16, 16);
}

void BS256_iteration(__m256i* N,__m256i BS_RK_256[32][32])
{
    int i = 0;
    uint64_t t1 , t2;
    __m256i buf_256[36][32];
    __m256i N_temp[128];
    __m256i temp_256[36][32];

    for(int j = 0; j < 4; j++)
    {
        for(int k = 0; k < 32; k++)
        {
            buf_256[j][k] = N[32*j+k];//load data
        }     
    }
        
    while(i < 32)//32轮迭代计算
    {

        for(int j = 0; j < 32; j++)//4道32bit数据操作:
        {
            buf_256[4+i][j]= buf_256[i+1][j] ^ buf_256[i+2][j] ^ buf_256[i+3][j] ^ BS_RK_256[i][j];
        }

        Sbox_BS256(i,buf_256);//bingo256 合成置换T的非线性变换
        
        for(int j = 0; j < 32; j++)//bingo256 4道32bit数据操作:合成置换T的线性变换L
        {
            temp_256[4+i][j]= buf_256[4+i][j] ^ buf_256[4+i][(j+2)%32] ^ buf_256[4+i][(j+10)%32] ^ buf_256[4+i][(j+18)%32] ^ buf_256[4+i][(j+24)%32];
        }
        for(int j = 0; j < 32; j++)//4道32bit数据操作
        {
            buf_256[4+i][j]= temp_256[i+4][j] ^ buf_256[i][j];
        }        
        i++;
    }

    for(int j = 0; j < 4; j++)//反序计算
    {
        for(int k = 0; k < 32; k++)
        {

            N[32*j+k] = buf_256[35-j][k];
        }
    }

}

void Sbox_BS256(int round,__m256i buf_256[36][32])
{
    bits_256 sm4;

    for(int i = 0; i<4; i++)
    {
        sm4.b7 = buf_256[round+4][i*8];
        sm4.b6 = buf_256[round+4][i*8+1];
        sm4.b5 = buf_256[round+4][i*8+2];
        sm4.b4 = buf_256[round+4][i*8+3];
        sm4.b3 = buf_256[round+4][i*8+4];
        sm4.b2 = buf_256[round+4][i*8+5];
        sm4.b1 = buf_256[round+4][i*8+6];
        sm4.b0 = buf_256[round+4][i*8+7];

        Sm4_BS256_BoolFun(sm4,&buf_256[round+4][i*8+7],&buf_256[round+4][i*8+6],&buf_256[round+4][i*8+5],&buf_256[round+4][i*8+4],
            &buf_256[round+4][i*8+3],&buf_256[round+4][i*8+2],&buf_256[round+4][i*8+1],&buf_256[round+4][i*8]);

    }
    //for(int )

}

void sm4_bs256_enc(__m128i M[256],__m256i N[128],__m256i rk[32][32])
{
    BS_TRANS_128x256(M,N);
    BS256_iteration(N,rk);
    BS_TRANS_VER_128x256(N,M);
}

//130 gates - lwaes_isa
void Sm4_BS256_BoolFun(bits_256 in, __m256i *out0, __m256i *out1, __m256i *out2, __m256i *out3, __m256i *out4, __m256i *out5, __m256i *out6, __m256i *out7){
        __m256i y_t[21], t_t[8], t_m[46], y_m[18], t_b[30];
  	    y_t[18] = in.b2 ^in.b6;
		t_t[ 0] = in.b3 ^in.b4;
		t_t[ 1] = in.b2 ^in.b7;
		t_t[ 2] = in.b7 ^y_t[18];
		t_t[ 3] = in.b1 ^t_t[ 1];
		t_t[ 4] = in.b6 ^in.b7;
		t_t[ 5] = in.b0 ^y_t[18];
		t_t[ 6] = in.b3 ^in.b6;
		y_t[10] = in.b1 ^y_t[18];
		y_t[ 0] = in.b5 ^~ y_t[10];
		y_t[ 1] = t_t[ 0] ^t_t[ 3];
		y_t[ 2] = in.b0 ^t_t[ 0];
		y_t[ 4] = in.b0 ^t_t[ 3];
		y_t[ 3] = in.b3 ^y_t[ 4];
		y_t[ 5] = in.b5 ^t_t[ 5];
		y_t[ 6] = in.b0 ^~ in.b1;
		y_t[ 7] = t_t[ 0] ^~ y_t[10];
		y_t[ 8] = t_t[ 0] ^t_t[ 5];
		y_t[ 9] = in.b3;
		y_t[11] = t_t[ 0] ^t_t[ 4];
		y_t[12] = in.b5 ^t_t[ 4];
		y_t[13] = in.b5 ^~ y_t[ 1];
		y_t[14] = in.b4 ^~ t_t[ 2];
		y_t[15] = in.b1 ^~ t_t[ 6];
		y_t[16] = in.b0 ^~ t_t[ 2];
		y_t[17] = t_t[ 0] ^~ t_t[ 2];
		y_t[19] = in.b5 ^~ y_t[14];
		y_t[20] = in.b0 ^t_t[ 1];

    //The shared non-linear middle part for AES, AES^-1, and SM4
  	t_m[ 0] = y_t[ 3] ^	 y_t[12];
		t_m[ 1] = y_t[ 9] &	 y_t[ 5];
		t_m[ 2] = y_t[17] &	 y_t[ 6];
		t_m[ 3] = y_t[10] ^	 t_m[ 1];
		t_m[ 4] = y_t[14] &	 y_t[ 0];
		t_m[ 5] = t_m[ 4] ^	 t_m[ 1];
		t_m[ 6] = y_t[ 3] &	 y_t[12];
		t_m[ 7] = y_t[16] &	 y_t[ 7];
		t_m[ 8] = t_m[ 0] ^	 t_m[ 6];
		t_m[ 9] = y_t[15] &	 y_t[13];
		t_m[10] = t_m[ 9] ^	 t_m[ 6];
		t_m[11] = y_t[ 1] &	 y_t[11];
		t_m[12] = y_t[ 4] &	 y_t[20];
		t_m[13] = t_m[12] ^	 t_m[11];
		t_m[14] = y_t[ 2] &	 y_t[ 8];
		t_m[15] = t_m[14] ^	 t_m[11];
		t_m[16] = t_m[ 3] ^	 t_m[ 2];
		t_m[17] = t_m[ 5] ^	 y_t[18];
		t_m[18] = t_m[ 8] ^	 t_m[ 7];
		t_m[19] = t_m[10] ^	 t_m[15];
		t_m[20] = t_m[16] ^	 t_m[13];
		t_m[21] = t_m[17] ^	 t_m[15];
		t_m[22] = t_m[18] ^	 t_m[13];
		t_m[23] = t_m[19] ^	 y_t[19];
		t_m[24] = t_m[22] ^	 t_m[23];
		t_m[25] = t_m[22] &	 t_m[20];
		t_m[26] = t_m[21] ^	 t_m[25];
		t_m[27] = t_m[20] ^	 t_m[21];
		t_m[28] = t_m[23] ^	 t_m[25];
		t_m[29] = t_m[28] &	 t_m[27];
		t_m[30] = t_m[26] &	 t_m[24];
		t_m[31] = t_m[20] &	 t_m[23];
		t_m[32] = t_m[27] &	 t_m[31];
		t_m[33] = t_m[27] ^	 t_m[25];
		t_m[34] = t_m[21] &	 t_m[22];
		t_m[35] = t_m[24] &	 t_m[34];
		t_m[36] = t_m[24] ^	 t_m[25];
		t_m[37] = t_m[21] ^	 t_m[29];
		t_m[38] = t_m[32] ^	 t_m[33];
		t_m[39] = t_m[23] ^	 t_m[30];
		t_m[40] = t_m[35] ^	 t_m[36];
		t_m[41] = t_m[38] ^	 t_m[40];
		t_m[42] = t_m[37] ^	 t_m[39];
		t_m[43] = t_m[37] ^	 t_m[38];
		t_m[44] = t_m[39] ^	 t_m[40];
		t_m[45] = t_m[42] ^	 t_m[41];
		y_m[ 0] = t_m[38] &	 y_t[ 7];
		y_m[ 1] = t_m[37] &	 y_t[13];
		y_m[ 2] = t_m[42] &	 y_t[11];
		y_m[ 3] = t_m[45] &	 y_t[20];
		y_m[ 4] = t_m[41] &	 y_t[ 8];
		y_m[ 5] = t_m[44] &	 y_t[ 9];
		y_m[ 6] = t_m[40] &	 y_t[17];
		y_m[ 7] = t_m[39] &	 y_t[14];
		y_m[ 8] = t_m[43] &	 y_t[ 3];
		y_m[ 9] = t_m[38] &	 y_t[16];
		y_m[10] = t_m[37] &	 y_t[15];
		y_m[11] = t_m[42] &	 y_t[ 1];
		y_m[12] = t_m[45] &	 y_t[ 4];
		y_m[13] = t_m[41] &	 y_t[ 2];
		y_m[14] = t_m[44] &	 y_t[ 5];
		y_m[15] = t_m[40] &	 y_t[ 6];
		y_m[16] = t_m[39] &	 y_t[ 0];
		y_m[17] = t_m[43] &	 y_t[12];

  //bottom(outer) linear layer for sm4
  	t_b[ 0] = y_m[ 4] ^	 y_m[ 7];
		t_b[ 1] = y_m[13] ^	 y_m[15];
		t_b[ 2] = y_m[ 2] ^	 y_m[16];
		t_b[ 3] = y_m[ 6] ^	 t_b[ 0];
		t_b[ 4] = y_m[12] ^	 t_b[ 1];
		t_b[ 5] = y_m[ 9] ^	 y_m[10];
		t_b[ 6] = y_m[11] ^	 t_b[ 2];
		t_b[ 7] = y_m[ 1] ^	 t_b[ 4];
		t_b[ 8] = y_m[ 0] ^	 y_m[17];
		t_b[ 9] = y_m[ 3] ^	 y_m[17];
		t_b[10] = y_m[ 8] ^	 t_b[ 3];
		t_b[11] = t_b[ 2] ^	 t_b[ 5];
		t_b[12] = y_m[14] ^	 t_b[ 6];
		t_b[13] = t_b[ 7] ^	 t_b[ 9];
		t_b[14] = y_m[ 0] ^	 y_m[ 6];
		t_b[15] = y_m[ 7] ^	 y_m[16];
		t_b[16] = y_m[ 5] ^	 y_m[13];
		t_b[17] = y_m[ 3] ^	 y_m[15];
		t_b[18] = y_m[10] ^	 y_m[12];
		t_b[19] = y_m[ 9] ^	 t_b[ 1];
		t_b[20] = y_m[ 4] ^	 t_b[ 4];
		t_b[21] = y_m[14] ^	 t_b[ 3];
		t_b[22] = y_m[16] ^	 t_b[ 5];
		t_b[23] = t_b[ 7] ^	 t_b[14];
		t_b[24] = t_b[ 8] ^	 t_b[11];
		t_b[25] = t_b[ 0] ^	 t_b[12];
		t_b[26] = t_b[17] ^	 t_b[ 3];
		t_b[27] = t_b[18] ^	 t_b[10];
		t_b[28] = t_b[19] ^	 t_b[ 6];
		t_b[29] = t_b[ 8] ^	 t_b[10];
		*out0 = t_b[11] ^~ t_b[13];
		*out1 = t_b[15] ^~ t_b[23];
		*out2 = t_b[20] ^	 t_b[24];
		*out3 = t_b[16] ^	 t_b[25];
		*out4 = t_b[26] ^~ t_b[22];
		*out5 = t_b[21] ^	 t_b[13];
		*out6 = t_b[27] ^~ t_b[12];
		*out7 = t_b[28] ^~ t_b[29];
}