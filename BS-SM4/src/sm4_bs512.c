/*
 * @Descripttion : 
 * @Version      : 
 * @Autor        : one30
 * @Date         : 2022-04-24 15:51:00
 * @LastEditTime : 2022-04-24 21:46:44
 * @FilePath     : /BS-SM4/src/sm4_bs512.c
 */
#include "sm4_bs512.h"

void benchmark_sm4_bs512_ecb_encrypt(uint8_t *plain, uint8_t *cipher,int size,__m512i (*rk)[32])
{
    // int turns = 10000;
    int turns = 100;
    clock_t t = clock();
    for(int i=0; i<turns; i++)
    {
        //sm4_bs256_ecb_encrypt(cipher,plain,size,rk);
        sm4_bs512_ecb_encrypt(cipher, plain, size, rk);
    }
    double tt = (double)(clock() - t) / (CLOCKS_PER_SEC*turns);
	double speed = (double) size / (1024 * 1024 * tt);
    printf("SM4_encrypt>>> blocks: %d, time: %f s, speed: %f Mb/s\n", size/16, tt, speed*8);
}

void benchmark_sm4_bs512_ctr_encrypt(uint8_t *plain, uint8_t *cipher,int size,__m512i (*rk)[32],uint8_t * iv)
{
    //int turns = 10000;
    int turns = 10000;
    clock_t t = clock();
    for(int i=0; i<turns; i++)
    {
        //sm4_bs256_ctr_encrypt(cipher,plain,size,rk,iv);
        sm4_bs512_ctr_encrypt(cipher, plain, size, rk, iv);
    }
    double tt = (double)(clock() - t) / (CLOCKS_PER_SEC*turns);
	double speed = (double) size / (1024 * 1024 * tt);
    printf("SM4_encrypt>>> blocks: %d, time: %f s, speed: %f Mb/s\n", size/16, tt, speed*8);
}


void benchmark_sm4_bs512_gcm_encrypt(uint8_t *plain, uint8_t *cipher,int size,__m512i (*rk)[32],
    uint8_t * iv, int iv_len, uint8_t *add ,int add_len,
    uint8_t *tag, int tag_len, uint8_t T[][256][16])
{
    // int turns = 10000;
    int turns = 10000;
    clock_t t = clock();
    for(int i=0; i<turns; i++)
    {
        sm4_bs512_gcm_encrypt(cipher,plain,size,rk,iv,iv_len,add,add_len,
            tag,tag_len,T);
    }
    double tt = (double)(clock() - t) / (CLOCKS_PER_SEC*turns);
	double speed = (double) size / (1024 * 1024 * tt);
    printf("SM4_encrypt>>> blocks: %d, time: %f s, speed: %f Mb/s\n", size/16, tt, speed*8);
}

void sm4_bs512_ecb_encrypt(uint8_t* outputb,uint8_t* inputb,int size,__m512i (*rk)[32]){
    __m512i output_space[BLOCK_SIZE];
    __m128i input_space[BLOCK_SIZE*4];
    __m128i state[512];
    __m128i t;
    __m512i t2;
    //the masking for shuffle the data
    __m128i vindex_swap = _mm_setr_epi8(
		7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8
	);
    __m256i vindex_swap2 = _mm256_setr_epi8(
		7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8,
        7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8
	);
    __m512i vindex_swap3 = _mm512_set_epi8(
		7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8,
        7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8,
        7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8,
        7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8
	);

    memset(outputb,0,size);
    __m512i* out = (__m512i*)outputb;
    __m128i* in = (__m128i*)inputb;

    while(size > 0)
    {
        if(size < BS512_BLOCK_SIZE)
        {
            memset(input_space,0,BS512_BLOCK_SIZE);
            for(int i=0; i<size/16; i++)
            {
                t = _mm_shuffle_epi8(in[i],vindex_swap);
                _mm_storeu_si128(input_space+i,t);
            }
            
            sm4_bs512_enc(input_space,output_space,rk);


            // for(int i=0; i<(size+16)/32; i++)
            // {
            //     t2 = _mm256_shuffle_epi8(output_space[i],vindex_swap2);
            //     _mm256_storeu_si256(out+i,t2);          
            // }
            __m128i* out_t = (__m128i*)out;
            for(int i=0; i<size/16; i++)
            {
                t = _mm_shuffle_epi8(input_space[i],vindex_swap);
                _mm_storeu_si128(out_t,t);
                out_t++;
            }
            size = 0;
            //out += size;
        }
        else
        {
            memmove(state,inputb,BS512_BLOCK_SIZE);
            for(int i=0; i<BLOCK_SIZE*4; i++){
                t = _mm_shuffle_epi8(in[i],vindex_swap);
                _mm_storeu_si128(input_space+i,t);
            }
            sm4_bs512_enc(input_space,output_space,rk);
            for(int i=0; i<BLOCK_SIZE; i++)
            {
                t2 = _mm512_shuffle_epi8(output_space[i],vindex_swap3);
                _mm512_storeu_si512(out+i,t2);          
            }
            size -= BS512_BLOCK_SIZE;
            out += BLOCK_SIZE;
            in += BLOCK_SIZE*4;
        }
        
    }
}

void sm4_bs512_ctr_encrypt(uint8_t * outputb, uint8_t * inputb, int size, __m512i (*rk)[32], uint8_t * iv)
{
    __m128i ctr[BLOCK_SIZE*4];
    __m512i output_space[BLOCK_SIZE];
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

    __m512i * state = (__m512i *)outputb;

    while(size)
    {
        int chunk = MIN(size, BS512_BLOCK_SIZE);
        int blocks = chunk / (BLOCK_SIZE/8);

        int i;
        for (i = 0; i < blocks; i++)
        {
            //memmove(ctr + (i * WORDS_PER_BLOCK), iv_copy, BS512_BLOCK_SIZE/8);
            // Attention: the ctr mode iv counter from 0 while gcm is from 1
            //count = _mm_add_epi64(count,cnt);
            ctr[i] = iv_copy + count;
            count = _mm_add_epi64(count,cnt);
        }

        sm4_bs512_enc(ctr,output_space,rk);
        
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

void sm4_bs512_gcm_init(gcm_context *context, unsigned char *key,
__m512i (*BS_RK_512)[32], unsigned char *iv)
{
    //key_schedule
    sm4_bs512_key_schedule(key, BS_RK_512);
    //compute table, init h and E(y0)

    uint8_t p_h[32],c_h[32];
    memset(p_h, 0, 32);//all 0
    memcpy(p_h+16, iv, 16);//iv||counter0
    memset(p_h+31, 1, 1);
    // sm4_bs256_ecb_encrypt(c_h,p_h,32,BS_RK_256);
    sm4_bs512_ecb_encrypt(c_h,p_h,32,BS_RK_512);
    computeTable(context->T, c_h);
    memcpy(context->H, c_h, 16);
    memcpy(context->Enc_y0, c_h+16, 16);
}

void sm4_bs512_gcm_encrypt(uint8_t *outputb, uint8_t *inputb, int size,
    __m512i (*rk)[32], uint8_t *iv, int iv_len, uint8_t *add ,int add_len,
    uint8_t *tag, int tag_len, gcm_context *ctx)
{
    __m128i ctr[BLOCK_SIZE*4];
    __m512i output_space[BLOCK_SIZE];
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

    __m512i * state = (__m512i *)outputb;

    while(size)
    {
        int chunk = MIN(size, BS512_BLOCK_SIZE);
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
        //sm4_bs256_enc(ctr,output_space,rk);
        sm4_bs512_enc(ctr,output_space,rk);

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

void sm4_bs512_key_schedule(uint8_t* key, __m512i (*BS_RK_512)[32])
{
    uint32_t rkey[32];
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

    for(int i = 0; i<32; i++)
    {
        K[i+4] = K[i] ^ (sm4CalciRK(K[i+1]^K[i+2]^K[i+3]^CK[i]));
        rkey[i] = K[i+4];
        //printf("rkey[%d]=%08x\n",i,rkey[i]);
	}

    uint64_t BS_RK[8];
    for(int i = 0; i<32; i++)
    {
        //printf("rkey[%d]=%08x\n",i,rkey[i]);
        uint64_t t = 0x1;
        for(int j = 0; j < 32; j++)
        {
            for(int k = 0; k < 8; k++)
            {
                if(rkey[i] & t)
                    BS_RK[k] = ~0;
                else
                {
                    BS_RK[k] = 0;
                }
            }
            BS_RK_512[i][31-j] = _mm512_loadu_si512((__m512i*)BS_RK);
            t = t << 1;
        }
    }

    for(int i = 0; i<32; i++){ // 32 round
        uint64_t t = 0x1;
        for(int j = 0; j < 32; j++) //32 bit
        {

            if (rkey[i] & t)
                BS_RK_512[i][31-j] = _mm512_set1_epi32(-1);
            else {
                BS_RK_512[i][31-j] = _mm512_setzero_si512();
            }
            t = t << 1;
        }
    }
    
}

void Sm4_BS512_BoolFun(bits_512 in, __m512i *out0, __m512i *out1, __m512i *out2, __m512i *out3, __m512i *out4, __m512i *out5, __m512i *out6, __m512i *out7){
        __m512i y_t[21], t_t[8], t_m[46], y_m[18], t_b[30];
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

void BS512_iteration(__m512i* N, __m512i BS_RK_512[32][32])
{
    int i = 0;
    uint64_t t1 , t2;
    __m512i buf_512[36][32];
    __m512i N_temp[128];
    __m512i temp_512[36][32];

    for(int j = 0; j < 4; j++)
    {
        for(int k = 0; k < 32; k++)
        {
            buf_512[j][k] = N[32*j+k];//load data
        }     
    }

    while(i < 32)//32轮迭代计算
    {

        for(int j = 0; j < 32; j++)//4道32bit数据操作:
        {
            buf_512[4+i][j]= buf_512[i+1][j] ^ buf_512[i+2][j] ^ buf_512[i+3][j] ^ BS_RK_512[i][j];
        }

        Sbox_BS512(i,buf_512);//bingo256 合成置换T的非线性变换
        
        for(int j = 0; j < 32; j++)//bingo256 4道32bit数据操作:合成置换T的线性变换L
        {
            temp_512[4+i][j]= buf_512[4+i][j] ^ buf_512[4+i][(j+2)%32] ^ buf_512[4+i][(j+10)%32] ^ buf_512[4+i][(j+18)%32] ^ buf_512[4+i][(j+24)%32];
        }
        for(int j = 0; j < 32; j++)//4道32bit数据操作
        {
            buf_512[4+i][j]= temp_512[i+4][j] ^ buf_512[i][j];
        }        
        i++;
    }

    for(int j = 0; j < 4; j++)//反序计算
    {
        for(int k = 0; k < 32; k++)
        {
            N[32*j+k] = buf_512[35-j][k];
        }
    }
}

void Sbox_BS512(int round,__m512i buf_512[36][32])
{
    bits_512 sm4;

    for(int i = 0; i<4; i++)
    {
        sm4.b7 = buf_512[round+4][i*8];
        sm4.b6 = buf_512[round+4][i*8+1];
        sm4.b5 = buf_512[round+4][i*8+2];
        sm4.b4 = buf_512[round+4][i*8+3];
        sm4.b3 = buf_512[round+4][i*8+4];
        sm4.b2 = buf_512[round+4][i*8+5];
        sm4.b1 = buf_512[round+4][i*8+6];
        sm4.b0 = buf_512[round+4][i*8+7];

        Sm4_BS512_BoolFun(sm4,&buf_512[round+4][i*8+7],&buf_512[round+4][i*8+6],&buf_512[round+4][i*8+5],&buf_512[round+4][i*8+4],
            &buf_512[round+4][i*8+3],&buf_512[round+4][i*8+2],&buf_512[round+4][i*8+1],&buf_512[round+4][i*8]);

    }

}

void sm4_bs512_enc(__m128i* M,__m512i* N,__m512i rk[32][32])
{
    BS_TRANS2_128x512(M,N);
    BS512_iteration(N,rk);
    BS_TRANS2_VER_128x512(N,M);
}

//from usuba sse.h orthogonalize
void BS_TRANS2_128x512(__m128i* M,__m512i* N){
    Ortho_128x128(M);
    Ortho_128x128(&(M[128]));
    Ortho_128x128(&(M[256]));
    Ortho_128x128(&(M[384]));
    uint64_t t0[2], t1[2], t2[2], t3[2];
    for(int i=0; i<128; i++)
    {
        /* _mm_store_si128((uint64_t*)t0, M[i]);
        _mm_store_si128((uint64_t*)t1, M[128+i]);
        _mm_store_si128((uint64_t*)t2, M[256+i]);
        _mm_store_si128((uint64_t*)t3, M[384+i]); */
        _mm_store_si128((__m128i*)t0, M[i]);
        _mm_store_si128((__m128i*)t1, M[128+i]);
        _mm_store_si128((__m128i*)t2, M[256+i]);
        _mm_store_si128((__m128i*)t3, M[384+i]);
        N[i] = _mm512_set_epi64(t3[1], t3[0], t2[1], t2[0], 
            t1[1], t1[0], t0[1], t0[0]);
    }
}

void BS_TRANS2_VER_128x512(__m512i* N,__m128i* M){
    __m64 temp[8];
    for(int i = 0; i < 128; i++)
    {
        _mm512_store_epi64((__m512i*)temp,N[i]);
        M[i] = _mm_set_epi64(temp[1],temp[0]);
        M[128+i]= _mm_set_epi64(temp[3],temp[2]);
        M[256+i] = _mm_set_epi64(temp[5],temp[4]);  
        M[384+i] = _mm_set_epi64(temp[7],temp[6]);
    }

    Ortho_128x128(M);
    Ortho_128x128(&(M[128]));
    Ortho_128x128(&(M[256]));
    Ortho_128x128(&(M[384]));
}