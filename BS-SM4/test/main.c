/*
 * @Descripttion : 
 * @Version      : 
 * @Autor        : one30
 * @Date         : 2022-04-19 22:20:53
 * @LastEditTime : 2022-05-04 11:36:34
 * @FilePath     : /BS-SM4/test/main.c
 */

#include <stdio.h>
#include "sm4_bs256.h"

int main(int argc, char * argv[]){
    printf("bitslice!\n");
     sm4_bs256_ecb_test();
    //  sm4_bs256_ctr_test();
    //  sm4_bs256_gcm_test();

    sm4_bs512_ecb_test();
    // sm4_bs512_ctr_test();
    // sm4_bs512_gcm_test();
}
