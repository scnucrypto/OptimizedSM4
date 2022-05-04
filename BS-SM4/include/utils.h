/*
 * @Descripttion : 
 * @Version      : 
 * @Autor        : one30
 * @Date         : 2022-04-19 22:44:12
 * @LastEditTime : 2022-04-23 22:47:36
 * @FilePath     : /BS-SM4/include/utils.h
 */
#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))
#define MAX(X,Y) ((X) > (Y) ? (X) : (Y))

#ifdef __cplusplus
extern "C" {
#endif

void dump_hex(uint8_t * h, int len);
uint64_t start_rdtsc();
uint64_t end_rdtsc();

#ifdef __cplusplus
}
#endif

#endif // UTILS_H