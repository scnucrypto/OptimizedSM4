# 国密SM4算法优化方案整理
## AESNI-SM4
ref:https://github.com/mjosaarinen/sm4ni.git 
实现方案：AESNI指令集+同构映射
### 快速编译及测试
```
$ mkdir build && cd build
$ cmake ..
$ make
$ ../bin/sm4ni
```

## BS-SM4
ref:基于塔域的SM4算法快速软件实现
实现方案：比特切片+SIMD(AVX2/AVX512)+SM4
### 快速编译及测试
```
$ mkdir build && cd build
$ cmake ..
$ make
$ ../bin/bs_sm4
```

## LUT-SM4
ref:SM4的快速软件实现技术
实现方案：使用8-32查找表实现 
### 快速编译及测试
```
$ mkdir build && cd build
$ cmake ..
$ make
$ ../bin/lut_sm4
```

## OpenSSL-BS-SM4
ref:基于塔域的SM4算法快速软件实现
实现方案：openssl+比特切片+SIMD(AVX2/AVX512)+SM4
### 快速编译及测试
```
$ ./config --prefix=安装目录(/openssl-1.1.1i/out) -mavx2 -mavx512f -mavx512bw
$ make
$ make install
```