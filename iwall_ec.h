#ifndef _IWALL_EC_H_
#define _IWALL_EC_H_
#include <openssl/ec.h>

//功能：自定义产生ECC密钥对函数
//返回值：成功返回1，失败返回0
int iwall_ec_keygen(EC_KEY *ec_key);

//功能：自定义ECDSA签名算法
//返回值：成功返回1，失败返回0
int iwall_ec_sign(int type, const unsigned char *dgst, int dlen, unsigned char *sig, unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey);

//功能：自定义ECDSA签名验证算法
//返回值：成功返回1，失败返回0
int iwall_ec_verify(int type, const unsigned char *dgst, int dgst_len, const unsigned char *sigbuf, int sig_len, EC_KEY *eckey);

//功能：自定义ECDH密钥交换算法
//返回值：成功返回密钥长度，失败返回-1
int iwall_ec_compute_key(unsigned char **psec, size_t *pseclen, const EC_POINT *pub_key, const EC_KEY *ecdh);

#endif // !_IWALL_EC_H_
