#ifndef _IWALL_RSA_H_
#define _IWALL_RSA_H_
#include <openssl/rsa.h>

//功能：自定义产生密钥对函数
//返回值：成功返回1，失败返回-1
int iwall_rsa_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);

//功能：自定义RSA公钥加密
//返回值：成功返回密文长度(128或256)，失败返回-1
int iwall_rsa_pub_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);

//功能：自定义RSA私钥解密
//返回值：成功返回解密后数据长度，失败返回-1
int iwall_rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);

//功能：自定义RSA签名算法
//返回值：成功返回1，失败返回-1
int iwall_rsa_sign(int type, const unsigned char *m, unsigned int m_length, unsigned char *sigret, unsigned int *siglen, const RSA *rsa);

//功能：自定义RSA签名验证算法
//返回值：成功返回1，失败返回-1
int iwall_rsa_verify(int type, const unsigned char *m, unsigned int m_length, const unsigned char *sigbuf, unsigned int siglen, const RSA *rsa);

#endif
