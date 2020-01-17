#include <string.h>
#include "iwall_rsa.h"
#include "rsa/rsa.h"
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/sha.h>

int iwall_rsa_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
	printf("welcome to iwall rsa_genkey!\n");
	return 1;
}

int iwall_rsa_pub_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
	printf("welcome to iwall rsa_pub_enc!\n");
	unsigned char data_in[512] = {0};
	unsigned char data_out[512] = {0};
	int bits = RSA_bits(rsa);

	switch (padding)
	{
	case RSA_NO_PADDING:
		RSA_padding_add_none(data_in, bits / 8, from, flen); break;
	case RSA_PKCS1_PADDING:
		RSA_padding_add_PKCS1_type_2(data_in, bits / 8, from, flen);break;
	case RSA_SSLV23_PADDING:
		RSA_padding_add_SSLv23(data_in, bits / 8, from, flen);break;
	default:
		printf("padding type unknown!");
		return -1;
	}
	
	R_RSA_PUBLIC_KEY rsa_pubkey;
	memset(&rsa_pubkey, 0, sizeof(R_RSA_PUBLIC_KEY));
	rsa_pubkey.bits = bits;

	int bn_len = 0;
	BIGNUM *bn_e = NULL;
	BIGNUM *bn_n = NULL;
	RSA_get0_key(rsa, &bn_n, &bn_e, NULL);
	memset(data_out, 0, sizeof(data_out));
	bn_len = BN_bn2bin(bn_e, data_out);
	memcpy(rsa_pubkey.exponent + MAX_RSA_MODULUS_LEN - bn_len, data_out, bn_len);
	memset(data_out, 0, sizeof(data_out));
	bn_len = BN_bn2bin(bn_n, data_out);
	memcpy(rsa_pubkey.modulus + MAX_RSA_MODULUS_LEN - bn_len, data_out, bn_len);
	
	int out_len = 0;
	memset(data_out, 0, sizeof(data_out));
	if (0 != RSAPublicBlock(data_out, &out_len, data_in, bits / 8, &rsa_pubkey))
		return -1;
	memcpy(to, data_out, out_len);
	return out_len;
}

int iwall_rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
	printf("welcome to iwall rsa_priv_dec!\n");
	unsigned char data_out[512] = { 0 };
	R_RSA_PRIVATE_KEY rsa_prikey;
	memset(&rsa_prikey, 0, sizeof(R_RSA_PRIVATE_KEY));
	rsa_prikey.bits = RSA_bits(rsa);

	int bn_len = 0;
	BIGNUM *bn_n = NULL;
	BIGNUM *bn_p = NULL;
	BIGNUM *bn_q = NULL;
	BIGNUM *bn_dp = NULL;
	BIGNUM *bn_dq = NULL;
	BIGNUM *bn_i = NULL;
	RSA_get0_key(rsa, &bn_n, NULL, NULL);
	memset(data_out, 0, sizeof(data_out));
	bn_len = BN_bn2bin(bn_n, data_out);
	memcpy(rsa_prikey.modulus + MAX_RSA_MODULUS_LEN - bn_len, data_out, bn_len);
	RSA_get0_factors(rsa, &bn_p, &bn_q);
	RSA_get0_crt_params(rsa, &bn_dp, &bn_dq, &bn_i);
	memset(data_out, 0, sizeof(data_out));
	bn_len = BN_bn2bin(bn_p, data_out);
	memcpy(rsa_prikey.prime[0]+ MAX_RSA_PRIME_LEN-bn_len, data_out, bn_len);
	memset(data_out, 0, sizeof(data_out));
	bn_len = BN_bn2bin(bn_q, data_out);
	memcpy(rsa_prikey.prime[1] + MAX_RSA_PRIME_LEN-bn_len, data_out, bn_len);
	memset(data_out, 0, sizeof(data_out));
	bn_len = BN_bn2bin(bn_dp, data_out);
	memcpy(rsa_prikey.primeExponent[0] + MAX_RSA_PRIME_LEN - bn_len, data_out, bn_len);
	memset(data_out, 0, sizeof(data_out));
	bn_len = BN_bn2bin(bn_dq, data_out);
	memcpy(rsa_prikey.primeExponent[1] + MAX_RSA_PRIME_LEN - bn_len, data_out, bn_len);
	memset(data_out, 0, sizeof(data_out));
	bn_len = BN_bn2bin(bn_i, data_out);
	memcpy(rsa_prikey.coefficient + MAX_RSA_PRIME_LEN - bn_len, data_out, bn_len);


	int out_len = 0;
	memset(data_out, 0, sizeof(data_out));
	if (0 != RSAPrivateBlock(data_out, &out_len, (unsigned char*)from, flen, &rsa_prikey))
		return -1;

	switch (padding)
	{
	case RSA_NO_PADDING:
		memcpy(to, data_out, out_len);
		return out_len;
	case RSA_PKCS1_PADDING:
	case RSA_SSLV23_PADDING:
		for (int i = 1; i < out_len; i++)
		{
			if (data_out[i] == 0x00)
			{
				memcpy(to, data_out + i + 1, out_len - i - 1);
				return out_len - i - 1;
			}
		}
		return -1;
	default:
		printf("error:padding type unknown!\n");
		return -1;
	}
}

int iwall_rsa_sign(int type, const unsigned char *m, unsigned int m_length, unsigned char *sigret, unsigned int *siglen, const RSA *rsa)
{
	printf("welcome to iwall rsa_sign!\n");
	int hash_len = 0;
	unsigned char hash_v[64] = {0};
	unsigned char data_in[512] = {0};
	int bits = RSA_bits(rsa);

	switch (type)
	{
	case NID_sha1:
		hash_len = SHA_DIGEST_LENGTH;
		SHA1(m, m_length, hash_v);
		break;
	default:
		printf("error:hash algID unknown!\n");
		return -1;
	}

	RSA_padding_add_PKCS1_type_2(data_in, bits / 8, hash_v, hash_len);
	if (-1 == iwall_rsa_priv_dec(bits / 8, data_in, sigret, rsa, RSA_NO_PADDING))
		return -1;
	*siglen = bits / 8;
	return 1;
}

//功能：自定义RSA签名验证算法
//返回值：成功返回1，失败返回-1
int iwall_rsa_verify(int type, const unsigned char *m, unsigned int m_length, const unsigned char *sigbuf, unsigned int siglen, const RSA *rsa)
{
	printf("welcome to iwall rsa_verify!\n");
	int hash_len = 0;
	unsigned char hash_v[64] = { 0 };
	unsigned char data_out[512] = {0};
	int bits = RSA_bits(rsa);

	switch (type)
	{
	case NID_sha1:
		hash_len = SHA_DIGEST_LENGTH;
		SHA1(m, m_length, hash_v);
		break;
	default:
		printf("error:Hash algID unknown!\n");
		return -1;
	}

	if (-1 == iwall_rsa_pub_enc(siglen, sigbuf, data_out, rsa, RSA_NO_PADDING))
		return -1;
	if (0 == memcmp(hash_v, data_out+(bits / 8)- hash_len, hash_len))
		return 1;
	else
		return -1;
}
