#include <stdio.h>
#include <string.h>
#include <openssl/engine.h>
#include <openssl/ssl.h>

#include "crypto_engine.h"

#ifdef WIN32
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")
#endif

void testRSA()
{
	RSA *rsa = RSA_new();
	BIGNUM *e = BN_new();

	BN_set_word(e, 65537);
	RSA_generate_key_ex(rsa, 2048, e, NULL);

	unsigned char buff_in[256] = {0};
	unsigned char buff_out[256] = {0};
	unsigned char buff_bak[256] = {0};

	memset(buff_in, 0x88, 256);
	if (-1 == RSA_public_encrypt(256, buff_in, buff_out, rsa, RSA_NO_PADDING))
	{
		printf("rsa public key encrypt error!\n");
		return;
	}
	if (-1 == RSA_private_decrypt(256, buff_out, buff_bak, rsa, RSA_NO_PADDING))
	{
		printf("rsa private key decrypt error!\n");
		return;
	}
	
	if (0 != memcmp(buff_in, buff_bak, 256))
	{
		printf("rsa encrypt and decrypt error!\n");
		return;
	}

	int out_len = 0;
	memset(buff_out, 0, sizeof(buff_out));
	if (1 != RSA_sign(NID_sha1, buff_in, 256, buff_out, &out_len, rsa))
	{
		printf("rsa sign error!\n");
		return;
	}
	if (1 != RSA_verify(NID_sha1, buff_in, 256, buff_out, out_len, rsa))
	{
		printf("rsa verify error!\n");
		return;
	}
	printf("rsa test ok!\n");
}

void testEC()
{
	unsigned char *sign_value = NULL;
	EC_KEY *ec_key_a = NULL;
	EC_KEY *ec_key_b = NULL;
	ec_key_a = EC_KEY_new();
	ec_key_b = EC_KEY_new();
	if (!ec_key_a || !ec_key_b)
	{
		printf("new ec_key error!\n");
		goto END;
	}

	//获取当前支持的曲线
	int crv_num = EC_get_builtin_curves(NULL, 0);
	EC_builtin_curve *curves = (EC_builtin_curve *)malloc(sizeof(EC_builtin_curve) * crv_num);
	EC_get_builtin_curves(curves, crv_num);

	//任意选择一种曲线,生成密钥参数
	EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(curves[25].nid);
	if (!ec_group)
	{
		printf("get ec_group by name error!\n");
		goto END;
	}

	//设置密钥参数
	if (1 != EC_KEY_set_group(ec_key_a, ec_group))
	{
		printf("set group for ec_key error!\n");
		goto END;
	}
	if (1 != EC_KEY_set_group(ec_key_b, ec_group))
	{
		printf("set group for ec_key error!\n");
		goto END;
	}

	//生成密钥
	if (1 != EC_KEY_generate_key(ec_key_a))
	{
		printf("gen ec_key error!\n");
		goto END;
	}
	if (1 != EC_KEY_generate_key(ec_key_b))
	{
		printf("gen ec_key error!\n");
		goto END;
	}

	//检测密钥正确性
	if (1 != EC_KEY_check_key(ec_key_a) || 1 != EC_KEY_check_key(ec_key_b))
	{
		printf("set group for ec_key error!\n");
		goto END;
	}

	int max_size = ECDSA_size(ec_key_a);
	unsigned char sign_data[20];

	memset(sign_data, 0x77, 20);
	sign_value = (unsigned char *)malloc(max_size+1);
	memset(sign_value, 0, max_size + 1);
	//ECDSA签名和签名验证
	int siglen = 0;
	if (1 != ECDSA_sign(0, sign_data, 20, sign_value, &siglen, ec_key_a))
	{
		printf("ecdsa sign error!\n");
		goto END;
	}
	if (1 != ECDSA_verify(0, sign_data, 20, sign_value, siglen, ec_key_a))
	{
		printf("ecdsa verify error!\n");
		goto END;
	}

	//测试密钥协商
	unsigned char share_key_1[128] = {0};
	unsigned char share_key_2[128] = { 0 };
	const EC_POINT *pubkey_b = EC_KEY_get0_public_key(ec_key_b);
	int key_len_1 = ECDH_compute_key(share_key_1, 128, pubkey_b, ec_key_a, NULL);
	const EC_POINT *pubkey_a = EC_KEY_get0_public_key(ec_key_a);
	int key_len_2 = ECDH_compute_key(share_key_2, 128, pubkey_a, ec_key_b, NULL);
	if (key_len_1 != key_len_2 || 0 != memcmp(share_key_1, share_key_2, key_len_1))
	{
		printf("ecdsa compute key error!\n");
		goto END;
	}
	printf("ec test ok!\n");

END:
	EC_KEY_free(ec_key_a);
	EC_KEY_free(ec_key_b);
	free(sign_value);
}

int main()
{
	ENGINE *engine = ENGINE_load_iwall_engine();
	if (NULL == engine)
	{
		printf("Engine load error!\n");
		return 0;
	}

	testRSA();
	testEC();

	ENGINE_clean_iwall_engine(engine);
	return 0;
}
