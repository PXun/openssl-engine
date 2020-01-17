#include <string.h>
#include <openssl/engine.h>
#include "iwall_rsa.h"
#include "iwall_ec.h"

static const char *engine_id = "iwall";
static const char *engine_name = "iwall_engine";

static int engine_init(ENGINE *e)
{
	return 1;
}

static int engine_finish(ENGINE *e)
{
	return 1;
}

static int engine_destroy(ENGINE *e)
{
	return 1;
}

ENGINE *ENGINE_load_iwall_engine()
{
	ENGINE *engine = ENGINE_new();
	if (!engine) return NULL;

	RSA_METHOD *rsa_method = RSA_meth_dup((RSA_METHOD *)RSA_get_default_method());
	//下列算法如不需要外部自定义，请屏蔽
	//RSA_meth_set_keygen(rsa_method, iwall_rsa_keygen);
	RSA_meth_set_pub_enc(rsa_method, iwall_rsa_pub_enc);
	RSA_meth_set_priv_dec(rsa_method, iwall_rsa_priv_dec);
	RSA_meth_set_sign(rsa_method, iwall_rsa_sign);
	RSA_meth_set_verify(rsa_method, iwall_rsa_verify);

	EC_KEY_METHOD *ec_method = EC_KEY_METHOD_new((EC_KEY_METHOD *)EC_KEY_get_default_method());
	//EC_KEY_METHOD_set_keygen(ec_method, iwall_ec_keygen);
	EC_KEY_METHOD_set_sign(ec_method, iwall_ec_sign, NULL, NULL);
	EC_KEY_METHOD_set_verify(ec_method, iwall_ec_verify, NULL);
	EC_KEY_METHOD_set_compute_key(ec_method, iwall_ec_compute_key);


	if (!ENGINE_set_id(engine, engine_id)
		|| !ENGINE_set_name(engine, engine_name)
		|| !ENGINE_set_RSA(engine, rsa_method)//设置engine使用的RSA方法
		|| !ENGINE_set_EC(engine, ec_method)//设置engine使用EC算法
		|| !ENGINE_set_init_function(engine, engine_init)
		|| !ENGINE_set_finish_function(engine, engine_finish)
		|| !ENGINE_set_destroy_function(engine, engine_destroy))
	{
		ENGINE_free(engine);
		return NULL;
	}

	if (0 == ENGINE_set_default_RSA(engine)
		|| 0 == ENGINE_set_default_EC(engine))
	{
		ENGINE_free(engine);
		return NULL;
	}

	return engine;
}

void ENGINE_clean_iwall_engine(ENGINE *engine)
{
	if (!engine) return;
	ENGINE_set_RSA(engine, RSA_get_default_method());
	ENGINE_set_EC(engine, EC_KEY_get_default_method());
	ENGINE_set_default_RSA(engine);
	ENGINE_set_default_EC(engine);
	ENGINE_free(engine);
}
