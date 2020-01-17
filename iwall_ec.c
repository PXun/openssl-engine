#include <string.h>
#include "iwall_ec.h"

int iwall_ec_keygen(EC_KEY *ec_key)
{
	return 1;
}

int iwall_ec_sign(int type, const unsigned char *dgst, int dlen, unsigned char *sig, unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey)
{
	return 1;
}

int iwall_ec_verify(int type, const unsigned char *dgst, int dgst_len, const unsigned char *sigbuf, int sig_len, EC_KEY *eckey)
{
	return 1;
}

int iwall_ec_verify_sig(const unsigned char *dgst, int dgst_len, const ECDSA_SIG *sig, EC_KEY *eckey)
{
	return 1;
}

int iwall_ec_compute_key(unsigned char **psec,size_t *pseclen,const EC_POINT *pub_key,const EC_KEY *ecdh)
{
	*pseclen = 128;
	*psec = (unsigned char *)malloc(128);
	memset(*psec, 0x11, 128);
	return 128;
}
