
#ifndef _RSAHEADER_H_
#define _RSAHEADER_H_

#ifdef __cplusplus
extern "C" {
#endif



	/* RSA key lengths.
	*/
#define MIN_RSA_MODULUS_BITS 508
#define MAX_RSA_MODULUS_BITS 2048
#define MAX_RSA_MODULUS_LEN ((MAX_RSA_MODULUS_BITS + 7) / 8)
#define MAX_RSA_PRIME_BITS ((MAX_RSA_MODULUS_BITS + 1) / 2)
#define MAX_RSA_PRIME_LEN ((MAX_RSA_PRIME_BITS + 7) / 8)



	/* Error codes.
	*/
#define RE_CONTENT_ENCODING 0x0400
#define RE_DATA 0x0401
#define RE_DIGEST_ALGORITHM 0x0402
#define RE_ENCODING 0x0403
#define RE_KEY 0x0404
#define RE_KEY_ENCODING 0x0405
#define RE_LEN 0x0406
#define RE_MODULUS_LEN 0x0407
#define RE_NEED_RANDOM 0x0408
#define RE_PRIVATE_KEY 0x0409
#define RE_PUBLIC_KEY 0x040a
#define RE_SIGNATURE 0x040b
#define RE_SIGNATURE_ENCODING 0x040c

	/* RSA public and private key.
	*/
	typedef struct {
		unsigned int bits;                           /* length in bits of modulus */
		unsigned char modulus[MAX_RSA_MODULUS_LEN];                    /* modulus */
		unsigned char exponent[MAX_RSA_MODULUS_LEN];           /* public exponent */
	} R_RSA_PUBLIC_KEY;

	typedef struct {
		unsigned int bits;                           /* length in bits of modulus */
		unsigned char modulus[MAX_RSA_MODULUS_LEN];                    /* modulus */
		unsigned char publicExponent[MAX_RSA_MODULUS_LEN];     /* public exponent */
		unsigned char exponent[MAX_RSA_MODULUS_LEN];          /* private exponent */
		unsigned char prime[2][MAX_RSA_PRIME_LEN];               /* prime factors */
		unsigned char primeExponent[2][MAX_RSA_PRIME_LEN];   /* exponents for CRT */
		unsigned char coefficient[MAX_RSA_PRIME_LEN];          /* CRT coefficient */
	} R_RSA_PRIVATE_KEY;

	/* RSA prototype key.
	*/
	typedef struct {
		unsigned int bits;                           /* length in bits of modulus */
		int useFermat4;                        /* public exponent (1 = F4, 0 = 3) */
	} R_RSA_PROTO_KEY;


	int RSAPublicBlock (unsigned char *output, unsigned int *outputLen, const unsigned char *input,unsigned int inputLen,R_RSA_PUBLIC_KEY *publicKey) ;
	int RSAPrivateBlock (unsigned char *output, unsigned int *outputLen,unsigned char *input,unsigned int inputLen, R_RSA_PRIVATE_KEY *privateKey)  ;                     


#ifdef __cplusplus
}
#endif

#endif
