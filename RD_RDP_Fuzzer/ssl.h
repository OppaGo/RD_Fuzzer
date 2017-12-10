#ifndef _SSL_H
#define _SSL_H

#include <openssl\rc4.h>
#include <openssl\md5.h>
#include <openssl\sha.h>
#include <openssl\bn.h>
#include <openssl\x509v3.h>

#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")
#include "rdesktop.h"

#if defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER >= 0x0090800f)
#define D2I_X509_CONST const
#else
#define D2I_X509_CONST
#endif

#define SSL_RC4 RC4_KEY
#define SSL_SHA1 SHA_CTX
#define SSL_MD5 MD5_CTX
#define SSL_CERT X509
#define SSL_RKEY RSA

namespace RD_FUZZER
{
	class RDP_SSL {
	private:
		void reverse(uint8 * p, int len);

	public:
		void ssl_sha1_init(SSL_SHA1 * sha1);
		void ssl_sha1_update(SSL_SHA1 * sha1, uint8 * data, uint32 len);
		void ssl_sha1_final(SSL_SHA1 * sha1, uint8 * out_data);
		void ssl_md5_init(SSL_MD5 * md5);
		void ssl_md5_update(SSL_MD5 * md5, uint8 * data, uint32 len);
		void ssl_md5_final(SSL_MD5 * md5, uint8 * out_data);
		void ssl_rc4_set_key(SSL_RC4 * rc4, uint8 * key, uint32 len);
		void ssl_rc4_crypt(SSL_RC4 * rc4, uint8 * in_data, uint8 * out_data, uint32 len);
		void ssl_rsa_encrypt(uint8 * out, uint8 * in, int len, uint32 modulus_size, uint8 * modulus,
			uint8 * exponent);
		SSL_CERT *ssl_cert_read(uint8 * data, uint32 len);
		void ssl_cert_free(SSL_CERT * cert);
		SSL_RKEY *ssl_cert_to_rkey(SSL_CERT * cert, uint32 * key_len);
		RD_BOOL ssl_certs_ok(SSL_CERT * server_cert, SSL_CERT * cacert);
		int ssl_cert_print_fp(FILE * fp, SSL_CERT * cert);
		void ssl_rkey_free(SSL_RKEY * rkey);
		int ssl_rkey_get_exp_mod(SSL_RKEY * rkey, uint8 * exponent, uint32 max_exp_len, uint8 * modulus,
			uint32 max_mod_len);
		RD_BOOL ssl_sig_ok(uint8 * exponent, uint32 exp_len, uint8 * modulus, uint32 mod_len,
			uint8 * signature, uint32 sig_len);
	};
}

#endif
