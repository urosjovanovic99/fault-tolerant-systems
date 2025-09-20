#pragma once
#include <unordered_map>
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

static class certificate_authority {
private:
	static std::unordered_map<std::string, EVP_PKEY*> issued_keys;
	static const char* propq;
	static OSSL_LIB_CTX* libctx;
	static const unsigned int bits;

public:
	static EVP_PKEY* generate_keys(std::string node_name);
	static EVP_PKEY* get_issued_public_key(std::string node_name);
};