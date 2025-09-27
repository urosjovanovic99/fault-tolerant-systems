#pragma once
#include <unordered_map>
#include <iostream>
#include <filesystem>

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <spdlog/spdlog.h>

class certificate_authority {
private:
	static std::unordered_map<std::string, EVP_PKEY*> issued_keys;
	static const unsigned int bits;

	static bool save_private_key(EVP_PKEY* pkey, const std::string& filename);
	static bool save_public_key(EVP_PKEY* pkey, const std::string& filename);

public:
	static const char* propq;
	static OSSL_LIB_CTX* libctx;

	static EVP_PKEY* generate_keys(std::string node_name);
	static EVP_PKEY* get_issued_public_key(std::string node_name);
	static bool export_issed_keys(std::string node_name, std::filesystem::path);
};