#pragma once
#include <unordered_map>
#include <iostream>
#include <openssl/rsa.h>

class certificate_authority {
private:
	std::unordered_map<std::string, EVP_PKEY*> issued_keys;

public:
	EVP_PKEY* generate_keys(std::string node_name);
	EVP_PKEY* get_issued_public_key(std::string node_name);
};