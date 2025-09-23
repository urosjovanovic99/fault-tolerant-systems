#include"certificate_authority.h"

std::unordered_map<std::string, EVP_PKEY*> certificate_authority::issued_keys;
const char* certificate_authority::propq = NULL;
const unsigned int certificate_authority::bits = 4096;
OSSL_LIB_CTX* certificate_authority::libctx = nullptr;

EVP_PKEY* certificate_authority::generate_keys(std::string node_name) {
    EVP_PKEY* pkey = NULL;

    std::cout << "Generating RSA key, this may take some time..." << std::endl;
    pkey = EVP_PKEY_Q_keygen(libctx, propq, "RSA", (size_t)bits);

    if (pkey == NULL)
        std::cout << "EVP_PKEY_Q_keygen() failed" << std::endl;

    if (certificate_authority::issued_keys.find(node_name) != certificate_authority::issued_keys.end()) {
        certificate_authority::issued_keys.erase(node_name);
    }

    certificate_authority::issued_keys.insert({ node_name, pkey });

    return pkey;
}

EVP_PKEY* certificate_authority::get_issued_public_key(std::string node_name) {
    EVP_PKEY* keypair = nullptr;
    if (certificate_authority::issued_keys.at(node_name)) {
        keypair = certificate_authority::issued_keys[node_name];
    }
    
    if (keypair == nullptr) {
        return nullptr;
    }

    // Create a new public-only EVP_PKEY by serializing & deserializing
    BIO* mem = BIO_new(BIO_s_mem());
    if (!mem) return nullptr;

    // Write only the public key portion to memory (SubjectPublicKeyInfo format)
    if (!PEM_write_bio_PUBKEY(mem, keypair)) {
        BIO_free(mem);
        return nullptr;
    }

    // Read it back as a new EVP_PKEY that contains only the public part
    EVP_PKEY* pubkey = PEM_read_bio_PUBKEY(mem, nullptr, nullptr, nullptr);
    BIO_free(mem);

    return pubkey; // caller must EVP_PKEY_free(pubkey)
}
