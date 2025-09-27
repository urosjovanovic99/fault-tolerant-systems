#include"certificate_authority.h"

std::unordered_map<std::string, EVP_PKEY*> certificate_authority::issued_keys;
const char* certificate_authority::propq = nullptr;
const unsigned int certificate_authority::bits = 4096;
OSSL_LIB_CTX* certificate_authority::libctx = nullptr;

EVP_PKEY* certificate_authority::generate_keys(std::string node_name) {
    EVP_PKEY* pkey = NULL;

    spdlog::debug("Generating RSA key for node {}, this may take some time...", node_name);
    pkey = EVP_PKEY_Q_keygen(libctx, propq, "RSA", (size_t)bits);

    if (pkey == NULL) {
        spdlog::error("EVP_PKEY_Q_keygen() failed");
        std::cout << "EVP_PKEY_Q_keygen() failed" << std::endl;
    }

    if (certificate_authority::issued_keys.find(node_name) != certificate_authority::issued_keys.end()) {
        certificate_authority::issued_keys.erase(node_name);
    }

    spdlog::debug("Key has been successfully generated for node {}", node_name);
    certificate_authority::issued_keys.insert({ node_name, pkey });

    return pkey;
}

EVP_PKEY* certificate_authority::get_issued_public_key(std::string node_name) {
    spdlog::debug("Retrieving public key for node{}", node_name);
    EVP_PKEY* keypair = nullptr;
    if (certificate_authority::issued_keys.at(node_name)) {
        keypair = certificate_authority::issued_keys[node_name];
    }
    
    if (keypair == nullptr) {
        spdlog::error("Node with name {} does not own public key", node_name);
        return nullptr;
    }

    BIO* mem = BIO_new(BIO_s_mem());
    if (!mem) {
        spdlog::critical("No enough memory while generating key for node {}", node_name);
        return nullptr;
    }

    if (!PEM_write_bio_PUBKEY(mem, keypair)) {
        spdlog::critical("Something went wrong while returning public key for node {}", node_name);
        BIO_free(mem);
        return nullptr;
    }

    EVP_PKEY* pubkey = PEM_read_bio_PUBKEY(mem, nullptr, nullptr, nullptr);
    BIO_free(mem);

    spdlog::debug("Retrieve public key for node {} successfully", node_name);
    return pubkey; // caller must EVP_PKEY_free(pubkey)
}

bool certificate_authority::export_issed_keys(std::string node_name, std::filesystem::path key_path) {
    EVP_PKEY* pkey = certificate_authority::issued_keys.at(node_name);
    if (!pkey) {
        spdlog::error("There is no issued keys for node {}", node_name);
        return false;
    }
    std::error_code ec;
    if (!std::filesystem::exists(key_path)) {
        std::filesystem::create_directories(key_path, ec);
        if (ec) {
            spdlog::error("Error while creating logging directory, {}", ec.message());
            return false;
        }
    }

    std::filesystem::path public_key_path = key_path / "public_key.pem";
    std::filesystem::path private_key_path = key_path / "private_key.pem";

    return certificate_authority::save_private_key(pkey, private_key_path.string()) &&
        certificate_authority::save_public_key(pkey, public_key_path.string());
}

bool certificate_authority::save_private_key(EVP_PKEY* pkey, const std::string& filename) {
    BIO* bio = BIO_new_file(filename.c_str(), "w");
    if (!bio) {
        spdlog::error("Failed to open file for writing private key");
        return false;
    }

    if (!PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        spdlog::error("PEM_write_PrivateKey failed");
        BIO_free(bio);
        return false;
    }

    BIO_free(bio);
    return true;
}

bool certificate_authority::save_public_key(EVP_PKEY* pkey, const std::string& filename) {
    BIO* bio = BIO_new_file(filename.c_str(), "w");
    if (!bio) {
        spdlog::error("Failed to open file for writing public key");
        return false;
    }

    if (!PEM_write_bio_PUBKEY(bio, pkey)) {
        spdlog::error("PEM_write_PUBKEY failed");
        BIO_free(bio);
        return false;
    }

    BIO_free(bio);
    return true;
}