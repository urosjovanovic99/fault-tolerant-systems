#include"node.h"

node::node(std::string name, bool is_faulty) {
	this->name = name;
	this->is_faulty = is_faulty;
	this->neighbours = nullptr;
	this->issued_key = certificate_authority::generate_keys(name);
}

EVP_PKEY* node::register_node(std::string name) {
	return certificate_authority::generate_keys(this->name);
}

bool node::get_is_node_faulty() {
	return this->is_faulty;
}

void node::set_is_node_faulty(bool is_faulty) {
	this->is_faulty = is_faulty;
}

std::vector<unsigned char*> node::get_messages()
{
	return this->messages;
}

EVP_PKEY* node::get_public_key() {
	return certificate_authority::get_issued_public_key(this->name);
}

std::vector<unsigned char> node::sign_message(const std::string& message) {
    std::vector<unsigned char> signature; // empty by default

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "EVP_MD_CTX_new() failed\n";
        return signature;
    }

    if (!this->issued_key) {
        std::cerr << "Do not own issued key\n";
        EVP_MD_CTX_free(ctx);
        return signature;
    }

    // Init signing with SHA-256 and private key
    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, this->issued_key) != 1) {
        std::cerr << "EVP_DigestSignInit() failed\n";
        EVP_MD_CTX_free(ctx);
        return signature;
    }

    // Feed message
    if (EVP_DigestSignUpdate(ctx, message.data(), message.size()) != 1) {
        std::cerr << "Message hashing failed\n";
        EVP_MD_CTX_free(ctx);
        return signature;
    }

    // First call to get required signature length
    size_t siglen = 0;
    if (EVP_DigestSignFinal(ctx, nullptr, &siglen) != 1) {
        std::cerr << "Getting buffer size failed\n";
        EVP_MD_CTX_free(ctx);
        return signature;
    }

    // Allocate vector to the right size
    signature.resize(siglen);

    // Second call: actually get the signature
    if (EVP_DigestSignFinal(ctx, signature.data(), &siglen) != 1) {
        std::cerr << "Signing message failed\n";
        EVP_MD_CTX_free(ctx);
        signature.clear();
        return signature;
    }

    // Resize in case siglen < allocated size
    signature.resize(siglen);

    EVP_MD_CTX_free(ctx);
    return signature;
}

bool node::verify_message(const std::string& message,
    const std::vector<unsigned char>& signature) {

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "EVP_MD_CTX_new() failed\n";
        return false;
    }

    // Init verify with SHA-256 and public key
    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, this->issued_key) != 1) {
        std::cerr << "EVP_DigestVerifyInit() failed\n";
        EVP_MD_CTX_free(ctx);
        return false;
    }

    // Feed original message
    if (EVP_DigestVerifyUpdate(ctx, message.data(), message.size()) != 1) {
        std::cerr << "Message hashing failed\n";
        EVP_MD_CTX_free(ctx);
        return false;
    }

    // Perform verification
    int rc = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
    EVP_MD_CTX_free(ctx);

    if (rc == 1) {
        return true;
    }
    else if (rc == 0) {
        std::cerr << "Signature invalid\n";
        return false;
    }
    else {
        std::cerr << "Verification error\n";
        return false;
    }
}
