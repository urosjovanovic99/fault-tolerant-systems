#include"node.h"

node::node(std::string name, bool is_faulty, unsigned int faulty_nodes) {
	this->name = name;
	this->is_faulty = is_faulty;
	this->neighbours = nullptr;
    this->faulty_nodes = faulty_nodes;
	this->issued_key = certificate_authority::generate_keys(name);
}

node::node(std::string name, bool is_faulty, std::unordered_map<std::string, node*>* neighbours, unsigned int faulty_nodes) {
    this->name = name;
    this->is_faulty = is_faulty;
    this->neighbours = neighbours;
    this->faulty_nodes = faulty_nodes;
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

chain_message node::get_messages()
{
	return this->messages;
}

EVP_PKEY* node::get_public_key() {
	return certificate_authority::get_issued_public_key(this->name);
}

std::vector<unsigned char> node::sign_message(const std::vector<unsigned char>& message) {
    std::vector<unsigned char> signature; // empty by default

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cout << "EVP_MD_CTX_new() failed" << std::endl;
        return signature;
    }

    if (!this->issued_key) {
        std::cout << "Do not own issued key\n";
        EVP_MD_CTX_free(ctx);
        return signature;
    }

    // Init signing with SHA-256 and private key
    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, this->issued_key) != 1) {
        std::cout << "EVP_DigestSignInit() failed\n";
        EVP_MD_CTX_free(ctx);
        return signature;
    }

    // Feed message
    if (EVP_DigestSignUpdate(ctx, message.data(), message.size()) != 1) {
        std::cout << "Message hashing failed\n";
        EVP_MD_CTX_free(ctx);
        return signature;
    }

    // First call to get required signature length
    size_t siglen = 0;
    if (EVP_DigestSignFinal(ctx, nullptr, &siglen) != 1) {
        std::cout << "Getting buffer size failed\n";
        EVP_MD_CTX_free(ctx);
        return signature;
    }

    // Allocate vector to the right size
    signature.resize(siglen);

    // Second call: actually get the signature
    if (EVP_DigestSignFinal(ctx, signature.data(), &siglen) != 1) {
        std::cout << "Signing message failed\n";
        EVP_MD_CTX_free(ctx);
        signature.clear();
        return signature;
    }

    // Resize in case siglen < allocated size
    signature.resize(siglen);

    EVP_MD_CTX_free(ctx);
    return signature;
}

bool node::verify_message(const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature, EVP_PKEY *public_key) {

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cout << "EVP_MD_CTX_new() failed\n";
        return false;
    }

    // Init verify with SHA-256 and public key
    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, public_key) != 1) {
        std::cout << "EVP_DigestVerifyInit() failed\n";
        EVP_MD_CTX_free(ctx);
        return false;
    }

    // Feed original message
    if (EVP_DigestVerifyUpdate(ctx, message.data(), message.size()) != 1) {
        std::cout << "Message hashing failed\n";
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
        std::cout << "Signature invalid\n";
        return false;
    }
    else {
        std::cout << "Verification error\n";
        return false;
    }
}

// receive message and check chain signatures, if it is valid store in map
chain_message node::receive_message(chain_message chain_message) {
    std::deque<std::string> signers(chain_message.signers);
    std::deque<std::vector<unsigned char>> signatures(chain_message.signatures);

    bool is_verified = true;

    while (!signers.empty() && !signatures.empty()) {
        std::string signer = signers.back();
        std::vector<unsigned char> signature = signatures.back();
        std::vector<unsigned char> message = signers.size() == 1 ? chain_message.plain_message : signatures.at(signatures.size() - 2);
        auto public_key = certificate_authority::get_issued_public_key(signer);
        bool is_signature_valid = this->verify_message(message, signature, public_key);
        if (!is_signature_valid) {
            is_verified = false;
            break;
        }
        signers.pop_back();
        signatures.pop_back();
    }

    if (is_verified) {
        this->messages = chain_message;
    }

    if (is_verified && chain_message.signers.size() < this->faulty_nodes) {
        this->send_message(chain_message);
    }

    return chain_message;
}

// signe and send last received message to all other nodes that didn't signed it
void node::send_message(chain_message chain_message) {
    std::vector<unsigned char> signature;
    if (chain_message.signers.size() == 0) {
        signature = this->sign_message(chain_message.plain_message);
    }
    else {
        signature = this->sign_message(chain_message.signatures.back());
    }
    chain_message.signatures.push_back(signature);
    chain_message.signers.push_back(this->name);

    for (auto it = this->neighbours->begin(); it != this->neighbours->end(); ++it) {
        if (it->first != this->name && std::find(chain_message.signers.begin(), chain_message.signers.end(), it->first) == chain_message.signers.end()) {
            it->second->receive_message(chain_message);
        }
    }
}