#include"node.h"

node::node(std::string name, bool is_faulty, int faulty_nodes) {
	this->name = name;
	this->is_faulty = is_faulty;
	this->neighbours = nullptr;
    this->faulty_nodes = faulty_nodes;
	this->issued_key = certificate_authority::generate_keys(name);
}

node::node(std::string name, bool is_faulty, std::unordered_map<std::string, node*>* neighbours, int faulty_nodes) {
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

std::vector<chain_message> node::get_messages()
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

// verify all signatures in message and if verification is success, store it locally with other messages
// if already signed by this node discard it
void node::receive_message(chain_message received_message) {
    if (std::find(received_message.signers.begin(), received_message.signers.end(), this->name) != received_message.signers.end()) {
        return; // already signed it
    }

    std::deque<std::string> signers(received_message.signers);
    std::deque<std::vector<unsigned char>> signatures(received_message.signatures);

    bool is_verified = true;

    while (!signers.empty() && !signatures.empty()) {
        std::string signer = signers.back();
        std::vector<unsigned char> signature = signatures.back();
        std::vector<unsigned char> message = signers.size() == 1 ? received_message.plain_message : signatures.at(signatures.size() - 2);
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
        this->messages.push_back(received_message);
    }
}

// go through all received messages and if message is not signed by this node, sign it and forward it to other nodes
void node::send_messages() {
    for (auto it = this->messages.begin(); it != this->messages.end(); ++it) {
        if (it->signers.size() < (this->faulty_nodes + 1) &&
            (std::find(it->signers.begin(), it->signers.end(), this->name) == it->signers.end() || it->signers.size() == 0)) {
            // if this is first signature sign plain message, otherwise sign other signatures
            std::vector<unsigned char> signed_message = this->sign_message(it->signatures.size() == 0 ? it->plain_message : it->signatures.back());

            // create message for forwarding
            chain_message forwarding_message = *it;
            forwarding_message.signers.push_back(this->name);
            forwarding_message.signatures.push_back(signed_message);

            // add signature on old message as well
            it->signers.push_back(this->name);
            it->signatures.push_back(signed_message);

            for (auto node = this->neighbours->begin(); node != this->neighbours->end(); ++node) {
                if (std::find(forwarding_message.signers.begin(), forwarding_message.signers.end(), node->first) == forwarding_message.signers.end()) {
                    node->second->receive_message(forwarding_message);
                }
            }
        }
    }
}