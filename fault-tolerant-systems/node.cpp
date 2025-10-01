#include "node.h"
#include "AByz.h"
#include <nlohmann/json.hpp>

const std::string node::log_directory = "logs";
const std::chrono::system_clock::time_point node::now = std::chrono::system_clock::now();
node* node::source_node = nullptr;

void node::set_source_node(node* source) {
    node::source_node = source;
}

std::string node::get_current_timestamp() {
    std::time_t t = std::chrono::system_clock::to_time_t(now);

    std::tm tm;
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    // Use '-' for separators in the time portion so the string is valid on Windows
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H-%M-%SZ"); // note: %H-%M-%S (hyphens) instead of %H:%M:%S
    return oss.str();
}

node::node(std::string name, bool is_faulty, int faulty_nodes) {
	this->name = name;
	this->is_faulty = is_faulty;
	this->neighbours = nullptr;
    this->faulty_nodes = faulty_nodes;
	this->issued_key = certificate_authority::generate_keys(name);
    this->file = this->create_logging();
}

node::node(std::string name, bool is_faulty, std::unordered_map<std::string, node*>* neighbours, int faulty_nodes) {
    this->name = name;
    this->is_faulty = is_faulty;
    this->neighbours = neighbours;
    this->faulty_nodes = faulty_nodes;
    this->issued_key = certificate_authority::generate_keys(name);
    this->file = this->create_logging();
}

std::ofstream* node::create_logging() {
    std::string timestamp = node::get_current_timestamp();
    std::filesystem::path path = std::filesystem::path(log_directory) / timestamp / this->name / (this->name + "_NODE.json");
    std::error_code ec;
    if (!std::filesystem::exists(path)) {
        std::filesystem::create_directories(path.parent_path(), ec);
        if (ec) {
            spdlog::error("Error while creating logging directory, {}", ec.message());
            return nullptr;
        }
    }
    return new std::ofstream(path);
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

std::string node::get_node_name() {
    return this->name;
}

std::vector<chain_message> node::get_messages()
{
	return this->messages;
}

EVP_PKEY* node::get_public_key() {
	return certificate_authority::get_issued_public_key(this->name);
}

std::vector<unsigned char> node::sign_message(const std::vector<unsigned char>& message) {
    spdlog::info("{} node signing message", this->name);
    std::vector<unsigned char> signature;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        spdlog::error("EVP_MD_CTX_new() failed while creating context");
        return signature;
    }

    if (!this->issued_key) {
        spdlog::error("Node {} do not has issued key", this->name);
        spdlog::info("Free used memory");
        EVP_MD_CTX_free(ctx);
        return signature;
    }

    // Init signing with SHA-256 and private key
    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, this->issued_key) != 1) {
        spdlog::error("EVP_DigestSignInit() failed");
        spdlog::info("Free used memory");
        EVP_MD_CTX_free(ctx);
        return signature;
    }

    // Feed message
    if (EVP_DigestSignUpdate(ctx, message.data(), message.size()) != 1) {
        spdlog::error("Message hashing failed");
        spdlog::info("Free used memory");
        EVP_MD_CTX_free(ctx);
        return signature;
    }

    // First call to get required signature length
    size_t siglen = 0;
    if (EVP_DigestSignFinal(ctx, nullptr, &siglen) != 1) {
        spdlog::error("Getting buffer size failed");
        spdlog::info("Free used memory");
        EVP_MD_CTX_free(ctx);
        return signature;
    }

    // Allocate vector to the right size
    signature.resize(siglen);

    // Second call: actually get the signature
    if (EVP_DigestSignFinal(ctx, signature.data(), &siglen) != 1) {
        spdlog::critical("Signing message failed");
        spdlog::info("Free used memory");
        EVP_MD_CTX_free(ctx);
        signature.clear();
        return signature;
    }

    // Resize in case siglen < allocated size
    signature.resize(siglen);

    EVP_MD_CTX_free(ctx);

    spdlog::info("Node {} successfully signed message", this->name);
    return signature;
}

bool node::verify_message(const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature, EVP_PKEY *public_key) {

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        spdlog::error("EVP_MD_CTX_new() failed while creating context for message verify");
        return false;
    }

    // Init verify with SHA-256 and public key
    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, public_key) != 1) {
        spdlog::error("EVP_DigestVerifyInit() failed while creating context for message verify");
        spdlog::info("Free used memory");
        EVP_MD_CTX_free(ctx);
        return false;
    }

    // Feed original message
    if (EVP_DigestVerifyUpdate(ctx, message.data(), message.size()) != 1) {
        spdlog::critical("Message hashing failed");
        spdlog::info("Free used memory");
        EVP_MD_CTX_free(ctx);
        return false;
    }

    // Perform verification
    int rc = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
    EVP_MD_CTX_free(ctx);

    if (rc == 1) {
        spdlog::debug("Message verification successfull");
        return true;
    }
    else if (rc == 0) {
        spdlog::critical("Signature invalid");
        return false;
    }
    else {
        spdlog::error("Verification error");
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
    else {
        // push back default message
        chain_message default_message(AByz::default_message);
        this->messages.push_back(default_message);
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

            // if node is faulty, simulate message tweaking
            if (this->is_faulty && (rand() % 10) < 5) {
                std::string tweaked_message = chain_message::generate_random_message();
                forwarding_message.plain_message = std::vector<unsigned char>(tweaked_message.begin(), tweaked_message.end());
            }

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

void node::choose_message() {
    std::string source_message;
    for (auto it = this->messages.begin(); it != this->messages.end(); ++it) {
        std::string current_message(it->plain_message.begin(), it->plain_message.end());
        if (current_message != AByz::default_message && it->signers.front() == node::source_node->name) {
            if (source_message == current_message || source_message.empty()) {
                source_message = current_message;
            }
            else {
                this->message = new chain_message(AByz::default_message);
                return;
            }
        }
    }
    if (source_message.empty()) {
        this->message = new chain_message(AByz::default_message);
    }
    else {
        this->message = new chain_message(source_message);
    }
    return;
}

void node::export_node_to_file() {
    if (this->file && this->file->is_open()) {
        nlohmann::json node;
        node["name"] = this->name;
        node["is_faulty"] = this->is_faulty;
        node["choosen_message"] = std::string(this->message->plain_message.begin(), this->message->plain_message.end());
        std::vector<std::string> messages;
        for (auto it = this->messages.begin(); it != this->messages.end(); ++it) {
            messages.push_back(it->to_string());
        }
        node["messages"] = messages;
        *this->file << node.dump(4);
        std::string timestamp = node::get_current_timestamp();
        std::filesystem::path path = std::filesystem::path(log_directory) / timestamp / this->name;
        if (!certificate_authority::export_issed_keys(this->name, path)) {
            spdlog::error("Error exporting private and public keys to a file");
        }
    }
    else {
        spdlog::error("Logging file does not exists or it is corrupted");
    }
}

node::~node() {
    if (this->file != nullptr) {
        this->file->close();
        this->file = nullptr;
    }

    if (this->issued_key != nullptr) {
        EVP_PKEY_free(this->issued_key);
        this->issued_key = nullptr;
    }
}