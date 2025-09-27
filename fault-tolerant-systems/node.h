#pragma once
#include"certificate_authority.h"
#include"message.h"
#include <iostream>
#include <unordered_set>
#include <deque>
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <sstream>

#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <spdlog/spdlog.h>

class node {
private:
	std::string name;
	EVP_PKEY* issued_key;
	bool is_faulty;
	std::vector<chain_message> messages;
	std::unordered_map<std::string, node*>* neighbours;
	int faulty_nodes;
	std::ofstream* file;

	static const std::string log_directory;
	static const std::chrono::system_clock::time_point now;

private:
	EVP_PKEY* register_node(std::string name);
	std::vector<unsigned char> sign_message(const std::vector<unsigned char>& message);
	bool verify_message(const std::vector<unsigned char>&, const std::vector<unsigned char>& signature, EVP_PKEY* public_key);
	std::ofstream* create_logging();

public:
	node(std::string name, bool is_faulty, int faulty_nodes = 0);
	node(std::string name, bool is_faulty, std::unordered_map<std::string, node*>* neighbours, int faulty_nodes = 0);
	bool get_is_node_faulty();
	void set_is_node_faulty(bool is_faulty);
	std::vector<chain_message> get_messages();
	EVP_PKEY* get_public_key();
	void send_messages();
	void receive_message(chain_message message);
	void export_node_to_file();

	static std::string get_current_timestamp();

	~node();
};