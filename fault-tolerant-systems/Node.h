#pragma once
#include"certificate_authority.h"
#include <iostream>
#include <unordered_set>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/bio.h>

class node {
private:
	std::string name;
	EVP_PKEY* issued_key;
	bool is_faulty;
	std::vector<unsigned char*> messages;
	node* neighbours;

	EVP_PKEY* register_node(std::string name);
public:
	std::vector<unsigned char> sign_message(const std::string& message);
	bool verify_message(const std::string& message,
		const std::vector<unsigned char>& signature);

public:
	node(std::string name, bool is_faulty);
	bool get_is_node_faulty();
	void set_is_node_faulty(bool is_faulty);
	std::vector<unsigned char*> get_messages();
	EVP_PKEY* get_public_key();
	//void send_message(std::string name);
	//void receive_message(unsigned char message);
	//void export_messages_to_file();
};