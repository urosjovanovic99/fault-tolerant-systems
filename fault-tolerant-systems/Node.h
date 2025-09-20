#pragma once
#include <iostream>
#include <unordered_set>
#include <openssl/rsa.h>

class node {
private:
	std::string name;
	EVP_PKEY* issued_key;
	bool is_faulty;
	std::unordered_set<unsigned char> message;
	node* neighbours;

public:
	node(std::string name, bool is_faulty);
	bool get_is_node_faulty();
	void set_is_node_faulty(bool is_faulty);
	std::unordered_set<unsigned char> get_messages();
	EVP_PKEY* get_public_key();
	void send_message(std::string name);
	void receive_message(unsigned char message);
	void export_messages_to_file();
	void encrypt_message();
	void decrypt_message();
};