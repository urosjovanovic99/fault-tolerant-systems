#pragma once
class node {
private:
	node* neighbours;
	bool is_faulty;
	long message;
	long private_key;
	long public_key;

public:
	bool get_is_node_faulty();
	long get_message();
	void get_public_key();
	void set_is_node_faulty(bool is_faulty);
	void set_message(long message);
	void send_message();
	void receive_message(long message);
	void export_message_to_file();
	void encrypt_message();
	void decrypt_message();
};