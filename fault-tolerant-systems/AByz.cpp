#include"AByz.h"
#include"string.h"

std::string AByz::default_message = "DEFAULT MESSAGE";

AByz::AByz(int N, int m, bool is_source_faulty) {
	this->N = N;
	this->m = m;
	this->is_source_faulty = is_source_faulty;
	this->message = this->generate_random_message();
	this->create_graph();
	this->source_node = this->pick_starting_node();
}

std::string AByz::generate_random_message() {
	std::vector<unsigned char> message;
	for (int i = 0; i < 10; i++) {
		int ascii_index = (rand() % 26) + 65;
		unsigned char letter = static_cast<char>(ascii_index);
		message.push_back(letter);
	}
	std::string random_message(message.begin(), message.end());
	return random_message;
}

void AByz::create_graph() {
	this->nodes = new std::unordered_map<std::string, node*>(this->N);
	
	int number_of_faulty = 0;
	for (int i = 0; i < N; i++) {
		bool is_faulty = number_of_faulty++ < this->m;
		std::string name(1, static_cast<char>(('A' + i)));
		node* n = new node(name, is_faulty, this->nodes, this->m);
		this->nodes->insert({ name, n });
	}
}

node* AByz::pick_starting_node() {
	std::string node_name(1, this->is_source_faulty ? static_cast<char>('A' + (rand() % m)) : static_cast<char>('A' + (rand() % (N - m) + m)));
	return this->nodes->at(node_name);
}

void AByz::run_algorithm() {
	chain_message starting_message(this->message);

	this->source_node->receive_message(starting_message);
	this->source_node->send_messages();

	for (int round = 0; round < this->m; round++) {
		for (auto node = nodes->begin(); node != nodes->end(); ++node) {
			if (node->second != this->source_node) {
				node->second->send_messages();
			}
		}
	}

	for (auto node = nodes->begin(); node != nodes->end(); ++node) {
		node->second->export_node_to_file();
	}
}