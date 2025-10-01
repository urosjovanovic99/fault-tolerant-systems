#include"AByz.h"
#include"string.h"
#include <nlohmann/json.hpp>

std::string AByz::default_message = "DEFAULT MESSAGE";
const std::string AByz::log_directory = "logs";

AByz::AByz(int N, int m, bool is_source_faulty) {
	this->N = N;
	this->m = m;
	this->is_source_faulty = is_source_faulty;
	this->message = chain_message::generate_random_message();
	this->create_graph();
	this->source_node = this->pick_starting_node();
	this->file = this->create_logging();
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

	this->export_result_to_file();
}

std::ofstream* AByz::create_logging() {
	std::string timestamp = node::get_current_timestamp();
	std::filesystem::path path = std::filesystem::path(log_directory) / timestamp / "AByz" / "AByz.json";
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

void AByz::export_result_to_file() {
	if (this->file && this->file->is_open()) {
		nlohmann::json abyz;
		abyz["N"] = this->N;
		abyz["m"] = this->m;
		abyz["is_source_faulty"] = this->is_source_faulty;
		abyz["source_node"] = this->source_node->get_node_name();
		abyz["default_message"] = AByz::default_message;
		abyz["message"] = this->message;
		nlohmann::json nodes = nlohmann::json::array();
		for (auto it = this->nodes->begin(); it != this->nodes->end(); ++it) {
			nodes.push_back({
				{ "name", it->second->get_node_name() },
				{ "is_node_faulty", it->second->get_is_node_faulty() }
			});
		}
		abyz["nodes"] = nodes;
		*this->file << abyz.dump(4);
		std::string timestamp = node::get_current_timestamp();
	}
	else {
		spdlog::error("Logging file does not exists or it is corrupted");
	}
}

AByz::~AByz() {
	if (this->file && this->file->is_open()) {
		this->file->close();
		this->file = nullptr;
	}
}