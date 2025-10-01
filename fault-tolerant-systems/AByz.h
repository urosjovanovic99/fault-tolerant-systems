#pragma once
#include"node.h"
#include <string>
#include <unordered_map>
#include <vector>
#include <cstdlib>

class AByz {
private:
	int N;
	int m;
	bool is_source_faulty;
	std::string message;
	std::unordered_map<std::string, node*>* nodes;
	node* source_node;
	std::ofstream* file;
	static const std::string log_directory;

public:
	static std::string default_message;

private:
	void create_graph();
	node* pick_starting_node();
	std::ofstream* create_logging();

public:
	AByz(int N, int m, bool is_source_faulty);
	void run_algorithm();
	void export_result_to_file();

	~AByz();
};