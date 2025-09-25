#pragma once
#include"node.h"
#include<string>
#include<unordered_map>
#include<vector>
#include <cstdlib>

class AByz {
private:
	int N;
	int m;
	bool is_source_faulty;
	std::string message;
	std::unordered_map<std::string, node*>* nodes;
	node* source_node;
public:
	static std::string default_message;

private:
	std::string generate_random_message();
	void create_graph();
	node* pick_starting_node();

public:
	AByz(int N, int m, bool is_source_faulty);
	void run_algorithm();
	// void export_result_to_file();
};