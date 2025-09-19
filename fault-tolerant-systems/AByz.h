#pragma once
#include"node.h"

class AByz {
private:
	int N;
	int m;
	bool is_source_faulty;
	unsigned char* message;
	node** nodes;
public:
	const static unsigned char* const default_message;
	void init();
	unsigned char* generate_random_message();
	void export_result_to_file();
};