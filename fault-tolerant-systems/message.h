#pragma once
#include<vector>
#include<string>
#include<stack>
#include<deque>

struct chain_message {
	std::deque<std::vector<unsigned char>> signatures;
	std::vector<unsigned char> plain_message;
	std::stack<std::string> signers;
};