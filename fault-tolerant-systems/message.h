#pragma once
#include<vector>
#include<string>
#include<deque>

struct chain_message {
	std::deque<std::vector<unsigned char>> signatures;
	std::vector<unsigned char> plain_message;
	std::deque<std::string> signers;

	chain_message(std::string plain_message) {
		this->plain_message = std::vector<unsigned char>(plain_message.begin(), plain_message.end());
	}
};