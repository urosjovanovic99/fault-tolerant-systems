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

	std::string to_string() {
		std::string message = "";
		for (std::string signer : this->signers) {
			message += signer + ".";
		}
		message += "(" + std::string(this->plain_message.begin(), this->plain_message.end()) + ")";
		return message;
	}

	static std::string generate_random_message() {
		std::vector<unsigned char> message;
		for (int i = 0; i < 10; i++) {
			int ascii_index = (rand() % 26) + 65;
			unsigned char letter = static_cast<char>(ascii_index);
			message.push_back(letter);
		}
		std::string random_message(message.begin(), message.end());
		return random_message;
	}
};