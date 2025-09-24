#include <iostream>
#include "node.h"

int main()
{
	std::string message = "TESTIRANJE PORUKE";
	std::vector<unsigned char> plain_message(message.begin(), message.end());

	node n1("A", false);
	node n2("B", false);
	node n3("C", false);
	node n4("D", false);
	node n5("E", false);

	chain_message chain_message;
	chain_message.plain_message = plain_message;
	
	chain_message = n1.receive_message(chain_message);
	chain_message = n2.receive_message(chain_message);
	chain_message = n3.receive_message(chain_message);
	chain_message = n4.receive_message(chain_message);
	chain_message = n5.receive_message(chain_message);

	std::cout << "SIGNERS" << std::endl;
	while (!chain_message.signers.empty()) {
		std::cout << chain_message.signers.back() << std::endl;
		auto sig = chain_message.signatures.back();
		std::cout << sig.data() << std::endl;
		chain_message.signers.pop_back();
	}
}
