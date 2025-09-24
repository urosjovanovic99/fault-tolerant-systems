#include <iostream>
#include "node.h"
#include"message.h"
int main()
{
	std::string message = "TESTIRANJE PORUKE";
	std::vector<unsigned char> plain_message(message.begin(), message.end());
	std::unordered_map<std::string, node*>* neighbours = new std::unordered_map<std::string, node*>();

	node n1("A", false, neighbours, 0);
	node n2("B", false, neighbours, 0);
	node n3("C", false, neighbours, 0);
	node n4("D", false, neighbours, 0);
	node n5("E", false, neighbours, 0);
	neighbours->insert({ "A", &n1 });
	neighbours->insert({ "B", &n2 });
	neighbours->insert({ "C", &n3 });
	neighbours->insert({ "D", &n4 });
	neighbours->insert({ "E", &n5 });


	chain_message cm;
	cm.plain_message = plain_message;
	
	cm = n1.receive_message(cm);

	std::cout << "SIGNERS" << std::endl;
	while (!cm.signers.empty()) {
		std::cout << cm.signers.back() << std::endl;
	}

	chain_message n1_received_messages = n1.get_messages();
	chain_message n2_received_messages = n2.get_messages();
	chain_message n3_received_messages = n3.get_messages();
	chain_message n4_received_messages = n4.get_messages();
	chain_message n5_received_messages = n5.get_messages();


}
