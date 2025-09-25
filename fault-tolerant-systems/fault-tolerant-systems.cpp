#include <iostream>
#include "node.h"
#include"message.h"
int main()
{
	std::unordered_map<std::string, node*>* neighbours = new std::unordered_map<std::string, node*>();

	node n1("A", false, neighbours, 2);
	node n2("B", false, neighbours, 2);
	node n3("C", false, neighbours, 2);
	node n4("D", false, neighbours, 2);
	node n5("E", false, neighbours, 2);

	neighbours->insert({ "A", &n1 });
	neighbours->insert({ "B", &n2 });
	neighbours->insert({ "C", &n3 });
	neighbours->insert({ "D", &n4 });
	neighbours->insert({ "E", &n5 });


	chain_message cm("TESTIRANJE PORUKE");
	
	n1.receive_message(cm);
	n1.send_messages();

	for (int round = 0; round < 2; round++) {
		for (auto node = neighbours->begin(); node != neighbours->end(); ++node) {
			if (node->second != &n1) {
				node->second->send_messages();
			}
		}
	}

	std::vector<chain_message> n1_received_messages = n1.get_messages();
	std::vector<chain_message> n2_received_messages = n2.get_messages();
	std::vector<chain_message> n3_received_messages = n3.get_messages();
	std::vector<chain_message> n4_received_messages = n4.get_messages();
	std::vector<chain_message> n5_received_messages = n5.get_messages();


}
