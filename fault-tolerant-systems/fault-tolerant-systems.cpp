#include <iostream>
#include"AByz.h"

int main(int argc, char* argv[])
{
	int N = std::atoi(argv[1]);
	int m = std::atoi(argv[2]);
	bool is_source_faulty = std::atoi(argv[3]) == 1;
	AByz algorithm(N, m, is_source_faulty);
	algorithm.run_algorithm();
}
