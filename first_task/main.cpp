
#include "ScanUtility.hpp"


int main(int argc, char **argv)
{
	if (argc != 2)
		std::cout << "Wrong number of arguments" << std::endl;
	else {
		ScanUtility scanUtility(argv[1]);

		scanUtility.sсan_directory();
	}
	return 0;
}
