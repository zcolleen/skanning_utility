
#include "SkanUtility.hpp"

int main(int argc, char **argv)
{

	if (argc != 2)
		std::cout << "Wrong number of arguments" << std::endl;
	else {
		SkanUtility skanUtility(argv[1]);

		skanUtility.sсan_directory();
	}
	return 0;
}
