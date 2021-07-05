

#ifndef KASPERSKY_TEST_ScanUtility_HPP
#define KASPERSKY_TEST_ScanUtility_HPP

#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>


#define LISTENING_PORT 8081
#define IP_ADDRESS "127.0.0.1"
#define UTILITY_ERROR "Can't start utility"

class ScanUtility
{

private:
	const char *_directory;
	void _exit_failure();

public:
	ScanUtility(const char *directory);


	void sсan_directory();

};


#endif
