

#include "ScanUtility.hpp"


ScanUtility::ScanUtility(const char *directory) : _directory(directory) {}


void ScanUtility::_exit_failure()
{
    std::cout << UTILITY_ERROR << std::endl;
    exit(EXIT_FAILURE);
}

void ScanUtility::sсan_directory()
{
    struct sockaddr_in addr;
    char buf[1024];

    bzero(buf, sizeof buf);
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0)
        _exit_failure();
    addr.sin_family = AF_INET;
    addr.sin_port = htons(LISTENING_PORT);
    addr.sin_addr.s_addr = inet_addr(IP_ADDRESS);
    if (connect(socket_fd, (const struct sockaddr*) &addr, sizeof addr) < 0)
        _exit_failure();
    if (send(socket_fd, _directory, std::strlen(_directory), 0) < 0 ||
    recv(socket_fd, buf, sizeof buf, 0) < 0)
        return;
    std::cout << buf << std::endl;
}