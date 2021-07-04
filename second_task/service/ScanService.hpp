
#ifndef KASPERSKY_TEST_ScanService_HPP
#define KASPERSKY_TEST_ScanService_HPP

#include <iostream>
#include <fstream>
#include <thread>
#include <mutex>
#include <list>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <dirent.h>
#include <unistd.h>
#include <signal.h>

#define LISTENING_PORT 8081
#define IP_ADDRESS "127.0.0.1"
#define UNIX_SUSPICIOUS "rm -rf ~/Documents"
#define MAC_SUSPICIOUS "system(\"launchctl load /Library/LaunchAgents/com.malware.agent\")"
#define JS_SUSPICIOUS "<script>evil_script()</script>"
#define JS_EXTENSION "js"

// static int		_socket_fd = 0;

class ScanService
{
private:

	size_t _errors;
	size_t _js_suspicious;
	size_t _mac_suspicious;
	size_t _unix_suspicious;
	static int		_socket_fd;
	void    _scan_file(std::string file_name, std::mutex &unix_mutex, std::mutex &mac_mutex, std::mutex &js_mutex,
					   std::mutex &error_mutex);
	void	_print_report(size_t number_of_files);
	void    _write_data(std::mutex &mutex, size_t &data);
	void    _put_time_in_str(std::string &exection_time_str, clock_t &exection_time);
	void 	_sсan_directory(const char *directory);
	void	_read_directory(int client_fd);
	void	_exit_failure();
	static void	_signal_listener(int signal);

public:

	ScanService();

	[[noreturn]] void start_service();

};


#endif //KASPERSKY_TEST_ScanService_HPP
