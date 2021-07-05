
#ifndef KASPERSKY_TEST_ScanService_HPP
#define KASPERSKY_TEST_ScanService_HPP

#include <iostream>
#include <fstream>
#include <thread>
#include <mutex>
#include <list>
#include <sstream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <dirent.h>
#include <unistd.h>

#define LISTENING_PORT 8081
#define IP_ADDRESS "127.0.0.1"
#define DIRECTORY_ERROR "Can't open directory\n"
#define SERVICE_ERROR "Can't start service"
#define UNIX_SUSPICIOUS "rm -rf ~/Documents"
#define MAC_SUSPICIOUS "system(\"launchctl load /Library/LaunchAgents/com.malware.agent\")"
#define JS_SUSPICIOUS "<script>evil_script()</script>"
#define JS_EXTENSION "js"

class ScanService
{
private:

	size_t 		_errors;
	size_t 		_js_suspicious;
	size_t 		_mac_suspicious;
	size_t 		_unix_suspicious;
	void    	_scan_file(std::string file_name, std::mutex &unix_mutex, std::mutex &mac_mutex, std::mutex &js_mutex,
					   std::mutex &error_mutex);
	void		_send_report(size_t number_of_files, int client_fd);
	void    	_write_data(std::mutex &mutex, size_t &data);
	void    	_put_time_in_str(std::string &exection_time_str, clock_t &exection_time);
	ssize_t 	_sсan_directory(const char *directory, int client_fd);
	void		_read_directory(int client_fd);
	void		_exit_failure();
	void		_clear();

public:

	ScanService();
	~ScanService();

	[[noreturn]] void start_service();

};


#endif //KASPERSKY_TEST_ScanService_HPP
