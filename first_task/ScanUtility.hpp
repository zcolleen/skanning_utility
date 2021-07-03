

#ifndef KASPERSKY_TEST_ScanUtility_HPP
#define KASPERSKY_TEST_ScanUtility_HPP

#include <iostream>
#include <dirent.h>
#include <fstream>
#include <thread>
#include <mutex>
#include <list>

#define UNIX_SUSPICIOUS "rm -rf ~/Documents"
#define MAC_SUSPICIOUS "system(\"launchctl load /Library/LaunchAgents/com.malware.agent\")"
#define JS_SUSPICIOUS "<script>evil_script()</script>"
#define JS_EXTENSION "js"


class ScanUtility
{

private:
	const char *_directory;
    size_t _errors;
    size_t _js_suspicious;
    size_t _mac_suspicious;
    size_t _unix_suspicious;
    void    _scan_file(std::string file_name, std::mutex &unix_mutex, std::mutex &mac_mutex, std::mutex &js_mutex,
                       std::mutex &error_mutex);
	void	_print_report(size_t number_of_files);
    void    _write_data(std::mutex &mutex, size_t &data);
    void    _put_time_in_str(std::string &exection_time_str, clock_t &exection_time);

public:
	ScanUtility(const char *directory);

	void sсan_directory();

};


#endif
