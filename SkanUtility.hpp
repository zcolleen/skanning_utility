

#ifndef KASPERSKY_TEST_SKANUTILITY_HPP
#define KASPERSKY_TEST_SKANUTILITY_HPP

#include <iostream>
#include <dirent.h>
#include <fstream>

#define UNIX_SUSPICIOUS "rm -rf ~/Documents"
#define MAC_SUSPICIOUS "system(\"launchctl load /Library/LaunchAgents/com.malware.agent\")"
#define JS_SUSPICIOUS "<script>evil_script()</script>"
#define JS_EXTENSION "js"


class SkanUtility
{

private:
	size_t _errors;
	size_t _mac_suspicious;
	size_t _js_suspicious;
	size_t _unix_suspicious;
	const char *_directory;
	void	_scan_file(const std::string &file_name);
	void	_print_report(size_t number_of_files);

public:
	SkanUtility(const char *directory);

	void sсan_directory();

};


#endif
