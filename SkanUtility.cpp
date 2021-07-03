

#include "SkanUtility.hpp"


SkanUtility::SkanUtility(const char *directory) : _directory(directory), _errors(0),
_js_suspicious(0), _mac_suspicious(0), _unix_suspicious(0) {}


void SkanUtility::_scan_file(const std::string &file_name)
{
	std::ifstream file(file_name);
	std::string str;

	if (file.is_open()) {

		while (getline(file, str)) {

			if (str == UNIX_SUSPICIOUS) {
				++_unix_suspicious;
				break;
			}
			else if (str == MAC_SUSPICIOUS) {
				++_mac_suspicious;
				break;
			}
			else if (str == JS_SUSPICIOUS && file_name.substr(file_name.rfind('.') + 1) == JS_EXTENSION) {
				++_js_suspicious;
				break;
			}
		}
		file.close();
	}
	else
		++_errors;
}

void SkanUtility::_print_report(size_t number_of_files)
{
	std::cout << "====== Scan result ======" << std::endl <<
	"Processed files: " << number_of_files << std::endl <<
	"JS detects: " << _js_suspicious << std::endl <<
	"Unix detects: " << _unix_suspicious << std::endl <<
	"macOS detects: " << _mac_suspicious << std::endl <<
	"Errors: " << _errors << std::endl <<
	"Exection time: " << (float )clock() / CLOCKS_PER_SEC << std::endl <<
	"=========================" << std::endl;
}

void SkanUtility::sсan_directory()
{
	DIR *dir_stream;
	struct dirent *entry;
	size_t number_of_files = 0;

	if (!(dir_stream = opendir(_directory))) {
		std::cout << "Can't open directory" << std::endl;
		return ;
	}
	while ((entry = readdir(dir_stream))) {
		_scan_file(entry->d_name);
		++number_of_files;
	}
	closedir(dir_stream);
	_print_report(number_of_files);
}