

#include "SkanUtility.hpp"


SkanUtility::SkanUtility(const char *directory) : _directory(directory), _errors(0),
_js_suspicious(0), _mac_suspicious(0), _unix_suspicious(0) {}


void SkanUtility::_write_data(std::mutex &mutex, size_t &data)
{
    mutex.lock();
    ++data;
    mutex.unlock();
}

void SkanUtility::_scan_file(std::string file_name, std::mutex &unix_mutex, std::mutex &mac_mutex, std::mutex &js_mutex,
                             std::mutex &error_mutex)
{
	std::ifstream file(file_name);
	std::string str;

	if (file.is_open()) {

		while (getline(file, str)) {

			if (str == UNIX_SUSPICIOUS) {
                _write_data(unix_mutex, this->_unix_suspicious);
				break;
			}
			else if (str == MAC_SUSPICIOUS) {
                _write_data(mac_mutex, this->_mac_suspicious);
				break;
			}
			else if (str == JS_SUSPICIOUS && file_name.substr(file_name.rfind('.') + 1) == JS_EXTENSION) {
                _write_data(js_mutex, this->_js_suspicious);
				break;
			}
		}
		file.close();
	}
	else
        _write_data(error_mutex, this->_errors);
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
	std::list<std::thread> threads;
	std::mutex unix_mutex;
	std::mutex mac_mutex;
	std::mutex js_mutex;
	std::mutex error_mutex;


	if (!(dir_stream = opendir(_directory))) {
		std::cout << "Can't open directory" << std::endl;
		return ;
	}
	while ((entry = readdir(dir_stream))) {

	    threads.push_back(std::thread(&SkanUtility::_scan_file, this, entry->d_name, std::ref(unix_mutex),
                                      std::ref(mac_mutex), std::ref(js_mutex), std::ref(error_mutex)));
		++number_of_files;
	}
	for (auto it = threads.begin(); it != threads.end(); ++it)
        (*it).join();
	closedir(dir_stream);
	_print_report(number_of_files);
}