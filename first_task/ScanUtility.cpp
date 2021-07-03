

#include "ScanUtility.hpp"


ScanUtility::ScanUtility(const char *directory) : _directory(directory), _errors(0),
_js_suspicious(0), _mac_suspicious(0), _unix_suspicious(0) {}


void ScanUtility::_write_data(std::mutex &mutex, size_t &data)
{
    mutex.lock();
    ++data;
    mutex.unlock();
}

void ScanUtility::_scan_file(std::string file_name, std::mutex &unix_mutex, std::mutex &mac_mutex, std::mutex &js_mutex,
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

void ScanUtility::_put_time_in_str(std::string &exection_time_str, clock_t &exection_time) {

        clock_t time = exection_time % 60;
        if (time > 9)
            exection_time_str += std::to_string(time);
        else
            exection_time_str += "0" + std::to_string(time);
        exection_time /= 60;
}

void ScanUtility::_print_report(size_t number_of_files)
{
    std::string exection_time_str;
    clock_t exection_time = clock() / CLOCKS_PER_SEC;

    _put_time_in_str(exection_time_str, exection_time);
    exection_time_str += ":";
    _put_time_in_str(exection_time_str, exection_time);
    exection_time_str += ":";
    _put_time_in_str(exection_time_str, exection_time);

	std::cout << "====== Scan result ======" << std::endl <<
	"Processed files: " << number_of_files << std::endl <<
	"JS detects: " << _js_suspicious << std::endl <<
	"Unix detects: " << _unix_suspicious << std::endl <<
	"macOS detects: " << _mac_suspicious << std::endl <<
	"Errors: " << _errors << std::endl <<
	"Exection time: " << exection_time_str << std::endl <<
	"=========================" << std::endl;
}

void ScanUtility::sсan_directory()
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

	    threads.push_back(std::thread(&ScanUtility::_scan_file, this, entry->d_name, std::ref(unix_mutex),
                                      std::ref(mac_mutex), std::ref(js_mutex), std::ref(error_mutex)));
		++number_of_files;
	}
	for (auto it = threads.begin(); it != threads.end(); ++it)
        (*it).join();
	closedir(dir_stream);
	_print_report(number_of_files);
}