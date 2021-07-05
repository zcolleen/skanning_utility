
#include "ScanService.hpp"

ScanService::ScanService() : _errors(0), _js_suspicious(0), _mac_suspicious(0), _unix_suspicious(0) {
    bzero(_directory, sizeof _directory);
}

ScanService::~ScanService() = default;

void ScanService::_write_data(std::mutex &mutex, size_t &data)
{
	mutex.lock();
	++data;
	mutex.unlock();
}

void ScanService::_scan_file(std::string file_name, std::mutex &unix_mutex, std::mutex &mac_mutex, std::mutex &js_mutex,
							 std::mutex &error_mutex)
{
    std::string absolute_file_name = std::string(_directory) + "/" + file_name;
	std::ifstream file(absolute_file_name);
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
	else {
        _write_data(error_mutex, this->_errors);
    }
}

ssize_t ScanService::_sсan_directory(int client_fd)
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
		send(client_fd, DIRECTORY_ERROR, std::strlen(DIRECTORY_ERROR), 0);
		return -1;
	}
	while ((entry = readdir(dir_stream))) {

		threads.push_back(std::thread(&ScanService::_scan_file, this, entry->d_name, std::ref(unix_mutex),
									  std::ref(mac_mutex), std::ref(js_mutex), std::ref(error_mutex)));
		++number_of_files;
	}
	for (auto it = threads.begin(); it != threads.end(); ++it)
		(*it).join();
	closedir(dir_stream);
	return number_of_files;
}

void ScanService::_exit_failure()
{
	std::cout << SERVICE_ERROR << std::endl;
	exit(EXIT_FAILURE);
}

void ScanService::_clear()
{
	_unix_suspicious = 0;
	_mac_suspicious = 0;
	_js_suspicious = 0;
	_errors = 0;
    bzero(_directory, sizeof _directory);
}

void ScanService::_put_time_in_str(std::string &exection_time_str, clock_t &exection_time) {

    clock_t time = exection_time % 60;
    if (time > 9)
        exection_time_str += std::to_string(time);
    else
        exection_time_str += "0" + std::to_string(time);
    exection_time /= 60;
}

void ScanService::_send_report(size_t number_of_files, int client_fd, size_t exec_start_time)
{
    std::stringstream stringstream;
    std::string exection_time_str;
    size_t exection_time = clock() / CLOCKS_PER_SEC - exec_start_time;

    _put_time_in_str(exection_time_str, exection_time);
    exection_time_str += ":";
    _put_time_in_str(exection_time_str, exection_time);
    exection_time_str += ":";
    _put_time_in_str(exection_time_str, exection_time);

    stringstream << "====== Scan result ======" << std::endl <<
                 "Processed files: " << number_of_files << std::endl <<
                 "JS detects: " << _js_suspicious << std::endl <<
                 "Unix detects: " << _unix_suspicious << std::endl <<
                 "macOS detects: " << _mac_suspicious << std::endl <<
                 "Errors: " << _errors << std::endl <<
                 "Exection time: " << exection_time_str << std::endl <<
                 "=========================" << std::endl;
    std::string report(stringstream.str());
    send(client_fd, report.c_str(), report.size(), 0);
}

void ScanService::_read_directory(int client_fd)
{
	ssize_t number_of_files;
	size_t exec_start_time;

	if (recv(client_fd, _directory, sizeof _directory, 0) <= 0)
		return;
	exec_start_time = clock() / CLOCKS_PER_SEC;
	if ((number_of_files = _sсan_directory(client_fd)) < 0)
		return;
	 _send_report(number_of_files, client_fd, exec_start_time);
	_clear();
}

[[noreturn]] void ScanService::start_service()
{
	int socket_fd;
	struct sockaddr_in addr;
	int client_fd;
	const int optval = 1;

	if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0 || (setsockopt(socket_fd,
		SOL_SOCKET, SO_REUSEADDR, (void *) &optval, sizeof optval)))
		_exit_failure();
	addr.sin_family = AF_INET;
	addr.sin_port = htons(LISTENING_PORT);
	addr.sin_addr.s_addr = inet_addr(IP_ADDRESS);
	if (bind(socket_fd, (const struct sockaddr*)&addr, sizeof addr) ||
			listen(socket_fd, SOMAXCONN))
		_exit_failure();
	socklen_t addrlen = sizeof addr;
	std::cout << "Service has started" << std::endl;
	while (true)
	{
		client_fd = accept(socket_fd, (struct sockaddr*)&addr, &addrlen);
		_read_directory(client_fd);
		shutdown(client_fd, SHUT_RDWR);
		close(client_fd);
	}
}
