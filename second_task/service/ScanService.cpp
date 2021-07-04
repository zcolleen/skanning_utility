

#include "ScanService.hpp"


ScanService::ScanService() : _errors(0), _js_suspicious(0), _mac_suspicious(0), _unix_suspicious(0) {}


void ScanService::_write_data(std::mutex &mutex, size_t &data)
{
	mutex.lock();
	++data;
	mutex.unlock();
}

void ScanService::_scan_file(std::string file_name, std::mutex &unix_mutex, std::mutex &mac_mutex, std::mutex &js_mutex,
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

void ScanService::_sсan_directory(const char *directory)
{
	DIR *dir_stream;
	struct dirent *entry;
	size_t number_of_files = 0;
	std::list<std::thread> threads;
	std::mutex unix_mutex;
	std::mutex mac_mutex;
	std::mutex js_mutex;
	std::mutex error_mutex;


	if (!(dir_stream = opendir(directory))) {
		std::cout << "Can't open directory" << std::endl;
		return ;
	}
	while ((entry = readdir(dir_stream))) {

		threads.push_back(std::thread(&ScanService::_scan_file, this, entry->d_name, std::ref(unix_mutex),
									  std::ref(mac_mutex), std::ref(js_mutex), std::ref(error_mutex)));
		++number_of_files;
	}
	for (auto it = threads.begin(); it != threads.end(); ++it)
		(*it).join();
	closedir(dir_stream);
}

void ScanService::_exit_failure()
{
	std::cout << "Can't start service" << std::endl;
	exit(EXIT_FAILURE);
}

void ScanService::_read_directory(int client_fd)
{
	char buffer[256];
	bzero(buffer, sizeof buffer);

	if (recv(client_fd, buffer, sizeof buffer, 0) <= 0)
		return;
	_sсan_directory(buffer);
}

void ScanService::_signal_listener(int signal)
{
	if (signal == SIGINT) {
		shutdown(_socket_fd, SHUT_RDWR);
		close(_socket_fd);
		exit(0);
	}
}

[[noreturn]] void ScanService::start_service()
{
	struct sockaddr_in addr;
	int client_fd;

	signal(SIGINT, _signal_listener);
	_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (_socket_fd < 0)
		_exit_failure();
	addr.sin_family = AF_INET;
	addr.sin_port = htons(LISTENING_PORT);
	addr.sin_addr.s_addr = inet_addr(IP_ADDRESS);
	if (bind(_socket_fd, (const struct sockaddr*)&addr, sizeof addr) ||
			listen(_socket_fd, SOMAXCONN))
		_exit_failure();
	socklen_t addrlen = sizeof addr;
	std::cout << "Service has started" << std::endl;
	while (true)
	{
		client_fd = accept(_socket_fd, (struct sockaddr*)&addr, &addrlen);
		_read_directory(client_fd);
		shutdown(client_fd, SHUT_RDWR);
		close(client_fd);
	}
}
