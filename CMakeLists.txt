cmake_minimum_required(VERSION 3.17)
project(kaspersky_test)

set(CMAKE_CXX_STANDARD 14)

add_executable(kaspersky_test second_task/service/ScanService.cpp second_task/service/ScanService.hpp second_task/service/main_service.cpp)