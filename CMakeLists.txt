cmake_minimum_required(VERSION 3.17)
project(kaspersky_test)

set(CMAKE_CXX_STANDARD 14)

add_executable(kaspersky_test second_task/utility/ScanUtility.cpp second_task/utility/ScanUtility.hpp second_task/utility/main_utility.cpp)
