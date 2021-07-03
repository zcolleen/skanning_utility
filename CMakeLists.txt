cmake_minimum_required(VERSION 3.17)
project(kaspersky_test)

set(CMAKE_CXX_STANDARD 14)

add_executable(kaspersky_test main.cpp SkanUtility.cpp SkanUtility.hpp)