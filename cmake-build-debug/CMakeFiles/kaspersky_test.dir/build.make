# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.17

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Disable VCS-based implicit rules.
% : %,v


# Disable VCS-based implicit rules.
% : RCS/%


# Disable VCS-based implicit rules.
% : RCS/%,v


# Disable VCS-based implicit rules.
% : SCCS/s.%


# Disable VCS-based implicit rules.
% : s.%


.SUFFIXES: .hpux_make_needs_suffix_list


# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /Applications/CLion.app/Contents/bin/cmake/mac/bin/cmake

# The command to remove a file.
RM = /Applications/CLion.app/Contents/bin/cmake/mac/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/semen/CLionProjects/kaspercky_test

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/semen/CLionProjects/kaspercky_test/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/kaspersky_test.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/kaspersky_test.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/kaspersky_test.dir/flags.make

CMakeFiles/kaspersky_test.dir/second_task/ScanService.cpp.o: CMakeFiles/kaspersky_test.dir/flags.make
CMakeFiles/kaspersky_test.dir/second_task/ScanService.cpp.o: ../second_task/ScanService.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/semen/CLionProjects/kaspercky_test/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/kaspersky_test.dir/second_task/ScanService.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/kaspersky_test.dir/second_task/ScanService.cpp.o -c /Users/semen/CLionProjects/kaspercky_test/second_task/ScanService.cpp

CMakeFiles/kaspersky_test.dir/second_task/ScanService.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/kaspersky_test.dir/second_task/ScanService.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/semen/CLionProjects/kaspercky_test/second_task/ScanService.cpp > CMakeFiles/kaspersky_test.dir/second_task/ScanService.cpp.i

CMakeFiles/kaspersky_test.dir/second_task/ScanService.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/kaspersky_test.dir/second_task/ScanService.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/semen/CLionProjects/kaspercky_test/second_task/ScanService.cpp -o CMakeFiles/kaspersky_test.dir/second_task/ScanService.cpp.s

CMakeFiles/kaspersky_test.dir/second_task/main_service.cpp.o: CMakeFiles/kaspersky_test.dir/flags.make
CMakeFiles/kaspersky_test.dir/second_task/main_service.cpp.o: ../second_task/main_service.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/semen/CLionProjects/kaspercky_test/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/kaspersky_test.dir/second_task/main_service.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/kaspersky_test.dir/second_task/main_service.cpp.o -c /Users/semen/CLionProjects/kaspercky_test/second_task/main_service.cpp

CMakeFiles/kaspersky_test.dir/second_task/main_service.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/kaspersky_test.dir/second_task/main_service.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/semen/CLionProjects/kaspercky_test/second_task/main_service.cpp > CMakeFiles/kaspersky_test.dir/second_task/main_service.cpp.i

CMakeFiles/kaspersky_test.dir/second_task/main_service.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/kaspersky_test.dir/second_task/main_service.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/semen/CLionProjects/kaspercky_test/second_task/main_service.cpp -o CMakeFiles/kaspersky_test.dir/second_task/main_service.cpp.s

# Object files for target kaspersky_test
kaspersky_test_OBJECTS = \
"CMakeFiles/kaspersky_test.dir/second_task/ScanService.cpp.o" \
"CMakeFiles/kaspersky_test.dir/second_task/main_service.cpp.o"

# External object files for target kaspersky_test
kaspersky_test_EXTERNAL_OBJECTS =

kaspersky_test: CMakeFiles/kaspersky_test.dir/second_task/ScanService.cpp.o
kaspersky_test: CMakeFiles/kaspersky_test.dir/second_task/main_service.cpp.o
kaspersky_test: CMakeFiles/kaspersky_test.dir/build.make
kaspersky_test: CMakeFiles/kaspersky_test.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/semen/CLionProjects/kaspercky_test/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX executable kaspersky_test"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/kaspersky_test.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/kaspersky_test.dir/build: kaspersky_test

.PHONY : CMakeFiles/kaspersky_test.dir/build

CMakeFiles/kaspersky_test.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/kaspersky_test.dir/cmake_clean.cmake
.PHONY : CMakeFiles/kaspersky_test.dir/clean

CMakeFiles/kaspersky_test.dir/depend:
	cd /Users/semen/CLionProjects/kaspercky_test/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/semen/CLionProjects/kaspercky_test /Users/semen/CLionProjects/kaspercky_test /Users/semen/CLionProjects/kaspercky_test/cmake-build-debug /Users/semen/CLionProjects/kaspercky_test/cmake-build-debug /Users/semen/CLionProjects/kaspercky_test/cmake-build-debug/CMakeFiles/kaspersky_test.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/kaspersky_test.dir/depend

