# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.21

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

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/Cellar/cmake/3.21.3/bin/cmake

# The command to remove a file.
RM = /usr/local/Cellar/cmake/3.21.3/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/hamzasaleem/Desktop/bicycl-master/benchs

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/hamzasaleem/Desktop/bicycl-master/benchs

# Include any dependencies generated for this target.
include CMakeFiles/main_build.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/main_build.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/main_build.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/main_build.dir/flags.make

CMakeFiles/main_build.dir/main.o: CMakeFiles/main_build.dir/flags.make
CMakeFiles/main_build.dir/main.o: main.cpp
CMakeFiles/main_build.dir/main.o: CMakeFiles/main_build.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/hamzasaleem/Desktop/bicycl-master/benchs/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/main_build.dir/main.o"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/main_build.dir/main.o -MF CMakeFiles/main_build.dir/main.o.d -o CMakeFiles/main_build.dir/main.o -c /Users/hamzasaleem/Desktop/bicycl-master/benchs/main.cpp

CMakeFiles/main_build.dir/main.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/main_build.dir/main.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/hamzasaleem/Desktop/bicycl-master/benchs/main.cpp > CMakeFiles/main_build.dir/main.i

CMakeFiles/main_build.dir/main.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/main_build.dir/main.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/hamzasaleem/Desktop/bicycl-master/benchs/main.cpp -o CMakeFiles/main_build.dir/main.s

# Object files for target main_build
main_build_OBJECTS = \
"CMakeFiles/main_build.dir/main.o"

# External object files for target main_build
main_build_EXTERNAL_OBJECTS =

main: CMakeFiles/main_build.dir/main.o
main: CMakeFiles/main_build.dir/build.make
main: CMakeFiles/main_build.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/hamzasaleem/Desktop/bicycl-master/benchs/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable main"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/main_build.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/main_build.dir/build: main
.PHONY : CMakeFiles/main_build.dir/build

CMakeFiles/main_build.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/main_build.dir/cmake_clean.cmake
.PHONY : CMakeFiles/main_build.dir/clean

CMakeFiles/main_build.dir/depend:
	cd /Users/hamzasaleem/Desktop/bicycl-master/benchs && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/hamzasaleem/Desktop/bicycl-master/benchs /Users/hamzasaleem/Desktop/bicycl-master/benchs /Users/hamzasaleem/Desktop/bicycl-master/benchs /Users/hamzasaleem/Desktop/bicycl-master/benchs /Users/hamzasaleem/Desktop/bicycl-master/benchs/CMakeFiles/main_build.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/main_build.dir/depend
