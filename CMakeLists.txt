cmake_minimum_required (VERSION 3.5.1)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project (CGDKG VERSION 0.0.1 LANGUAGES CXX)
set (CGDKG_DESCRIPTION "Class Group DKG")

################################################################################
# Set the output folder where your program will be created
################################################################################
set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/bin)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})

################################################################################
# Add cmake.utils to the list of CMAKE_MODULE_PATH
################################################################################
set (MODULE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/cmake.utils")
list (APPEND CMAKE_MODULE_PATH "${MODULE_DIR}")

##############################################################################
# Print information (to ease debugging)
##############################################################################
message (STATUS "Running on system ${CMAKE_HOST_SYSTEM} with processor ${CMAKE_HOST_SYSTEM_PROCESSOR}")
if (CMAKE_CROSSCOMPILING)
  message (STATUS "Targeting system ${CMAKE_SYSTEM} with processor ${CMAKE_SYSTEM_PROCESSOR}")
endif ()
message (STATUS "Using CMake ${CMAKE_VERSION}")
message (STATUS "C++ compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")

##############################################################################
# Set C++ standard to c++11
##############################################################################
set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

##############################################################################
# Set flags and build type (release or debug)
##############################################################################
if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message (STATUS "Setting build type to 'Release' as none was specified.")
  set (CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose type of build" FORCE)
  set_property (CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release")
endif ()

if(NOT MSVC)
  set (CMAKE_CXX_FLAGS_RELEASE "-O3 -Wall -Wextra -DNDEBUG")
  set (CMAKE_CXX_FLAGS_DEBUG "-O3 -g -Wall -Wextra -DDEBUG")
endif()

################################################################################
# Looking for GMP
################################################################################
find_package (gmp REQUIRED)

################################################################################
# Include directories for header files and libs
################################################################################
include_directories(include)
include_directories(/usr/local/include/)
include_directories(/usr/local/include/miracl/)
include_directories(/usr/local/lib/)
link_directories(/usr/local/lib/)

################################################################################
# Add source files
################################################################################
file(GLOB SOURCES "src/*.cpp")

################################################################################
# Add executable
################################################################################
add_executable(main ${SOURCES})
target_link_libraries(main gmp::gmp core)