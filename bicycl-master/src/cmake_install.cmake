# Install script for directory: /Users/hamzasaleem/Desktop/bicycl-master/src

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/Library/Developer/CommandLineTools/usr/bin/objdump")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include" TYPE FILE FILES "/Users/hamzasaleem/Desktop/bicycl-master/src/bicycl.hpp")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/bicycl" TYPE FILE FILES
    "/Users/hamzasaleem/Desktop/bicycl-master/src/bicycl/seclevel.hpp"
    "/Users/hamzasaleem/Desktop/bicycl-master/src/bicycl/gmp_extras.hpp"
    "/Users/hamzasaleem/Desktop/bicycl-master/src/bicycl/gmp_extras.inl"
    "/Users/hamzasaleem/Desktop/bicycl-master/src/bicycl/qfi.hpp"
    "/Users/hamzasaleem/Desktop/bicycl-master/src/bicycl/qfi.inl"
    "/Users/hamzasaleem/Desktop/bicycl-master/src/bicycl/CL_HSM_utils.hpp"
    "/Users/hamzasaleem/Desktop/bicycl-master/src/bicycl/CL_HSM_utils.inl"
    "/Users/hamzasaleem/Desktop/bicycl-master/src/bicycl/CL_HSMqk.hpp"
    "/Users/hamzasaleem/Desktop/bicycl-master/src/bicycl/CL_HSMqk.inl"
    "/Users/hamzasaleem/Desktop/bicycl-master/src/bicycl/DKG.hpp"
    "/Users/hamzasaleem/Desktop/bicycl-master/src/bicycl/DKG.inl"
    "/Users/hamzasaleem/Desktop/bicycl-master/src/bicycl/dealing.pb.h"
    "/Users/hamzasaleem/Desktop/bicycl-master/src/bicycl/dealing.pb.cc"
    "/Users/hamzasaleem/Desktop/bicycl-master/src/bicycl/NetworkingManager.hpp"
    )
endif()

