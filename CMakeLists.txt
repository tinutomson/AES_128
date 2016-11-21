cmake_minimum_required (VERSION 2.8)

# Project name
project (AES_project)

# The version number
set(VERSION_MAJOR 0)
set(VERSION_MINOR 1)

set(CMAKE_CXX_FLAGS "-Wall -g")
add_compile_options(-std=c++0x) # CMake 2.8.12 or newer

file(GLOB SRCS aes.cpp aes.hpp test_aes.cpp)
add_executable(AES ${SRCS})