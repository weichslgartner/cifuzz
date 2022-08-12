cmake_minimum_required(VERSION 3.21)

project(CmakeTest)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

enable_testing()

find_package(cifuzz)
enable_fuzz_testing()

add_subdirectory(src/parser)
add_subdirectory(src/utils)
