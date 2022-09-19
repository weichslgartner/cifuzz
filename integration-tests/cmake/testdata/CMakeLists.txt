cmake_minimum_required(VERSION 3.19)

project(CmakeTest LANGUAGES CXX)

enable_testing()

add_subdirectory(src/parser)
add_subdirectory(src/coverage)
