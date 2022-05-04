cmake_minimum_required(VERSION 2.8)
project(sm4ni)
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c++11 -Wall -O2 -march=native -DSM4NI_UNROL")

include_directories(./include)
aux_source_directory(./src DIR_SRCS)
aux_source_directory(./test DIR_SRCS)

add_executable(sm4ni ./test/test_main.c ${DIR_SRCS})
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)