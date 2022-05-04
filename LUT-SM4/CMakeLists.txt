cmake_minimum_required(VERSION 2.8)
project(lut_sm4)
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c++11 -O2")

include_directories(./include)
aux_source_directory(./src DIR_SRCS)
aux_source_directory(./test DIR_SRCS)

add_executable(lut_sm4 ./test/main.c ${DIR_SRCS})
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)