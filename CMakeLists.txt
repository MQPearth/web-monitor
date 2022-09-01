cmake_minimum_required(VERSION 3.19)
project(web-monitor)

set(CMAKE_CXX_STANDARD 11)

file(GLOB THIRD_PARTY_LIB "${CMAKE_SOURCE_DIR}/third_party/lib/*/*.*")

find_library(ssl crypto)

include_directories(${CMAKE_SOURCE_DIR}/third_party/include)

add_executable(${PROJECT_NAME} main.cc)

target_link_libraries(${PROJECT_NAME} ssl crypto
        ${THIRD_PARTY_LIB})
