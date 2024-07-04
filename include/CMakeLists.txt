cmake_minimum_required(VERSION 3.21)

project(asiotls 
  VERSION 0.0.0 
  LANGUAGES CXX)

find_package(MbedTLS REQUIRED)

add_library(${PROJECT_NAME} INTERFACE)

target_include_directories(${PROJECT_NAME} INTERFACE .)

target_link_libraries(${PROJECT_NAME} 
  INTERFACE 
    MbedTLS::mbedtls)