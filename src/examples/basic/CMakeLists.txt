cmake_minimum_required(VERSION 3.21)

set(EXPORT_COMPILE_COMMANDS ON)

project(asiotls-examples-basic 
  VERSION 0.0.0 
  LANGUAGES CXX)

find_package(asio REQUIRED)
find_package(MbedTLS REQUIRED)

add_executable(${PROJECT_NAME} 
  main.cpp)

target_link_libraries(${PROJECT_NAME} 
  PRIVATE 
    asio::asio
    MbedTLS::mbedtls
    asiotls)