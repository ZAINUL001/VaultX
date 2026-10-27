cmake_minimum_required(VERSION 3.16)
project(VaultX VERSION 1.0.0 DESCRIPTION "Secure Multithreaded File Vault" LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_FLAGS_RELEASE "-O3")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

file(GLOB_RECURSE VAULTX_LIB_SOURCES CONFIGURE_DEPENDS
    ${CMAKE_SOURCE_DIR}/src/crypto/*.cpp
    ${CMAKE_SOURCE_DIR}/src/core/*.cpp
    ${CMAKE_SOURCE_DIR}/src/threading/*.cpp
    ${CMAKE_SOURCE_DIR}/src/io/*.cpp
    ${CMAKE_SOURCE_DIR}/src/benchmark/*.cpp
)

add_library(vaultx_lib STATIC ${VAULTX_LIB_SOURCES})
target_include_directories(vaultx_lib PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_compile_options(vaultx_lib PUBLIC -Wall -Wextra)
target_link_libraries(vaultx_lib PUBLIC OpenSSL::Crypto Threads::Threads)

add_executable(vaultx src/main.cpp)
target_link_libraries(vaultx PRIVATE vaultx_lib)

enable_testing()
add_subdirectory(tests)
