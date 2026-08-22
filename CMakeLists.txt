cmake_minimum_required(VERSION 3.16)
project(protectme VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler warnings
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -Werror")
endif()

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_executable(protectme
    userspace/main.cpp
    userspace/cli/cli.cpp
    userspace/cli/commands.cpp
    userspace/daemon/daemon.cpp
    userspace/daemon/enforcer.cpp
    userspace/policy/policy.cpp
    userspace/audit/audit.cpp
)

target_include_directories(protectme PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/userspace
)

install(TARGETS protectme DESTINATION bin)