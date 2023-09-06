cmake_minimum_required(VERSION 3.20)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# check if use g++ unless wagie
set(CMAKE_CXX_COMPILER "/usr/bin/g++")
# set(CMAKE_VERBOSE_MAKEFILE ON)
# Export the compilation commands to a file
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(p99fuse)

# Linux Fuse header
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/CMake")
find_package(fuse3 REQUIRED)
if(FUSE3_FOUND)
  message(STATUS "fuse ver ${FUSE3_MOUNT_VERSION} library found: ${FUSE3_LIBRARY}")
  message(STATUS "fuse ver ${FUSE3_MOUNT_VERSION} include path found: ${FUSE3_INCLUDE_DIR}")
else()
  message(FATAL_ERROR "fuse library not found")
endif()

# C++ io_uring Library
include(FetchContent)
FetchContent_Declare(
    liburing4cpp
    GIT_REPOSITORY https://github.com/CarterLi/liburing4cpp.git
    GIT_TAG        async
)
FetchContent_MakeAvailable(liburing4cpp)

# Create the build directory
set(BUILD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/build)
if(NOT EXISTS ${BUILD_DIR})
    file(MAKE_DIRECTORY ${BUILD_DIR})
endif()

# Add options to the compilation of source files
add_compile_options(-Wall -Wextra -Werror -Weffc++ -Wshadow -Wstrict-aliasing -Wduplicated-branches -Wfloat-equal -Wswitch-default -Wswitch-enum -Wwrite-strings -Wdangling-else -Wunreachable-code)

# Create the executable
add_executable(p99fuse main.cpp)

# link to class files
include_directories(${FUSE3_INCLUDE_DIR})
target_link_libraries(p99fuse PUBLIC liburing4pp ${FUSE3_LIBRARY})

# Set the output directory for the executable
set_target_properties(p99fuse PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${BUILD_DIR})
