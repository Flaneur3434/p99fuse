cmake_minimum_required(VERSION 3.20)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# check if use g++ unless wagie
set(CMAKE_CXX_COMPILER "/usr/bin/g++")

set(CMAKE_VERBOSE_MAKEFILE ON)

# Export the compilation commands to a file
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Create the build directory
set(BUILD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/build)
if(NOT EXISTS ${BUILD_DIR})
    file(MAKE_DIRECTORY ${BUILD_DIR})
endif()

# Add options to the compilation of source files
add_compile_options(-Wall -Wextra -Wshadow -Wduplicated-branches -Wswitch-default -Wswitch-enum -Wwrite-strings)

project(9bind)

# Create the executable
add_executable(9bind main.cpp)

# Set the output directory for the executable
set_target_properties(9bind PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${BUILD_DIR})

# Linux Fuse header
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/CMake")
find_package(fuse3 REQUIRED)
if(FUSE3_FOUND)
  message(STATUS "fuse ver ${FUSE3_MOUNT_VERSION} library found: ${FUSE3_LIBRARY}")
  message(STATUS "fuse ver ${FUSE3_MOUNT_VERSION} include path found: ${FUSE3_INCLUDE_DIR}")
else()
  message(FATAL_ERROR "fuse library not found")
endif()

include(FetchContent)
FetchContent_Declare(
    liburing4cpp
    GIT_REPOSITORY https://github.com/CarterLi/liburing4cpp.git
    GIT_TAG async
	FIND_PACKAGE_ARGS # use find_package() before trying to download source
)

FetchContent_Declare(
	libssh2
	GIT_REPOSITORY https://github.com/libssh2/libssh2.git
	GIT_TAG master
	FIND_PACKAGE_ARGS # use find_package() before trying to download source
)

FetchContent_MakeAvailable(liburing4cpp libssh2)
target_include_directories(9bind PUBLIC ${FUSE3_INCLUDE_DIR})
target_link_libraries(9bind PUBLIC liburing4cpp PUBLIC libssh2 PUBLIC ${FUSE3_LIBRARY})
