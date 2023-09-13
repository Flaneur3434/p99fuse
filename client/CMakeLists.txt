project(9fuse)

# Create the executable
add_executable(9fuse 9p.c 9pfs.c util.c)

set_property(TARGET 9fuse PROPERTY C_STANDARD 11)

# Add options to the compilation of source files
target_compile_options(9fuse PUBLIC -Wall -Wextra -Wshadow -Wduplicated-branches -Wswitch-default -Wswitch-enum -Wwrite-strings -Wno-missing-braces)

# Set the output directory for the executable
set_target_properties(9fuse PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${BUILD_DIR})

# Linux Fuse header
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMake")
find_package(fuse3 REQUIRED)
if(FUSE3_FOUND)
  message(STATUS "fuse ver ${FUSE3_MOUNT_VERSION} library found: ${FUSE3_LIBRARY}")
  message(STATUS "fuse ver ${FUSE3_MOUNT_VERSION} include path found: ${FUSE3_INCLUDE_DIR}")
else()
  message(FATAL_ERROR "fuse library not found")
endif()

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/lib)

target_include_directories(9fuse PUBLIC ${FUSE3_INCLUDE_DIR} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(9fuse PUBLIC ${FUSE3_LIBRARY} lib)
target_compile_definitions(9fuse PUBLIC FUSE_USE_VERSION=30)
