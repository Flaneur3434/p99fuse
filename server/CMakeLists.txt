# Add options to the compilation of source files
add_compile_options(-Wall -Wextra -Wshadow -Wduplicated-branches -Wswitch-default -Wswitch-enum -Wwrite-strings)

project(9fs)

# Create the executable
add_executable(9fs 9fs.c authnone.c authp9any.c authrhosts.c convD2M.c convM2D.c convM2S.c convS2M.c des.c dirmodeconv.c doprint.c fcallconv.c oldfcall.c print.c random.c readn.c remotehost.c rune.c safecpy.c strecpy.c tokenize.c utfrune.c)

# Set the output directory for the executable
set_target_properties(9fs PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${BUILD_DIR})

include(FetchContent)
FetchContent_Declare(
	libssh2
	GIT_REPOSITORY https://github.com/libssh2/libssh2.git
	GIT_TAG master
	FIND_PACKAGE_ARGS # use find_package() before trying to download source
)

FetchContent_MakeAvailable(libssh2)
target_link_libraries(9fs PUBLIC libssh2)
target_include_directories(9fs PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
