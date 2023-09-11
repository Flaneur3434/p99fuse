project(9srv)

# Create the executable
add_executable(9srv 9fs.c authnone.c authp9any.c authrhosts.c authssh2.c convD2M.c convM2D.c convM2S.c convS2M.c des.c dirmodeconv.c doprint.c fcallconv.c oldfcall.c print.c random.c readn.c remotehost.c rune.c safecpy.c strecpy.c tokenize.c utfrune.c)

set_property(TARGET 9srv PROPERTY C_STANDARD 11)

# Add options to the compilation of source files
target_compile_options(9srv PUBLIC -Wall -Wextra -Wshadow -Wduplicated-branches -Wswitch-default -Wswitch-enum -Wwrite-strings -Wno-missing-braces)

# Set the output directory for the executable
set_target_properties(9srv PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${BUILD_DIR})

include(FetchContent)
FetchContent_Declare(
	libssh2
	GIT_REPOSITORY https://github.com/libssh2/libssh2.git
	GIT_TAG master
	FIND_PACKAGE_ARGS # use find_package() before trying to download source
)

FetchContent_MakeAvailable(libssh2)
target_link_libraries(9srv PUBLIC libssh2::libssh2)
target_include_directories(9srv PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
