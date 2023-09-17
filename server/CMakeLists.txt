project(u9fs)

# Create the executable
add_executable(u9fs u9fs.c authnone.c authp9any.c authrhosts.c authssh2.c convD2M.c convM2D.c convM2S.c convS2M.c des.c dirmodeconv.c doprint.c fcallconv.c oldfcall.c print.c random.c readn.c remotehost.c rune.c safecpy.c strecpy.c tokenize.c utfrune.c)

set_property(TARGET u9fs PROPERTY C_STANDARD 11)

# Add options to the compilation of source files
target_compile_options(u9fs PUBLIC -Wall -Wextra -Wshadow -Wduplicated-branches -Wswitch-default -Wswitch-enum -Wwrite-strings -Wno-missing-braces)

# Set the output directory for the executable
set_target_properties(u9fs PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${BUILD_DIR})

target_link_libraries(u9fs PUBLIC libssh2::libssh2)
target_include_directories(u9fs PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
