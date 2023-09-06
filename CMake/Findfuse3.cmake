# Find the FUSE includes and library
#
#  FUSE_INCLUDE_DIR - where to find fuse.h, etc.
#  FUSE_LIBRARY   - List of libraries when using FUSE.
#  FUSE_FOUND       - True if FUSE lib is found.

# find includes
find_path(FUSE3_INCLUDE_DIR
	NAMES fuse.h
	PATH_SUFFIXES fuse3)
message(STATUS ${FUSE3_INCLUDE_DIR})

# find lib
find_library(FUSE3_LIBRARY
        NAMES fuse3
        HINTS /lib64 /lib /usr/lib64 /usr/lib /usr/local/lib64 /usr/local/lib /usr/lib/x86_64-linux-gnu
        )

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(fuse3
  REQUIRED_VARS FUSE3_LIBRARY FUSE3_INCLUDE_DIR)

mark_as_advanced(FUSE3_INCLUDE_DIR FUSE3_LIBRARY)
