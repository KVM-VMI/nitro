cmake_minimum_required(VERSION 2.8)

#-----------------------------------------------------------------------------
#                           GENERAL CONFIGURATION
#-----------------------------------------------------------------------------
project(libnitro C)
#-----------------------------------------------------------------------------
#                              DEPENDENCIES
#-----------------------------------------------------------------------------
# find your dependencies here !
# ==> use cmake --help-module-list
# ==> and cmake --help-module FindBoost to known which variables are setted
# find_package(Boost COMPONENTS filesystem threads)
# include_directories(${Boost_INCLUDE_DIRS})

#-----------------------------------------------------------------------------
#                           BUILD TYPES & FLAGS
#-----------------------------------------------------------------------------
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fdiagnostics-color")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g3 -O0")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Werror -O2")

# strip binary in release mode
if(CMAKE_BUILD_TYPE MATCHES "RELEASE")
    set(CMAKE_EXE_LINKER_FLAGS "-s")
endif()
#-----------------------------------------------------------------------------
#                               SOURCES
#-----------------------------------------------------------------------------
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
add_library(nitro SHARED libnitro.c)
#-----------------------------------------------------------------------------
#                               BUILD SUMMARY
#-----------------------------------------------------------------------------
message(STATUS " ↳ Compiler     → ${CMAKE_C_COMPILER}")
message(STATUS " ↳ Prefix       → ${CMAKE_INSTALL_PREFIX}")
message(STATUS " ↳ Build        → ${CMAKE_BUILD_TYPE}")
message(STATUS " ↳ Sanitizers   → ${COMPILER_SANITIZER}")
message(STATUS " ↳ C Flags    → ${CMAKE_C_FLAGS}")
