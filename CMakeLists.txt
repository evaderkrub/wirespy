# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2026 Dave Robins

cmake_minimum_required(VERSION 3.21)
project(wirespy LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(WIRESPY_BUILD_TESTS "Build the Catch2 test binary" ON)

# ---------------------------------------------------------------------------
# libwireshark (epan) + wiretap + wsutil.
#
# Two ways in:
#  * WIRESPY_WIRESHARK_ROOT=<dir>: a prefix that mirrors a system root
#    (<dir>/usr/include/wireshark, <dir>/usr/lib/<arch>/libwireshark.so ...),
#    i.e. what `apt-get download libwireshark-dev libwireshark18 ... &&
#    dpkg-deb -x` produces on a machine without root. glib still comes from
#    the system via pkg-config. The exe gets an rpath into the prefix.
#  * otherwise pkg-config's wireshark.pc (system install, MSYS2, ...). We
#    deliberately use the .pc rather than WiresharkConfig.cmake, whose
#    exported targets carry hard-coded build-host paths.
# ---------------------------------------------------------------------------
find_package(PkgConfig REQUIRED)
set(WIRESPY_WIRESHARK_ROOT "" CACHE PATH "Prefix mirroring / with an extracted libwireshark-dev (no-root install)")
if(WIRESPY_WIRESHARK_ROOT)
    set(_ws_inc "${WIRESPY_WIRESHARK_ROOT}/usr/include/wireshark")
    if(NOT EXISTS "${_ws_inc}/epan/epan.h")
        message(FATAL_ERROR "WIRESPY_WIRESHARK_ROOT=${WIRESPY_WIRESHARK_ROOT}: no usr/include/wireshark/epan/epan.h under it")
    endif()
    set(_ws_libdirs "${WIRESPY_WIRESHARK_ROOT}/usr/lib/${CMAKE_LIBRARY_ARCHITECTURE}" "${WIRESPY_WIRESHARK_ROOT}/usr/lib")
    find_library(WIRESPY_LIB_WIRESHARK NAMES wireshark HINTS ${_ws_libdirs} NO_DEFAULT_PATH REQUIRED)
    find_library(WIRESPY_LIB_WIRETAP   NAMES wiretap   HINTS ${_ws_libdirs} NO_DEFAULT_PATH REQUIRED)
    find_library(WIRESPY_LIB_WSUTIL    NAMES wsutil    HINTS ${_ws_libdirs} NO_DEFAULT_PATH REQUIRED)
    pkg_check_modules(GLIB REQUIRED IMPORTED_TARGET glib-2.0 gmodule-2.0 gthread-2.0)
    add_library(wirespy_wireshark INTERFACE)
    target_include_directories(wirespy_wireshark INTERFACE "${_ws_inc}")
    target_link_libraries(wirespy_wireshark INTERFACE
        "${WIRESPY_LIB_WIRESHARK}" "${WIRESPY_LIB_WIRETAP}" "${WIRESPY_LIB_WSUTIL}" PkgConfig::GLIB)
    get_filename_component(_ws_libdir "${WIRESPY_LIB_WIRESHARK}" DIRECTORY)
    list(APPEND CMAKE_BUILD_RPATH "${_ws_libdir}")
    list(APPEND CMAKE_INSTALL_RPATH "${_ws_libdir}")
    # libwireshark.so itself needs libsmi / libbcg729 from the same prefix,
    # and the loader only honours the exe's search path for TRANSITIVE
    # dependencies when it is DT_RPATH (RUNPATH, the default, is not).
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang" AND NOT APPLE AND NOT WIN32)
        add_link_options("-Wl,--disable-new-dtags")
    endif()
    # The data files (colorfilters, dfilters, manuf ...) live beside the
    # libraries' prefix; the server exports the directory to libwireshark.
    set(WIRESPY_DATA_DIR "${WIRESPY_WIRESHARK_ROOT}/usr/share/wireshark")
    # nlohmann_json's CMake package from the same prefix (nlohmann-json3-dev).
    list(APPEND CMAKE_PREFIX_PATH "${WIRESPY_WIRESHARK_ROOT}/usr")
else()
    pkg_check_modules(WIRESHARK REQUIRED IMPORTED_TARGET wireshark)
    add_library(wirespy_wireshark INTERFACE)
    target_link_libraries(wirespy_wireshark INTERFACE PkgConfig::WIRESHARK wiretap)
    pkg_get_variable(_ws_prefix wireshark prefix)
    set(WIRESPY_DATA_DIR "${_ws_prefix}/share/wireshark")
endif()

find_package(nlohmann_json CONFIG REQUIRED)

# Windows Wireshark reads global data beside the executable, regardless of
# WIRESHARK_DATA_DIR. Stage it for development binaries as well as bundles.
function(wirespy_stage_data target)
    if(WIN32)
        foreach(_name colorfilters dfilters dfilter_macros cfilters manuf services enterprises.tsv wka)
            if(EXISTS "${WIRESPY_DATA_DIR}/${_name}")
                add_custom_command(TARGET ${target} POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy_if_different
                        "${WIRESPY_DATA_DIR}/${_name}" "$<TARGET_FILE_DIR:${target}>/${_name}"
                    VERBATIM)
            endif()
        endforeach()
        if(NOT EXISTS "${WIRESPY_DATA_DIR}/colorfilters")
            message(WARNING "Wireshark colorfilters missing from ${WIRESPY_DATA_DIR}; install its runtime data package")
        endif()
    endif()
endfunction()

if(NOT TARGET wirespy_client)
    add_subdirectory(src/client)
endif()
add_subdirectory(src/server)
add_subdirectory(src/cli)

if(WIRESPY_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests/cpp)
endif()
