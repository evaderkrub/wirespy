# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2026 Dave Robins

find_package(Catch2 3 CONFIG QUIET)
if(NOT Catch2_FOUND)
  include(FetchContent)
  FetchContent_Declare(Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.7.1
    GIT_SHALLOW TRUE)
  FetchContent_MakeAvailable(Catch2)
  list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/extras")
endif()
include(Catch)

add_executable(wirespy_tests
  test_smoke.cpp
  test_wire_protocol.cpp
  test_tree_render.cpp
  test_decode_session.cpp
)

target_link_libraries(wirespy_tests PRIVATE
  Catch2::Catch2WithMain
  wirespy_proto
  wirespy_render
  wirespy_session
  wirespy_epan
)

wirespy_stage_data(wirespy_tests)
catch_discover_tests(wirespy_tests)

# End to end: the client library against the server this build produced,
# over the golden captures in tests/data.
add_executable(wirespy_e2e test_client_e2e.cpp)
target_link_libraries(wirespy_e2e PRIVATE Catch2::Catch2WithMain wirespy_client)
target_compile_definitions(wirespy_e2e PRIVATE
  "WIRESPY_SERVER_EXE=\"$<TARGET_FILE:wirespy_server>\""
  "WIRESPY_TEST_DATA=\"${CMAKE_CURRENT_SOURCE_DIR}/../data\"")
add_dependencies(wirespy_e2e wirespy_server)
catch_discover_tests(wirespy_e2e)
