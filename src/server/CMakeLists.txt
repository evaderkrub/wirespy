# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2026 Dave Robins

# wire_protocol — pure module, no I/O.
add_library(wirespy_proto STATIC
  wire_protocol.cpp
)
target_include_directories(wirespy_proto PUBLIC .)
target_link_libraries(wirespy_proto PUBLIC
  nlohmann_json::nlohmann_json
)

# tree_render — pure module, no I/O.
add_library(wirespy_render STATIC
  tree_render.cpp
)
target_include_directories(wirespy_render PUBLIC .)
target_link_libraries(wirespy_render PUBLIC
  nlohmann_json::nlohmann_json
)

# epan_runtime — RAII libwireshark init/teardown.
add_library(wirespy_epan STATIC
  epan_runtime.cpp
)
target_include_directories(wirespy_epan PUBLIC .)
target_link_libraries(wirespy_epan PUBLIC wirespy_wireshark)
if(WIRESPY_DATA_DIR)
  target_compile_definitions(wirespy_epan PRIVATE "WIRESPY_DATA_DIR=\"${WIRESPY_DATA_DIR}\"")
endif()

# decode_session — runs epan against a frame, returns tree + columns.
add_library(wirespy_session STATIC
  decode_session.cpp
)
target_include_directories(wirespy_session PUBLIC .)
target_link_libraries(wirespy_session PUBLIC
  wirespy_render
  wirespy_wireshark
)

# tcp_listener — accept loop, one thread per connection (Winsock or POSIX).
add_library(wirespy_tcp STATIC
  tcp_listener.cpp
)
target_include_directories(wirespy_tcp PUBLIC .)
if(WIN32)
  target_link_libraries(wirespy_tcp PUBLIC ws2_32)
else()
  find_package(Threads REQUIRED)
  target_link_libraries(wirespy_tcp PUBLIC Threads::Threads)
endif()

add_executable(wirespy_server
  main.cpp
)

target_link_libraries(wirespy_server PRIVATE
  wirespy_proto
  wirespy_render
  wirespy_epan
  wirespy_session
  wirespy_tcp
)
wirespy_stage_data(wirespy_server)
