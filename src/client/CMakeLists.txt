# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Dave Robins

# wirespy_client -- the client side of the protocol (docs/PROTOCOL.md) and
# the pcap / pcapng reader-writer. Links no Wireshark code; the dissector
# stays in wirespy_server. See the repository's licensing documentation.
add_library(wirespy_client STATIC
    wirespy_client.cpp
    pcap_reader.cpp
)
target_include_directories(wirespy_client PUBLIC .)
target_compile_features(wirespy_client PUBLIC cxx_std_20)
target_link_libraries(wirespy_client PUBLIC nlohmann_json::nlohmann_json)
if(WIN32)
    target_link_libraries(wirespy_client PUBLIC ws2_32)
else()
    find_package(Threads REQUIRED)
    target_link_libraries(wirespy_client PUBLIC Threads::Threads)
endif()
