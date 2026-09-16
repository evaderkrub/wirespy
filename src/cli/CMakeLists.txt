# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Dave Robins

add_executable(wirespy_cli wirespy_cli.cpp)
target_link_libraries(wirespy_cli PRIVATE wirespy_client)
