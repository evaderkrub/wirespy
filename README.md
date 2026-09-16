# wirespy

Wireshark packet decoding over a local TCP connection, with a C++20 client
library and command-line capture reader.

Send raw frames to `wirespy_server` and receive decoded protocol trees,
Wireshark summary columns, packet colours and display-filter results. The
decoder runs in its own process; client applications link only `wirespy_client`.

| Component | Purpose | License |
| --- | --- | --- |
| `src/server/` | Decoder built against Wireshark's libraries | GPL-2.0-or-later |
| `src/client/` | TCP client, server launcher, and pcap/pcapng reader and writer | MIT |
| `src/cli/` | Command-line capture summaries, packet details and JSON output | MIT |
| `docs/PROTOCOL.md` | Length-prefixed TCP protocol and operation reference | MIT |
| `tests/` | Unit and end-to-end tests with small capture fixtures | GPL-2.0-or-later |

## Build

Requires a C++20 compiler, CMake 3.21 or newer, Ninja, pkg-config, Wireshark
development libraries and nlohmann/json. The compatibility layer supports the
Wireshark 4.4 and 4.6 APIs. Tests use Catch2 3; CMake fetches version 3.7.1
when an installed copy is unavailable.

### Linux

On Debian or Ubuntu with suitable Wireshark development packages:

```bash
sudo apt-get install g++ cmake ninja-build pkg-config \
    libwireshark-dev libwiretap-dev libwsutil-dev nlohmann-json3-dev
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Without a system installation, `-DWIRESPY_WIRESHARK_ROOT=/path/to/prefix`
accepts a prefix containing extracted development packages in a mirrored
`usr/include/wireshark` and `usr/lib` layout. GLib is still found through
pkg-config. Otherwise, the build uses the installed `wireshark.pc` file.

### Windows

Build in an **MSYS2 MINGW64** shell:

```bash
pacman -S --needed mingw-w64-x86_64-toolchain mingw-w64-x86_64-cmake \
    mingw-w64-x86_64-ninja mingw-w64-x86_64-wireshark \
    mingw-w64-x86_64-nlohmann-json
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

The staging helper builds the server and CLI, then gathers their runtime DLLs
and Wireshark data files into `dist/wirespy/`:

```bash
bash scripts/build-server-msys2.sh
# Optionally copy that folder beside a client application:
bash scripts/build-server-msys2.sh --install /c/path/to/application
```

The decoder and client may use different toolchains because they communicate
over TCP. The client library can also be built independently with MSVC by
adding `src/client` to a CMake project that supplies `nlohmann_json::nlohmann_json`.
Use `-DWIRESPY_BUILD_TESTS=OFF` to skip tests.

## Use

```text
wirespy_cli capture.pcap --server /path/to/wirespy_server
wirespy_cli capture.pcapng -Y "tcp.port == 443"
wirespy_cli capture.pcap -V 1
wirespy_cli capture.pcap --json
```

The client launcher checks an explicit server path, `WIRESPY_SERVER`, and
locations beside the client executable. It can also connect to an already
running server on localhost.

```text
wirespy_server [--port N] [--parent-pid PID] [--data-dir DIR]
```

`--port 0` chooses a free port and prints `wirespy listening on tcp/<port>`.
`--parent-pid` exits when the spawning process exits. `--data-dir` selects the
Wireshark data directory; the Windows staging helper also places data beside
the executable as required by that platform's Wireshark runtime.

The server binds to loopback (`127.0.0.1`). Each connection has its own decode
session and display filter; calls into Wireshark are serialized. See the
[protocol reference](docs/PROTOCOL.md) for framing, operations and responses.

## License

The server is licensed under **GPL-2.0-or-later**, compatible with Wireshark's
GPLv2 licensing. The separate client library, CLI and protocol specification
are licensed under **MIT**. See [LICENSE](LICENSE), [LICENSE-MIT](LICENSE-MIT)
and [LICENSING.md](LICENSING.md) for the exact scope and dependency notices.

Wireshark is a separate upstream project. Its
[licensing FAQ](https://www.wireshark.org/faq.html#derived_work) describes
requirements for applications that use its code.
