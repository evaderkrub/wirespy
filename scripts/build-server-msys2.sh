#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2026 Dave Robins

# Builds wirespy_server on Windows with MSYS2's MinGW-w64 Wireshark and
# stages a self-contained folder that a client application can spawn:
#
#     <out>/wirespy/wirespy_server.exe      + every DLL it needs (ldd)
#     <out>/wirespy/share/wireshark/        Wireshark's data files (colouring
#                                           rules, display-filter macros, ...)
#
# Run it from an MSYS2 **MINGW64** shell (not MSYS, not UCRT64):
#
#     pacman -S --needed mingw-w64-x86_64-toolchain mingw-w64-x86_64-cmake \
#                        mingw-w64-x86_64-ninja mingw-w64-x86_64-wireshark \
#                        mingw-w64-x86_64-nlohmann-json
#     scripts/build-server-msys2.sh [-o <out>] [--install <client exe dir>]
#
# The default <out> is dist/ under the repo. --install copies <out>/wirespy
# beside the client executable. Applications can also copy a staged folder
# during their own build.
#
# The server uses the MSYS2 Wireshark development package. It runs in a
# separate process, so its toolchain need not match the client's.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="$PWD/dist"; INSTALL=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o|--out) OUT="$2"; shift 2;;
        --install) INSTALL="$2"; shift 2;;
        *) echo "unknown arg $1" >&2; exit 2;;
    esac
done
case "${MSYSTEM:-}" in MINGW64) ;; *) echo "run this from an MSYS2 MINGW64 shell (MSYSTEM=$MSYSTEM)" >&2; exit 2;; esac
if ! pkg-config --exists wireshark; then
    echo "no wireshark.pc: pacman -S mingw-w64-x86_64-wireshark" >&2; exit 2
fi

BUILD="$PWD/build-msys2"
# cmake is a NATIVE program: hand it Windows paths. MSYS2 converts most
# POSIX arguments itself, but explicit conversion also handles unusual
# directory names consistently.
cmake -S "$(cygpath -m "$PWD")" -B "$(cygpath -m "$BUILD")" -G Ninja -DCMAKE_BUILD_TYPE=Release -DWIRESPY_BUILD_TESTS=OFF
cmake --build "$(cygpath -m "$BUILD")" --target wirespy_server wirespy_cli

STAGE="$OUT/wirespy"
rm -rf "$STAGE"
mkdir -p "$STAGE/share/wireshark"
cp "$BUILD/src/server/wirespy_server.exe" "$BUILD/src/cli/wirespy_cli.exe" "$STAGE/"
cp LICENSE LICENSE-MIT LICENSING.md "$STAGE/"
mkdir -p "$STAGE/licenses/wireshark"
cp "$(pkg-config --variable=prefix wireshark)/share/licenses/wireshark/COPYING" \
    "$STAGE/licenses/wireshark/"

# Every DLL the server loads from /mingw64 (system DLLs are left alone).
copy_deps() {
    ldd "$1" | awk '/=> \/mingw64\//{print $3}' | sort -u | while read -r dll; do
        if [ ! -e "$STAGE/$(basename "$dll")" ]; then
            cp "$dll" "$STAGE/"
            copy_deps "$dll"
        fi
    done
}
copy_deps "$STAGE/wirespy_server.exe"
copy_deps "$STAGE/wirespy_cli.exe"
# libwireshark dlopen()s nothing it needs here (plugins are not loaded), so
# ldd's closure is the whole set.

# Wireshark's data files: the colouring rules and filter macros the server
# reads through --data-dir (the launcher passes it when share/wireshark
# sits beside the exe).
DATA="$(pkg-config --variable=prefix wireshark)/share/wireshark"
for f in colorfilters dfilters dfilter_macros cfilters manuf services enterprises.tsv wka; do
    [ -e "$DATA/$f" ] && cp "$DATA/$f" "$STAGE/share/wireshark/"
done
[ -d "$DATA/profiles" ] && cp -r "$DATA/profiles" "$STAGE/share/wireshark/"
# ... and the same files BESIDE the exe: on Windows libwireshark's data
# directory is the program's own directory and WIRESHARK_DATA_DIR is not
# consulted at all (wsutil/filesystem.c), so --data-dir cannot redirect it;
# a missing global colorfilters file counts as "loaded, empty" and every
# packet comes back uncoloured (found 2026-09-10, 4.6.5).
cp "$STAGE/share/wireshark/"* "$STAGE/" 2>/dev/null || true
[ -d "$DATA/profiles" ] && cp -r "$DATA/profiles" "$STAGE/"

echo "staged: $STAGE"
ls "$STAGE" | head -40
if [ -n "$INSTALL" ]; then
    mkdir -p "$INSTALL/wirespy"
    cp -r "$STAGE/." "$INSTALL/wirespy/"
    echo "installed beside $INSTALL"
fi
