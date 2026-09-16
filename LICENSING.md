# Licensing

Copyright (c) 2026 Dave Robins.

## Project license scope

Unless a file states otherwise, this project is free software: you may
redistribute it and/or modify it under the GNU General Public License as
published by the Free Software Foundation, either version 2 of the License,
or (at your option) any later version. The SPDX identifier is
`GPL-2.0-or-later`; the full license is in [LICENSE](LICENSE).

The following parts are instead licensed under the [MIT License](LICENSE-MIT):

- All files under `src/client/`, including their CMake build file.
- All files under `src/cli/`, including their CMake build file.
- `docs/PROTOCOL.md`.

The MIT client implements the documented TCP protocol and does not link
Wireshark libraries. The server links Wireshark and remains a separate GPL
program. These licenses grant rights only to wirespy's own code; they do not
relicense Wireshark or other dependencies.

The software is provided without warranty, including without any implied
warranty of merchantability or fitness for a particular purpose. See the
applicable license text for details.

## Dependencies

Dependencies are obtained from the system or fetched during configuration;
their source and binaries are not vendored in this repository.

| Dependency | Use | Upstream license information |
| --- | --- | --- |
| Wireshark (`libwireshark`, `wiretap`, `wsutil`) | Server decoding and runtime | [Wireshark COPYING](https://gitlab.com/wireshark/wireshark/-/blob/master/COPYING) and [licensing FAQ](https://www.wireshark.org/faq.html#derived_work) |
| GLib | Server runtime dependency | [GLib copying information](https://gitlab.gnome.org/GNOME/glib/-/blob/main/COPYING) |
| nlohmann/json | JSON protocol encoding and decoding | [MIT license](https://github.com/nlohmann/json/blob/develop/LICENSE.MIT) |
| Catch2 | Tests only | [Boost Software License 1.0](https://github.com/catchorg/Catch2/blob/devel/LICENSE.txt) |

## Binary distributions

The MSYS2 staging script produces a local runtime folder. Publishing that
folder is a separate distribution step: retain the relevant license and
copyright notices and provide the corresponding source required by the GPL
and any other included licenses. Include the source and build instructions
for the exact wirespy, Wireshark and dependency versions shipped. A generic
link to an upstream project's latest branch is not a substitute for that
corresponding source.

See [GNU GPL version 2](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html)
for the full distribution terms. This repository publishes source code;
it does not include prebuilt runtime bundles.
