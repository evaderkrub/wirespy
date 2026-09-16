// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Dave Robins

// src/server/ws_compat.hpp -- the few places libwireshark's API moved
// between the 4.4 series (Debian trixie's libwireshark-dev) and 4.6 (MSYS2),
// so one source builds against both. Include AFTER <ws_version.h>.
//
//   4.4: configuration_init(arg0, namespace); ws_log_init(progname, err_cb);
//        wtap_rec has no data buffer -- the caller builds the tvbuff and
//        hands it to epan_dissect_run(edt, ft, rec, tvb, fd, cinfo);
//        packet_provider_funcs has four members.
//   4.6: configuration_init(arg0); ws_log_init(err_cb); wtap_rec carries
//        its bytes (rec.data) and epan_dissect_run takes no tvb;
//        packet_provider_funcs grew three process-info callbacks.
#pragma once

#define WIRESPY_WS_AT_LEAST(maj, min) \
    (WIRESHARK_VERSION_MAJOR > (maj) || \
     (WIRESHARK_VERSION_MAJOR == (maj) && WIRESHARK_VERSION_MINOR >= (min)))
