<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 Dave Robins -->

# wirespy protocol

TCP, `127.0.0.1`, length-prefixed. Every integer is big-endian. One
*decode session* per connection: frame numbering, the time reference and
the display filter are per connection.

## Framing

Request:

```
[total_len : u32][json_len : u32][json header : json_len bytes][frame bytes : the rest]
```

Response:

```
[total_len : u32][json : total_len bytes]
```

A request body larger than 64 MiB closes the connection.

## Ops

The header's `op` selects one of these (default `decode`); `id` (integer) is
echoed back.

### `decode`

| Field | Meaning |
|---|---|
| `link_type` | libpcap DLT number, or a name: `EN10MB` (default), `NULL`, `RAW` (101), `IEEE802_11`, `LINUX_SLL`, `IPV4`, `IPV6`, `CAN_SOCKETCAN`, `USER0` |
| `ts_sec`, `ts_nsec` | the frame's timestamp; absent = untimed |
| `tree` | build the details tree (default true; `format: "columns"` turns it off) |
| `columns` | fill Wireshark's summary columns (default false, true for `format: "columns"`) |
| `color` | evaluate the colouring rules (default false) |
| `format` | `json` (default) / `text` (an indented dump) / `columns` |
| `transient` | do not advance the session: frame numbering, the time reference and the previous frame are untouched (a details pane re-dissecting one packet) |
| `frame_number`, `ref_ts_sec`/`ref_ts_nsec`, `prev_ts_sec`/`prev_ts_nsec` | with `transient`: the number this frame had in the in-order pass, and the timestamps of the reference (first) and previous frames, so relative and delta times come out the same |

Reply:

```json
{"id": 7, "ok": true, "frame_number": 7, "format": "json", "match": true,
 "columns": ["7", "0.071799993", "192.168.1.10", "192.168.1.1", "DNS", "71", "Standard query 0xbeef A example.com"],
 "color": {"name": "UDP", "fg": "#12272e", "bg": "#daeeff"},
 "decode": {"name": "frame", "showname": "", "value": "", "pos": 0, "size": 0,
            "children": [{"name": "eth", "showname": "Ethernet II, Src: ...", "value": "...hex...", "pos": 0, "size": 14, "children": [...]}, ...]}}
```

`match` is the session's display filter verdict (true when none is set).
`color` is present only when a rule matched. A dissection that could not run
answers `{"ok": false, "error": {"code": "BAD_FRAME" | "UNKNOWN_LINK_TYPE", "message": "..."}}`.

### `set_filter`

`{"op": "set_filter", "filter": "tcp.port == 80"}` compiles a Wireshark
display filter for every later `decode` (empty clears). A filter that does
not compile answers `{"ok": false, "error": {"code": "BAD_FILTER", "message": "<Wireshark's own message>"}}`
and the previous filter stays.

### `reset`

Frame numbering and the time reference start over (a new capture).

### `info`

```json
{"ok": true, "server": "wirespy", "wireshark": "4.4.18", "columns": ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"],
 "link_types": ["EN10MB", ...], "colors": true, "filter": ""}
```

`colors` is whether the colouring rules loaded (the `colorfilters` file was
found). `columns` are the profile's column titles, in the order `decode`
fills them.

## Threading

Connections are served on their own threads, but libwireshark is
single-threaded: every op takes one process-wide turn. Two clients
interleave; they never run at once.
