# SOT1

Server-oriented transfer, version 1. One TCP connection, one file, then the listening port closes.

The receiver generates the passcode and shows it locally. It does not send the passcode to the peer. The sender must already have it, from the person running the receiver.

The bytes on the wire are not encrypted. Use this on a network you trust, or inside a tunnel. The passcode stops a stranger who can reach the port from uploading a file. It does not hide the file from someone who can read the packets.

## Sequence

1. Receiver binds a TCP port and prints the address, port, and passcode.
2. Sender connects.
3. Sender writes the 4-byte magic `SOT1`, then an `auth` frame.
4. Receiver compares the passcode in constant time.
   - Match: `auth_ok`.
   - Anything else: `auth_reject`, then both sides close and the port closes.
5. Sender writes `meta`, then zero or more `data` frames, then `done`.
6. Receiver checks the declared size and the SHA-256, writes the file, and replies `ok` or `err`.
7. Both sides close the connection. The receiver closes the listening socket.

A second connection is refused. Start the receiver again for another file. That run gets a new passcode.

## Framing

Integers are big-endian. After the magic, every message is:

```
u32  payload length
u8   type
u8[] payload
```

`payload length` does not include the type byte. A payload larger than 16 KiB is rejected. File bytes are split into `data` frames of at most 16 KiB. The length is checked before the payload is read, so a peer cannot force a huge allocation.

| Type | Value | Payload |
| --- | --- | --- |
| `auth` | 1 | 8-byte passcode |
| `auth_ok` | 2 | empty |
| `auth_reject` | 3 | empty |
| `meta` | 4 | `u16` name length, name, `u64` file size |
| `data` | 5 | file bytes |
| `done` | 6 | 32-byte SHA-256 of the file bytes |
| `ok` | 7 | `u16` stored-name length, stored name, 32-byte SHA-256 |
| `err` | 8 | `u16` message length, message |

The SHA-256 covers only the file bytes, not the frames.

## Names

The receiver keeps the final path component and drops `..`. Characters other than letters, digits, `.`, `_`, `-`, space, `(`, and `)` become `_`. The stored name is at most 200 bytes. An existing file is not overwritten; the next free `name-2`, `name-3`, ... is used.

## Passcode

Eight characters from `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`. Comparison ignores case. A code of any other length is rejected by the sender before it connects, so a short typo does not consume the attempt. A wrong 8-character code does consume it.

## Limits

- Default maximum file size is 1 GiB.
- The accepted socket gets a 60-second send and receive timeout on platforms that support `SO_RCVTIMEO`.
- The listening backlog is 1.
