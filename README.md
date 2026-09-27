# sot

File transfer. The receiver opens a TCP port and prints a passcode. The sender connects with that passcode, uploads one file, and the port closes.

Version 0.1.0. Requires Zig 0.16. Licensed under the [MIT License](LICENSE).

The passcode is shown only on the receiver. Share the address, port, and passcode yourself. The wire format is not encrypted; use a trusted network or a tunnel. The frame layout is in [docs/protocol.md](docs/protocol.md). What this does and does not protect is in [SECURITY.md](SECURITY.md).

## Layout

```
.
├── build.zig
├── build.zig.zon
├── LICENSE
├── README.md
├── CONTRIBUTING.md
├── SECURITY.md
├── docs
│   └── protocol.md
└── src
    ├── root.zig          public SDK
    ├── main.zig          `sot` command
    ├── protocol.zig      SOT1 frames
    ├── passcode.zig      8-character code
    ├── name.zig          safe basename
    ├── receiver.zig      listen, accept one file, close
    ├── sender.zig        connect and upload
    └── transfer_test.zig
```

`src/root.zig` is the module other programs import as `sot`. The command in `src/main.zig` is a thin wrapper around that module.

## Build

Requires Zig 0.16.

```sh
zig build
zig build test
```

The binary is `zig-out/bin/sot`.

## Command

Receiver, on the machine that will store the file:

```sh
zig build run -- receive --bind 0.0.0.0 --dir received
```

It prints a line like `listening 0.0.0.0:54321` and `passcode K7Q2M9NP`, then waits. `0.0.0.0` means every IPv4 interface; give the sender a reachable address and that port.

Sender:

```sh
zig build run -- send 192.168.1.20 54321 K7Q2M9NP ./notes.txt
```

Passcodes are case-insensitive. A wrong code closes the port. Run `receive` again for another file.

```
sot receive [--bind 0.0.0.0] [--port 0] [--dir received] [--max-mib 1024] [--timeout 60]
sot send <host> <port> <passcode> <file> [--name remote-name]
```

`--port 0` lets the OS pick the port. `--timeout` is the idle limit in seconds on the accepted socket.

## Library

```zig
const std = @import("std");
const sot = @import("sot");

pub fn main(init: std.process.Init) !void {
    var listener = try sot.listen(init.io, .{
        .bind = "0.0.0.0",
        .save_dir = "received",
    });
    // Show listener.bound and listener.passcode, then block.
    var received = try listener.acceptFile(init.gpa);
    defer received.deinit(init.gpa);
}

pub fn upload(init: std.process.Init) !void {
    var sent = try sot.sendFile(init.io, init.gpa, .{
        .host = "127.0.0.1",
        .port = 54321,
        .passcode = "K7Q2M9NP",
        .path = "notes.txt",
    });
    defer sent.deinit(init.gpa);
}
```

`listen` returns before it blocks, so the passcode can be shown first. `acceptFile` takes one connection and then closes the listening socket, including when the passcode is wrong. Call `listener.close()` if you never accept.

Fetch the package, then in `build.zig`:

```zig
const sot_dep = b.dependency("sot", .{});
exe.root_module.addImport("sot", sot_dep.module("sot"));
```

```sh
zig fetch --save <repository-url>
```

The package name and the import name are both `sot`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). `zig build test` is the check that must pass.
