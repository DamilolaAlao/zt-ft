const std = @import("std");
const sot = @import("sot");

const usage =
    \\sot receive [--bind 0.0.0.0] [--port 0] [--dir received] [--max-mib 1024] [--timeout 60]
    \\sot send <host> <port> <passcode> <file> [--name remote-name]
    \\
    \\The receiver prints a passcode and waits for one file. Share the address,
    \\port, and passcode out of band. The listening port closes after that attempt.
    \\
;

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        if (err == error.BadUsage) {
            std.debug.print("{s}", .{usage});
        } else if (err == error.AuthRejected or err == error.BadPasscode) {
            std.debug.print("error: passcode rejected; the receiver has closed the port\n", .{});
        } else {
            std.debug.print("error: {s}\n", .{@errorName(err)});
        }
        std.process.exit(1);
    };
}

fn run(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2) return error.BadUsage;
    if (std.mem.eql(u8, args[1], "receive")) {
        try cmdReceive(init, args);
    } else if (std.mem.eql(u8, args[1], "send")) {
        try cmdSend(init, args);
    } else return error.BadUsage;
}

fn cmdReceive(init: std.process.Init, args: []const [:0]const u8) !void {
    var bind: []const u8 = "0.0.0.0";
    var port: u16 = 0;
    var dir: []const u8 = "received";
    var max_mib: u64 = 1024;
    var timeout: u32 = sot.protocol.default_timeout_seconds;
    var i: usize = 2;
    while (i < args.len) {
        const flag = args[i];
        i += 1;
        if (std.mem.eql(u8, flag, "--bind")) {
            bind = try take(args, &i);
        } else if (std.mem.eql(u8, flag, "--port")) {
            port = std.fmt.parseInt(u16, try take(args, &i), 10) catch return error.BadUsage;
        } else if (std.mem.eql(u8, flag, "--dir")) {
            dir = try take(args, &i);
        } else if (std.mem.eql(u8, flag, "--max-mib")) {
            max_mib = std.fmt.parseInt(u64, try take(args, &i), 10) catch return error.BadUsage;
        } else if (std.mem.eql(u8, flag, "--timeout")) {
            timeout = std.fmt.parseInt(u32, try take(args, &i), 10) catch return error.BadUsage;
        } else return error.BadUsage;
    }

    var listener = try sot.listen(init.io, .{
        .bind = bind,
        .port = port,
        .save_dir = dir,
        .max_bytes = std.math.mul(u64, max_mib, 1024 * 1024) catch return error.BadUsage,
        .timeout_seconds = timeout,
    });
    try printOut(init.io, "listening {f}\n", .{listener.bound});
    try printOut(init.io, "passcode  {s}\n", .{listener.passcode[0..]});
    try printOut(init.io, "save dir  {s}\n", .{dir});
    if (isUnspecified(listener.bound)) {
        try printOut(init.io, "tell the sender this machine's reachable address, the port, and the passcode\n", .{});
    }
    try printOut(init.io, "waiting for one file\n", .{});

    var received = try listener.acceptFile(init.gpa);
    defer received.deinit(init.gpa);
    const hex = std.fmt.bytesToHex(received.sha256, .lower);
    try printOut(init.io, "saved     {s}/{s}\n", .{ dir, received.name });
    try printOut(init.io, "bytes     {d}\n", .{received.bytes});
    try printOut(init.io, "sha256    {s}\n", .{hex[0..]});
    try printOut(init.io, "port closed\n", .{});
}

fn cmdSend(init: std.process.Init, args: []const [:0]const u8) !void {
    if (args.len < 6) return error.BadUsage;
    const host = args[2];
    const port = std.fmt.parseInt(u16, args[3], 10) catch return error.BadUsage;
    const code = args[4];
    const path = args[5];
    var remote_name: ?[]const u8 = null;
    var i: usize = 6;
    while (i < args.len) {
        const flag = args[i];
        i += 1;
        if (std.mem.eql(u8, flag, "--name")) {
            remote_name = try take(args, &i);
        } else return error.BadUsage;
    }

    var sent = try sot.sendFile(init.io, init.gpa, .{
        .host = host,
        .port = port,
        .passcode = code,
        .path = path,
        .remote_name = remote_name,
    });
    defer sent.deinit(init.gpa);
    const hex = std.fmt.bytesToHex(sent.sha256, .lower);
    try printOut(init.io, "stored    {s}\n", .{sent.remote_name});
    try printOut(init.io, "bytes     {d}\n", .{sent.bytes});
    try printOut(init.io, "sha256    {s}\n", .{hex[0..]});
}

fn take(args: []const [:0]const u8, i: *usize) ![:0]const u8 {
    if (i.* >= args.len) return error.BadUsage;
    const value = args[i.*];
    i.* += 1;
    return value;
}

fn isUnspecified(address: std.Io.net.IpAddress) bool {
    return switch (address) {
        .ip4 => |ip4| ip4.bytes[0] == 0 and ip4.bytes[1] == 0 and ip4.bytes[2] == 0 and ip4.bytes[3] == 0,
        .ip6 => |ip6| std.mem.eql(u8, &ip6.bytes, &[_]u8{0} ** 16),
    };
}

fn printOut(io: std.Io, comptime fmt: []const u8, args: anytype) !void {
    var buf: [512]u8 = undefined;
    var file_writer = std.Io.File.stdout().writerStreaming(io, &buf);
    try file_writer.interface.print(fmt, args);
    try file_writer.interface.flush();
}
