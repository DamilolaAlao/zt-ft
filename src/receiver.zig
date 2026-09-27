const std = @import("std");
const protocol = @import("protocol.zig");
const passcode = @import("passcode.zig");
const name_mod = @import("name.zig");

pub const ListenOptions = struct {
    /// Numeric address. `0.0.0.0` accepts every IPv4 interface.
    bind: []const u8 = "0.0.0.0",
    /// `0` lets the OS pick an ephemeral port. Read it from `Listener.bound`.
    port: u16 = 0,
    save_dir: []const u8 = "received",
    max_bytes: u64 = protocol.default_max_bytes,
    /// Idle limit on the accepted socket, in seconds. `0` disables it.
    timeout_seconds: u32 = protocol.default_timeout_seconds,
};

pub const Received = struct {
    /// Basename written inside `save_dir`. Owned by `allocator` passed to `acceptFile`.
    name: []u8,
    bytes: u64,
    sha256: [protocol.digest_len]u8,

    pub fn deinit(self: *Received, gpa: std.mem.Allocator) void {
        gpa.free(self.name);
        self.* = undefined;
    }
};

pub const Listener = struct {
    io: std.Io,
    server: std.Io.net.Server,
    passcode: [protocol.passcode_len]u8,
    bound: std.Io.net.IpAddress,
    save_dir: []const u8,
    max_bytes: u64,
    timeout_seconds: u32,
    closed: bool = false,

    /// Accepts one connection, writes one file, then closes the listening port.
    /// A rejected passcode also closes the port. Call `close` if this is never called.
    pub fn acceptFile(self: *Listener, gpa: std.mem.Allocator) !Received {
        defer self.close();
        const stream = try self.server.accept(self.io);
        defer stream.close(self.io);
        protocol.setIoTimeout(stream.socket.handle, self.timeout_seconds);
        return transfer(self, gpa, stream);
    }

    pub fn close(self: *Listener) void {
        if (self.closed) return;
        self.closed = true;
        self.server.deinit(self.io);
    }
};

/// Binds a port and generates a passcode. The passcode stays on this machine.
pub fn listen(io: std.Io, options: ListenOptions) !Listener {
    try std.Io.Dir.cwd().createDirPath(io, options.save_dir);
    const code = try passcode.generate(io);
    const requested = try std.Io.net.IpAddress.parse(options.bind, options.port);
    const server = try requested.listen(io, .{
        .reuse_address = true,
        .kernel_backlog = 1,
    });
    return .{
        .io = io,
        .server = server,
        .passcode = code,
        .bound = server.socket.address,
        .save_dir = options.save_dir,
        .max_bytes = options.max_bytes,
        .timeout_seconds = options.timeout_seconds,
    };
}

fn transfer(self: *Listener, gpa: std.mem.Allocator, stream: std.Io.net.Stream) !Received {
    var read_buf: [8192]u8 = undefined;
    var write_buf: [8192]u8 = undefined;
    var net_r = stream.reader(self.io, &read_buf);
    var net_w = stream.writer(self.io, &write_buf);

    var magic: [4]u8 = undefined;
    try readExact(&net_r, &magic);
    if (!std.mem.eql(u8, &magic, &protocol.magic)) return error.BadMagic;

    const payload = try gpa.alloc(u8, protocol.chunk_len);
    defer gpa.free(payload);

    const auth = try readFrame(&net_r, payload);
    if (auth.kind != .auth or !passcode.matches(self.passcode, auth.payload)) {
        try writeFrame(&net_w, .auth_reject, &.{});
        try flushNet(&net_w);
        return error.BadPasscode;
    }
    try writeFrame(&net_w, .auth_ok, &.{});
    try flushNet(&net_w);

    const meta_frame = try readFrame(&net_r, payload);
    if (meta_frame.kind != .meta) return error.UnexpectedMessage;
    const meta = protocol.decodeMeta(meta_frame.payload) catch {
        sendErr(&net_w, "bad meta");
        return error.BadFrame;
    };
    if (meta.size > self.max_bytes) {
        sendErr(&net_w, "file too large");
        return error.FileTooLarge;
    }

    var name_buf: [protocol.max_name_len]u8 = undefined;
    const safe = name_mod.sanitize(meta.name, &name_buf) catch {
        sendErr(&net_w, "bad name");
        return error.BadName;
    };

    var dir = try openSave(self.io, self.save_dir);
    defer dir.close(self.io);

    var saved_name: ?[]u8 = null;
    errdefer if (saved_name) |created| {
        dir.deleteFile(self.io, created) catch {};
        gpa.free(created);
    };

    const opened = try openUnique(gpa, self.io, dir, safe);
    saved_name = opened.name;
    defer opened.file.close(self.io);

    var file_buf: [8192]u8 = undefined;
    var file_w = opened.file.writerStreaming(self.io, &file_buf);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var remaining = meta.size;

    while (remaining > 0) {
        const frame = try readFrame(&net_r, payload);
        if (frame.kind != .data or frame.payload.len == 0) {
            sendErr(&net_w, "bad data");
            return error.UnexpectedMessage;
        }
        if (@as(u64, frame.payload.len) > remaining) {
            sendErr(&net_w, "size mismatch");
            return error.SizeMismatch;
        }
        try writeAllFile(&file_w, frame.payload);
        hasher.update(frame.payload);
        remaining -= frame.payload.len;
    }
    try flushFile(&file_w);

    const done = try readFrame(&net_r, payload);
    if (done.kind != .done or done.payload.len != protocol.digest_len) {
        sendErr(&net_w, "bad checksum");
        return error.BadFrame;
    }
    var expected: [protocol.digest_len]u8 = undefined;
    @memcpy(&expected, done.payload[0..protocol.digest_len]);
    var actual: [protocol.digest_len]u8 = undefined;
    hasher.final(&actual);
    if (!std.crypto.timing_safe.eql([protocol.digest_len]u8, expected, actual)) {
        sendErr(&net_w, "checksum mismatch");
        return error.ChecksumMismatch;
    }

    var ok_buf: [2 + protocol.max_name_len + protocol.digest_len]u8 = undefined;
    const ok_payload = protocol.putOk(&ok_buf, opened.name, &actual);
    try writeFrame(&net_w, .ok, ok_payload);
    try flushNet(&net_w);

    saved_name = null;
    return .{
        .name = opened.name,
        .bytes = meta.size,
        .sha256 = actual,
    };
}

const Opened = struct {
    file: std.Io.File,
    name: []u8,
};

fn openUnique(gpa: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, base: []const u8) !Opened {
    var n: usize = 1;
    while (n <= 100) : (n += 1) {
        const candidate = try suffixed(gpa, base, n);
        if (dir.createFile(io, candidate, .{ .exclusive = true })) |file| {
            return .{ .file = file, .name = candidate };
        } else |err| switch (err) {
            error.PathAlreadyExists => {
                gpa.free(candidate);
                continue;
            },
            else => {
                gpa.free(candidate);
                return err;
            },
        }
    }
    return error.NameExhausted;
}

fn suffixed(gpa: std.mem.Allocator, base: []const u8, n: usize) ![]u8 {
    if (n <= 1) return gpa.dupe(u8, base);
    const ext = std.fs.path.extension(base);
    const stem = base[0 .. base.len - ext.len];
    return std.fmt.allocPrint(gpa, "{s}-{d}{s}", .{ stem, n, ext });
}

fn openSave(io: std.Io, path: []const u8) !std.Io.Dir {
    if (std.fs.path.isAbsolute(path)) return std.Io.Dir.openDirAbsolute(io, path, .{});
    return std.Io.Dir.cwd().openDir(io, path, .{});
}

fn readExact(net_r: *std.Io.net.Stream.Reader, buf: []u8) !void {
    net_r.interface.readSliceAll(buf) catch |err| switch (err) {
        error.EndOfStream => return error.ConnectionClosed,
        error.ReadFailed => return net_r.err orelse err,
    };
}

fn readFrame(net_r: *std.Io.net.Stream.Reader, payload: []u8) !protocol.Frame {
    return protocol.readFrame(&net_r.interface, payload) catch |err| switch (err) {
        error.ReadFailed => return net_r.err orelse err,
        else => |e| return e,
    };
}

fn flushNet(net_w: *std.Io.net.Stream.Writer) !void {
    net_w.interface.flush() catch |err| switch (err) {
        error.WriteFailed => return net_w.err orelse err,
    };
}

fn writeFrame(net_w: *std.Io.net.Stream.Writer, kind: protocol.Kind, payload: []const u8) !void {
    protocol.writeFrame(&net_w.interface, kind, payload) catch |err| switch (err) {
        error.WriteFailed => return net_w.err orelse err,
        else => |e| return e,
    };
}

fn writeAllFile(file_w: *std.Io.File.Writer, bytes: []const u8) !void {
    file_w.interface.writeAll(bytes) catch |err| switch (err) {
        error.WriteFailed => return file_w.err orelse err,
    };
}

fn flushFile(file_w: *std.Io.File.Writer) !void {
    file_w.interface.flush() catch |err| switch (err) {
        error.WriteFailed => return file_w.err orelse err,
    };
}

fn sendErr(net_w: *std.Io.net.Stream.Writer, msg: []const u8) void {
    var buf: [202]u8 = undefined;
    const payload = protocol.putErr(&buf, msg);
    writeFrame(net_w, .err, payload) catch return;
    net_w.interface.flush() catch {};
}
