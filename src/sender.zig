const std = @import("std");
const protocol = @import("protocol.zig");
const name_mod = @import("name.zig");

pub const SendOptions = struct {
    host: []const u8,
    port: u16,
    passcode: []const u8,
    path: []const u8,
    /// Basename stored by the receiver. Defaults to the local file's basename.
    remote_name: ?[]const u8 = null,
    timeout_seconds: u32 = protocol.default_timeout_seconds,
    max_bytes: u64 = protocol.default_max_bytes,
};

pub const Sent = struct {
    /// Name the receiver actually stored. Owned by the allocator passed to `sendFile`.
    remote_name: []u8,
    bytes: u64,
    sha256: [protocol.digest_len]u8,

    pub fn deinit(self: *Sent, gpa: std.mem.Allocator) void {
        gpa.free(self.remote_name);
        self.* = undefined;
    }
};

/// Connects, presents the passcode, and uploads one file.
pub fn sendFile(io: std.Io, gpa: std.mem.Allocator, options: SendOptions) !Sent {
    if (options.passcode.len != protocol.passcode_len) return error.BadPasscode;

    const file = try std.Io.Dir.cwd().openFile(io, options.path, .{});
    defer file.close(io);
    const stat = try file.stat(io);
    if (stat.kind != .file) return error.NotAFile;
    if (stat.size > options.max_bytes) return error.FileTooLarge;

    const raw_name = options.remote_name orelse std.fs.path.basename(options.path);
    var name_buf: [protocol.max_name_len]u8 = undefined;
    const remote_name = try name_mod.sanitize(raw_name, &name_buf);

    const address = try resolve(io, options.host, options.port);
    // Zig 0.16's threaded Io panics if a connect timeout is set.
    const stream = try address.connect(io, .{
        .mode = .stream,
        .protocol = .tcp,
    });
    defer stream.close(io);
    protocol.setIoTimeout(stream.socket.handle, options.timeout_seconds);

    var read_buf: [8192]u8 = undefined;
    var write_buf: [8192]u8 = undefined;
    var net_r = stream.reader(io, &read_buf);
    var net_w = stream.writer(io, &write_buf);

    try writeAllNet(&net_w, &protocol.magic);
    try writeFrame(&net_w, .auth, options.passcode);
    try flushNet(&net_w);

    const payload = try gpa.alloc(u8, protocol.chunk_len);
    defer gpa.free(payload);

    const auth = try readFrame(&net_r, payload);
    switch (auth.kind) {
        .auth_ok => {},
        .auth_reject => return error.AuthRejected,
        .err => return error.RemoteRejected,
        else => return error.UnexpectedMessage,
    }

    var meta_buf: [2 + protocol.max_name_len + 8]u8 = undefined;
    const meta = protocol.putMeta(&meta_buf, remote_name, stat.size);
    try writeFrame(&net_w, .meta, meta);

    var file_buf: [8192]u8 = undefined;
    var file_r = file.readerStreaming(io, &file_buf);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var remaining = stat.size;
    while (remaining > 0) {
        const want: usize = @intCast(@min(remaining, payload.len));
        try readFile(&file_r, payload[0..want]);
        hasher.update(payload[0..want]);
        try writeFrame(&net_w, .data, payload[0..want]);
        remaining -= want;
    }
    var digest: [protocol.digest_len]u8 = undefined;
    hasher.final(&digest);
    try writeFrame(&net_w, .done, &digest);
    try flushNet(&net_w);

    const reply = try readFrame(&net_r, payload);
    switch (reply.kind) {
        .ok => {},
        .err => return error.RemoteRejected,
        else => return error.UnexpectedMessage,
    }
    const ok = try protocol.decodeOk(reply.payload);
    if (!std.crypto.timing_safe.eql([protocol.digest_len]u8, digest, ok.sha256)) {
        return error.ChecksumMismatch;
    }
    return .{
        .remote_name = try gpa.dupe(u8, ok.name),
        .bytes = stat.size,
        .sha256 = digest,
    };
}

fn resolve(io: std.Io, host: []const u8, port: u16) !std.Io.net.IpAddress {
    if (std.Io.net.IpAddress.parse(host, port)) |address| return address else |_| {}

    const hostname = try std.Io.net.HostName.init(host);
    var storage: [16]std.Io.net.HostName.LookupResult = undefined;
    var queue = std.Io.Queue(std.Io.net.HostName.LookupResult).init(&storage);
    try hostname.lookup(io, &queue, .{ .port = port });
    while (true) {
        const item = queue.getOne(io) catch |err| switch (err) {
            error.Closed => break,
            else => |e| return e,
        };
        switch (item) {
            .address => |address| return address,
            .canonical_name => {},
        }
    }
    return error.UnknownHostName;
}

fn readFile(file_r: *std.Io.File.Reader, buf: []u8) !void {
    file_r.interface.readSliceAll(buf) catch |err| switch (err) {
        error.EndOfStream => return error.UnexpectedEof,
        error.ReadFailed => return file_r.err orelse err,
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

fn writeAllNet(net_w: *std.Io.net.Stream.Writer, bytes: []const u8) !void {
    net_w.interface.writeAll(bytes) catch |err| switch (err) {
        error.WriteFailed => return net_w.err orelse err,
    };
}
