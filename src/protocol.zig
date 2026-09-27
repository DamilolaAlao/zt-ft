//! Framed TCP protocol.
//! The passcode is never sent by the receiver. The sender must already know it.

const std = @import("std");
const builtin = @import("builtin");

pub const magic = "SOT1".*;
pub const passcode_len = 8;
pub const digest_len = 32;
pub const max_name_len = 200;
pub const chunk_len = 16 * 1024;
pub const default_max_bytes: u64 = 1024 * 1024 * 1024;
pub const default_timeout_seconds: u32 = 60;

pub const Kind = enum(u8) {
    auth = 1,
    auth_ok = 2,
    auth_reject = 3,
    meta = 4,
    data = 5,
    done = 6,
    ok = 7,
    err = 8,
};

pub const Frame = struct {
    kind: Kind,
    payload: []u8,
};

pub const Meta = struct {
    name: []const u8,
    size: u64,
};

pub const Ok = struct {
    name: []const u8,
    sha256: [digest_len]u8,
};

pub fn writeFrame(w: *std.Io.Writer, kind: Kind, payload: []const u8) !void {
    if (payload.len > chunk_len) return error.FrameTooLarge;
    var hdr: [5]u8 = undefined;
    std.mem.writeInt(u32, hdr[0..4], @intCast(payload.len), .big);
    hdr[4] = @intFromEnum(kind);
    try w.writeAll(&hdr);
    try w.writeAll(payload);
}

pub fn readFrame(r: *std.Io.Reader, payload_buf: []u8) !Frame {
    var hdr: [5]u8 = undefined;
    try readAll(r, &hdr);
    const len = std.mem.readInt(u32, hdr[0..4], .big);
    if (len > payload_buf.len) return error.FrameTooLarge;
    const kind = std.enums.fromInt(Kind, hdr[4]) orelse return error.BadFrame;
    const payload = payload_buf[0..len];
    try readAll(r, payload);
    return .{ .kind = kind, .payload = payload };
}

fn readAll(r: *std.Io.Reader, buf: []u8) !void {
    r.readSliceAll(buf) catch |err| switch (err) {
        error.EndOfStream => return error.ConnectionClosed,
        else => |e| return e,
    };
}

pub fn putMeta(buf: []u8, name: []const u8, size: u64) []u8 {
    std.mem.writeInt(u16, buf[0..2], @intCast(name.len), .big);
    @memcpy(buf[2..][0..name.len], name);
    std.mem.writeInt(u64, buf[2 + name.len ..][0..8], size, .big);
    return buf[0 .. 2 + name.len + 8];
}

pub fn decodeMeta(payload: []const u8) error{BadFrame}!Meta {
    if (payload.len < 10) return error.BadFrame;
    const name_len = std.mem.readInt(u16, payload[0..2], .big);
    if (name_len == 0 or name_len > max_name_len) return error.BadFrame;
    const need = 2 + @as(usize, name_len) + 8;
    if (payload.len != need) return error.BadFrame;
    return .{
        .name = payload[2..][0..name_len],
        .size = std.mem.readInt(u64, payload[2 + name_len ..][0..8], .big),
    };
}

pub fn putOk(buf: []u8, name: []const u8, digest: *const [digest_len]u8) []u8 {
    std.mem.writeInt(u16, buf[0..2], @intCast(name.len), .big);
    @memcpy(buf[2..][0..name.len], name);
    @memcpy(buf[2 + name.len ..][0..digest_len], digest);
    return buf[0 .. 2 + name.len + digest_len];
}

pub fn decodeOk(payload: []const u8) error{BadFrame}!Ok {
    if (payload.len < 2 + digest_len) return error.BadFrame;
    const name_len = std.mem.readInt(u16, payload[0..2], .big);
    if (name_len == 0 or name_len > max_name_len) return error.BadFrame;
    const need = 2 + @as(usize, name_len) + digest_len;
    if (payload.len != need) return error.BadFrame;
    var digest: [digest_len]u8 = undefined;
    @memcpy(&digest, payload[2 + name_len ..][0..digest_len]);
    return .{
        .name = payload[2..][0..name_len],
        .sha256 = digest,
    };
}

pub fn putErr(buf: []u8, msg: []const u8) []u8 {
    const msg_len = @min(msg.len, 200);
    std.mem.writeInt(u16, buf[0..2], @intCast(msg_len), .big);
    @memcpy(buf[2..][0..msg_len], msg[0..msg_len]);
    return buf[0 .. 2 + msg_len];
}

/// Best-effort idle limit. The standard library sockets are blocking, so this
/// uses the platform receive and send timeouts. `0` leaves the socket unchanged.
pub fn setIoTimeout(handle: std.posix.socket_t, seconds: u32) void {
    if (seconds == 0 or builtin.os.tag == .windows) return;
    if (!@hasDecl(std.posix.SO, "RCVTIMEO")) return;
    var tv: std.posix.timeval = .{
        .sec = @intCast(seconds),
        .usec = 0,
    };
    const bytes = std.mem.asBytes(&tv);
    std.posix.setsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, bytes) catch {};
    if (@hasDecl(std.posix.SO, "SNDTIMEO")) {
        std.posix.setsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, bytes) catch {};
    }
}

test "frame round trip" {
    var storage: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&storage);
    try writeFrame(&w, .auth, "ABCDEFGH");
    var r: std.Io.Reader = .fixed(w.buffered());
    var payload: [32]u8 = undefined;
    const frame = try readFrame(&r, &payload);
    try std.testing.expectEqual(Kind.auth, frame.kind);
    try std.testing.expectEqualStrings("ABCDEFGH", frame.payload);
}

test "meta round trip" {
    var buf: [64]u8 = undefined;
    const encoded = putMeta(&buf, "notes.txt", 42);
    const meta = try decodeMeta(encoded);
    try std.testing.expectEqualStrings("notes.txt", meta.name);
    try std.testing.expectEqual(@as(u64, 42), meta.size);
}
