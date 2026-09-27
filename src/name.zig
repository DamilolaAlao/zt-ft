const std = @import("std");
const protocol = @import("protocol.zig");

/// Keeps the final path component and replaces characters that are unsafe in a file name.
/// `out` must be at least `protocol.max_name_len` bytes.
pub fn sanitize(input: []const u8, out: []u8) error{ BadName, NoSpaceLeft }![]u8 {
    if (out.len < protocol.max_name_len) return error.NoSpaceLeft;
    const component = lastComponent(input);
    if (component.len == 0 or component.len > 255) return error.BadName;
    if (std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, "..")) return error.BadName;

    var len: usize = 0;
    var meaningful = false;
    for (component) |byte| {
        if (len == protocol.max_name_len) break;
        const safe = switch (byte) {
            'a'...'z', 'A'...'Z', '0'...'9', '.', '_', '-', ' ', '(', ')' => byte,
            else => '_',
        };
        out[len] = safe;
        len += 1;
        if (safe != '.' and safe != '_' and safe != '-' and safe != ' ') meaningful = true;
    }
    if (!meaningful) return error.BadName;

    var name = out[0..len];
    if (isReserved(name)) {
        if (name.len + 2 > protocol.max_name_len) return error.BadName;
        std.mem.copyBackwards(u8, out[2 .. name.len + 2], name);
        out[0] = 'f';
        out[1] = '_';
        name = out[0 .. name.len + 2];
    }
    return name;
}

fn lastComponent(input: []const u8) []const u8 {
    var start: usize = 0;
    for (input, 0..) |byte, i| {
        if (byte == '/' or byte == '\\') start = i + 1;
    }
    return input[start..];
}

fn isReserved(name: []const u8) bool {
    const ext = std.fs.path.extension(name);
    const stem = name[0 .. name.len - ext.len];
    if (stem.len == 0 or stem.len > 4) return false;
    var upper: [4]u8 = undefined;
    for (stem, 0..) |byte, i| upper[i] = std.ascii.toUpper(byte);
    const token = upper[0..stem.len];
    const reserved = [_][]const u8{ "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "LPT1", "LPT2", "LPT3" };
    for (reserved) |item| if (std.mem.eql(u8, token, item)) return true;
    return false;
}

test "sanitize drops directories" {
    var buf: [protocol.max_name_len]u8 = undefined;
    const name = try sanitize("../secret/notes.txt", &buf);
    try std.testing.expectEqualStrings("notes.txt", name);
    const win = try sanitize("..\\..\\report.pdf", &buf);
    try std.testing.expectEqualStrings("report.pdf", win);
}

test "sanitize rejects dot segments" {
    var buf: [protocol.max_name_len]u8 = undefined;
    try std.testing.expectError(error.BadName, sanitize("..", &buf));
    try std.testing.expectError(error.BadName, sanitize("foo/..", &buf));
    try std.testing.expectError(error.BadName, sanitize("", &buf));
}

test "sanitize replaces odd characters" {
    var buf: [protocol.max_name_len]u8 = undefined;
    const name = try sanitize("weird:name?.txt", &buf);
    try std.testing.expectEqualStrings("weird_name_.txt", name);
}
