const std = @import("std");
const protocol = @import("protocol.zig");

/// Uppercase, read-aloud alphabet. `I`, `O`, `0`, and `1` are omitted.
/// Length is 32 so every random byte maps onto it without bias.
pub const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

comptime {
    if (alphabet.len != 32) @compileError("passcode alphabet must be 32 characters");
}

pub fn generate(io: std.Io) ![protocol.passcode_len]u8 {
    var raw: [protocol.passcode_len]u8 = undefined;
    try io.randomSecure(&raw);
    var code: [protocol.passcode_len]u8 = undefined;
    for (&code, raw) |*out, byte| out.* = alphabet[byte & 31];
    return code;
}

pub fn matches(expected: [protocol.passcode_len]u8, given: []const u8) bool {
    if (given.len != protocol.passcode_len) return false;
    var normalized: [protocol.passcode_len]u8 = undefined;
    for (&normalized, given) |*out, byte| out.* = std.ascii.toUpper(byte);
    return std.crypto.timing_safe.eql([protocol.passcode_len]u8, expected, normalized);
}

test "generated passcode uses the alphabet" {
    const code = try generate(std.testing.io);
    for (code) |byte| {
        try std.testing.expect(std.mem.indexOfScalar(u8, alphabet, byte) != null);
    }
}

test "passcode match is case insensitive" {
    const expected = "K7Q2M9NP".*;
    try std.testing.expect(matches(expected, "k7q2m9np"));
    try std.testing.expect(!matches(expected, "K7Q2M9NQ"));
    try std.testing.expect(!matches(expected, "K7Q2M9N"));
}
