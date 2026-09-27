const std = @import("std");
const protocol = @import("protocol.zig");
const receiver = @import("receiver.zig");
const sender = @import("sender.zig");

const Job = struct {
    listener: *receiver.Listener,
    gpa: std.mem.Allocator,
    received: ?receiver.Received = null,
    failed: ?anyerror = null,
};

fn acceptJob(job: *Job) void {
    job.received = job.listener.acceptFile(job.gpa) catch |err| {
        job.failed = err;
        return;
    };
}

test "one file transfers and the port closes" {
    const gpa = std.heap.smp_allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(std.testing.io, &root_buf);
    const root = root_buf[0..root_len];

    const payload = try gpa.alloc(u8, protocol.chunk_len + 3);
    defer gpa.free(payload);
    for (payload, 0..) |*byte, i| byte.* = @truncate(i);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "payload.bin", .data = payload });

    const in_path = try std.fs.path.join(gpa, &.{ root, "payload.bin" });
    defer gpa.free(in_path);
    const out_dir = try std.fs.path.join(gpa, &.{ root, "out" });
    defer gpa.free(out_dir);

    var listener = try receiver.listen(io, .{
        .bind = "127.0.0.1",
        .port = 0,
        .save_dir = out_dir,
        .timeout_seconds = 10,
    });
    const port = listener.bound.getPort();
    var job = Job{ .listener = &listener, .gpa = gpa };
    const thread = try std.Thread.spawn(.{}, acceptJob, .{&job});

    var sent = try sender.sendFile(io, gpa, .{
        .host = "127.0.0.1",
        .port = port,
        .passcode = &listener.passcode,
        .path = in_path,
        .remote_name = "../notes.bin",
        .timeout_seconds = 10,
    });
    defer sent.deinit(gpa);
    thread.join();

    try std.testing.expect(job.failed == null);
    var received = job.received orelse return error.TestUnexpectedResult;
    defer received.deinit(gpa);
    try std.testing.expectEqualStrings("notes.bin", received.name);
    try std.testing.expectEqualStrings("notes.bin", sent.remote_name);
    try std.testing.expectEqual(payload.len, received.bytes);
    try std.testing.expectEqualSlices(u8, &sent.sha256, &received.sha256);

    const body = try gpa.alloc(u8, payload.len + 1);
    defer gpa.free(body);
    var saved = try std.Io.Dir.openDirAbsolute(io, out_dir, .{});
    defer saved.close(io);
    const got = try saved.readFile(io, received.name, body);
    try std.testing.expectEqualSlices(u8, payload, got);

    const again = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    try std.testing.expectError(error.ConnectionRefused, again.connect(io, .{
        .mode = .stream,
        .protocol = .tcp,
    }));
}

test "wrong passcode is rejected once and the port closes" {
    const gpa = std.heap.smp_allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(std.testing.io, &root_buf);
    const root = root_buf[0..root_len];
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "tiny.txt", .data = "x" });
    const in_path = try std.fs.path.join(gpa, &.{ root, "tiny.txt" });
    defer gpa.free(in_path);
    const out_dir = try std.fs.path.join(gpa, &.{ root, "out" });
    defer gpa.free(out_dir);

    var listener = try receiver.listen(io, .{
        .bind = "127.0.0.1",
        .port = 0,
        .save_dir = out_dir,
        .timeout_seconds = 10,
    });
    const port = listener.bound.getPort();
    var job = Job{ .listener = &listener, .gpa = gpa };
    const thread = try std.Thread.spawn(.{}, acceptJob, .{&job});

    try std.testing.expectError(error.AuthRejected, sender.sendFile(io, gpa, .{
        .host = "127.0.0.1",
        .port = port,
        .passcode = "WRONGPAS",
        .path = in_path,
        .timeout_seconds = 10,
    }));
    thread.join();
    try std.testing.expect(job.received == null);
    try std.testing.expectEqual(error.BadPasscode, job.failed.?);

    const again = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    try std.testing.expectError(error.ConnectionRefused, again.connect(io, .{
        .mode = .stream,
        .protocol = .tcp,
    }));
}
