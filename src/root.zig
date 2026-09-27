//! Server-oriented file transfer.
//!
//! The receiver opens a TCP port, generates a passcode, and waits for one file.
//! The sender connects with that passcode. After the attempt, the port closes.

pub const protocol = @import("protocol.zig");
pub const listen = @import("receiver.zig").listen;
pub const Listener = @import("receiver.zig").Listener;
pub const ListenOptions = @import("receiver.zig").ListenOptions;
pub const Received = @import("receiver.zig").Received;
pub const sendFile = @import("sender.zig").sendFile;
pub const SendOptions = @import("sender.zig").SendOptions;
pub const Sent = @import("sender.zig").Sent;
pub const sanitizeName = @import("name.zig").sanitize;
pub const generatePasscode = @import("passcode.zig").generate;
pub const passcodeAlphabet = @import("passcode.zig").alphabet;

test {
    _ = @import("protocol.zig");
    _ = @import("passcode.zig");
    _ = @import("name.zig");
    _ = @import("transfer_test.zig");
}
