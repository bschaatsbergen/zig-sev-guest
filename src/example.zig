const std = @import("std");
const client = @import("client.zig");

pub fn main() !void {
    var device = try client.Device.open();
    defer device.close();

    std.debug.print("Opened /dev/sev-guest\n", .{});
}
