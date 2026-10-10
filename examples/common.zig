const std = @import("std");

pub fn read(init: std.process.Init, path: []const u8, limit: usize) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(init.io, path, init.arena.allocator(), .limited(limit));
}

pub fn save(init: std.process.Init, path: []const u8, bytes: []const u8) !void {
    try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = path, .data = bytes });
}

pub fn hex(comptime len: usize, input: []const u8) ![len]u8 {
    if (input.len != len * 2) return error.InvalidHexLength;
    var bytes: [len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, input);
    return bytes;
}
