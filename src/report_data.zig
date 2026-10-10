const std = @import("std");
const abi = @import("abi.zig");

/// Zero-pad up to 64 bytes. This does not hash input or generate a fresh nonce.
pub fn makeReportData(input: []const u8) ![64]u8 {
    if (input.len > 64) {
        return error.InputTooLong;
    }

    var data: [64]u8 = @splat(0);

    for (input, 0..) |byte, index| {
        data[index] = byte;
    }

    return data;
}

test "report data holds 64 bytes" {
    const input = [_]u8{ 42, 10 };
    const report_data = try makeReportData(&input);

    try std.testing.expectEqual(@as(usize, 64), report_data.len);
    try std.testing.expectEqual(@as(u8, 42), report_data[0]);
    try std.testing.expectEqual(@as(u8, 10), report_data[1]);

    for (report_data[2..]) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "rejects input longer than 64 bytes" {
    const input: [65]u8 = @splat(0);

    try std.testing.expectError(
        error.InputTooLong,
        makeReportData(&input),
    );
}

test "accepts exactly 64 bytes" {
    const input: [64]u8 = @splat(0);
    const report_data = try makeReportData(&input);

    try std.testing.expectEqual(@as(usize, 64), report_data.len);
}

test "constructs a report request" {
    const input = [_]u8{ 42, 10 };

    const request: abi.ReportRequest = .{
        .user_data = try makeReportData(&input),
        .vmpl = 0,
    };

    try std.testing.expectEqual(@as(u8, 42), request.user_data[0]);

    for (request.reserved) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}
