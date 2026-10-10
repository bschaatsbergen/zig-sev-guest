const std = @import("std");

// Linux include/uapi/linux/sev-guest.h, GPL-2.0-only WITH Linux-syscall-note.
// Interface definitions: Copyright (C) 2021 Advanced Micro Devices, Inc.
// Explicit padding keeps the x86_64 UAPI layout visible and zero initialized.
pub const get_report: u32 = 0xc0205300;
pub const get_ext_report: u32 = 0xc0205302;
pub const page_size = 4096;
pub const max_cert_bytes = 16 * 1024; // Linux SEV_FW_BLOB_MAX_SIZE.

pub const ExtendedReportRequest = extern struct {
    data: ReportRequest,
    certs_address: u64 = 0,
    certs_len: u32 = 0,
    padding: [4]u8 = @splat(0),
};

pub const ReportRequest = extern struct {
    user_data: [64]u8,
    vmpl: u32,
    reserved: [28]u8 = @splat(0),
};

pub const ReportResponse = extern struct {
    data: [4000]u8 = @splat(0),
};

test "report request matches the Linux ABI" {
    try std.testing.expectEqual(
        @as(usize, 96),
        @sizeOf(ReportRequest),
    );
    try std.testing.expectEqual(
        @as(usize, 64),
        @offsetOf(ReportRequest, "vmpl"),
    );
    try std.testing.expectEqual(
        @as(usize, 68),
        @offsetOf(ReportRequest, "reserved"),
    );
}

pub const GuestRequest = extern struct {
    msg_version: u8 = 1,
    padding: [7]u8 = @splat(0),
    req_data: u64,
    resp_data: u64,
    exitinfo2: u64 = 0,

    pub fn init(
        request: anytype,
        response: *ReportResponse,
    ) GuestRequest {
        return .{
            .req_data = @intFromPtr(request),
            .resp_data = @intFromPtr(response),
        };
    }
};

test "x86_64 Linux UAPI sizes alignment offsets and ioctl encodings" {
    const t = std.testing;
    try t.expectEqual(96, @sizeOf(ReportRequest));
    try t.expectEqual(4, @alignOf(ReportRequest));
    try t.expectEqual(4000, @sizeOf(ReportResponse));
    try t.expectEqual(1, @alignOf(ReportResponse));
    try t.expectEqual(32, @sizeOf(GuestRequest));
    try t.expectEqual(8, @alignOf(GuestRequest));
    try t.expectEqual(8, @offsetOf(GuestRequest, "req_data"));
    try t.expectEqual(16, @offsetOf(GuestRequest, "resp_data"));
    try t.expectEqual(24, @offsetOf(GuestRequest, "exitinfo2"));
    try t.expectEqual(112, @sizeOf(ExtendedReportRequest));
    try t.expectEqual(8, @alignOf(ExtendedReportRequest));
    try t.expectEqual(96, @offsetOf(ExtendedReportRequest, "certs_address"));
    try t.expectEqual(104, @offsetOf(ExtendedReportRequest, "certs_len"));
    try t.expectEqual(@as(u32, (3 << 30) | (32 << 16) | ('S' << 8)), get_report);
    try t.expectEqual(get_report + 2, get_ext_report);
}

test "guest request references request and response buffers" {
    const request: ReportRequest = .{
        .user_data = @splat(0),
        .vmpl = 0,
    };
    var response: ReportResponse = .{};

    const guest_request = GuestRequest.init(&request, &response);

    try std.testing.expectEqual(
        @as(usize, 32),
        @sizeOf(GuestRequest),
    );
    try std.testing.expectEqual(
        @as(u64, @intFromPtr(&request)),
        guest_request.req_data,
    );
    try std.testing.expectEqual(
        @as(u64, @intFromPtr(&response)),
        guest_request.resp_data,
    );
}
