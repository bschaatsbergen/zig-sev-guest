const std = @import("std");
const linux = std.os.linux;
const builtin = @import("builtin");
const abi = @import("abi.zig");
const report = @import("report.zig");
const cert_table = @import("cert_table.zig");

/// Numeric Linux errno, ioctl EXITINFO2 halves, and MSG_REPORT_RSP status.
/// Filled even when an operation fails; zeroed at the start of each operation.
pub const Diagnostics = struct {
    linux_errno: u16 = 0,
    firmware_error: u32 = 0,
    vmm_error: u32 = 0,
    response_status: u32 = 0,
    requested_cert_bytes: u32 = 0,
};

/// Synchronous borrowed transport. Request pointers remain valid for the call only.
/// Return Linux errno (0 on success); update guest.exitinfo2 and pointed-to buffers.
pub const Transport = struct {
    context: *anyopaque,
    ioctl: *const fn (*anyopaque, u32, *abi.GuestRequest) u16,
};

/// Owns one descriptor; do not copy an open Device or close it during a request.
/// All methods accessing Linux syscalls are guarded at compile time on macOS.
pub const Device = struct {
    fd: ?i32,

    pub fn open() !Device {
        var diagnostics: Diagnostics = .{};
        return openWithDiagnostics(&diagnostics);
    }

    pub fn openWithDiagnostics(diagnostics: *Diagnostics) !Device {
        diagnostics.* = .{};
        if (comptime builtin.os.tag != .linux or builtin.cpu.arch != .x86_64) return error.UnsupportedPlatform;
        while (true) {
            const result = linux.open("/dev/sev-guest", .{
                .ACCMODE = .RDWR,
                .CLOEXEC = true,
            }, 0);

            const errno = linux.errno(result);
            diagnostics.linux_errno = @backingInt(errno);
            switch (errno) {
                .SUCCESS => return .{ .fd = @intCast(result) },
                .INTR => continue,
                .NOENT => return error.DeviceNotFound,
                .ACCES, .PERM => return error.PermissionDenied,
                else => return error.OpenFailed,
            }
        }
    }

    pub fn close(self: *Device) void {
        const fd = self.fd orelse return;
        self.fd = null;
        // Linux releases the fd even on EINTR: retrying can close a reused fd.
        if (comptime builtin.os.tag == .linux and builtin.cpu.arch == .x86_64) _ = linux.close(fd);
    }

    pub fn transport(self: *Device) Transport {
        return .{ .context = self, .ioctl = deviceIoctl };
    }

    fn deviceIoctl(context: *anyopaque, command: u32, guest: *abi.GuestRequest) u16 {
        const self: *Device = @ptrCast(@alignCast(context));
        const fd = self.fd orelse return 9; // EBADF
        if (comptime builtin.os.tag != .linux or builtin.cpu.arch != .x86_64) return 38; // ENOSYS
        // Do not replay a potentially consumed firmware request, including EINTR.
        return @backingInt(linux.errno(linux.ioctl(fd, command, @intFromPtr(guest))));
    }
};

/// Owns only the certificate allocation. The report is an inline value.
pub const ExtendedReport = struct {
    report: [report.size]u8,
    certificates: []align(abi.page_size) u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ExtendedReport) void {
        self.allocator.free(self.certificates);
        self.* = undefined;
    }
};

pub const Client = struct {
    transport: Transport,
    diagnostics: Diagnostics = .{},

    fn call(self: *Client, command: u32, request: anytype, response: *abi.ReportResponse) bool {
        var guest = abi.GuestRequest.init(request, response);
        self.diagnostics = .{};
        self.diagnostics.linux_errno = self.transport.ioctl(self.transport.context, command, &guest);
        self.diagnostics.firmware_error = @truncate(guest.exitinfo2);
        self.diagnostics.vmm_error = @truncate(guest.exitinfo2 >> 32);
        return self.diagnostics.linux_errno == 0 and guest.exitinfo2 == 0;
    }

    fn extract(self: *Client, response: *const abi.ReportResponse, data: [64]u8, vmpl: u32) ![report.size]u8 {
        const bytes = &response.data;
        self.diagnostics.response_status = report.integer(u32, bytes, 0);
        if (self.diagnostics.response_status != 0) return error.FirmwareResponseFailed;
        if (report.integer(u32, bytes, 4) != report.size) return error.InvalidReportLength;
        try report.zero(bytes[8..32]);
        const raw = bytes[32..][0..report.size];
        if (!std.mem.eql(u8, raw[0x50..0x90], &data) or report.integer(u32, raw, 0x30) != vmpl) return error.ResponseMismatch;
        return raw.*;
    }

    /// Raw retrieval only; no certificate, signature or workload policy verification.
    pub fn getReport(self: *Client, data: [64]u8, vmpl: u32) ![report.size]u8 {
        self.diagnostics = .{};
        if (vmpl > 3) return error.InvalidVmpl;
        var request: abi.ReportRequest = .{ .user_data = data, .vmpl = vmpl };
        var response: abi.ReportResponse = .{};
        if (!self.call(abi.get_report, &request, &response)) return error.GuestRequestFailed;
        return self.extract(&response, data, vmpl);
    }

    /// Bounded negotiation: at most four ioctls, at most Linux's 16 KiB limit.
    /// A successful empty table means the hypervisor did not supply certificates.
    pub fn getExtendedReport(self: *Client, allocator: std.mem.Allocator, data: [64]u8, vmpl: u32) !ExtendedReport {
        self.diagnostics = .{};
        if (vmpl > 3) return error.InvalidVmpl;
        var certificates = try allocator.alignedAlloc(u8, .fromByteUnits(abi.page_size), 0);
        errdefer allocator.free(certificates);
        for (0..4) |_| {
            var request: abi.ExtendedReportRequest = .{
                .data = .{ .user_data = data, .vmpl = vmpl },
                .certs_address = if (certificates.len == 0) 0 else @intFromPtr(certificates.ptr),
                .certs_len = @intCast(certificates.len),
            };
            @memset(certificates, 0);
            var response: abi.ReportResponse = .{};
            if (self.call(abi.get_ext_report, &request, &response)) {
                if (request.certs_len > certificates.len) return error.InvalidCertificateBufferSize;
                const raw = try self.extract(&response, data, vmpl);
                _ = try cert_table.parse(certificates);
                return .{ .report = raw, .certificates = certificates, .allocator = allocator };
            }
            self.diagnostics.requested_cert_bytes = request.certs_len;
            if (self.diagnostics.vmm_error != 1 or self.diagnostics.firmware_error != 0) return error.GuestRequestFailed;
            const needed = request.certs_len;
            if (needed <= certificates.len or needed > abi.max_cert_bytes or needed % abi.page_size != 0) return error.InvalidCertificateBufferSize;
            const next = try allocator.alignedAlloc(u8, .fromByteUnits(abi.page_size), needed);
            allocator.free(certificates);
            certificates = next;
        }
        return error.CertificateBufferUnstable;
    }
};

test "mock transport success negotiation and all error channels" {
    const Mock = struct {
        calls: usize = 0,
        mode: enum { success, ioctl_error, firmware_error, length_error, changed_length, status_error, truncated, mismatch } = .success,
        fn ioctl(ctx: *anyopaque, command: u32, guest: *abi.GuestRequest) u16 {
            const m: *@This() = @ptrCast(@alignCast(ctx));
            m.calls += 1;
            const req: *abi.ReportRequest = @ptrFromInt(guest.req_data);
            std.debug.assert(guest.msg_version == 1 and std.mem.allEqual(u8, &req.reserved, 0));
            if (m.mode == .ioctl_error) {
                guest.exitinfo2 = (@as(u64, 2) << 32) | 0x16;
                return 5;
            }
            if (m.mode == .firmware_error) {
                guest.exitinfo2 = 0x27;
                return 0;
            }
            if (command == abi.get_ext_report) {
                const ext: *abi.ExtendedReportRequest = @ptrFromInt(guest.req_data);
                if (ext.certs_len == 0 or m.mode == .length_error or m.mode == .changed_length) {
                    ext.certs_len = switch (m.mode) {
                        .length_error => 0xffffffff,
                        .changed_length => ext.certs_len + abi.page_size,
                        else => abi.page_size,
                    };
                    guest.exitinfo2 = @as(u64, 1) << 32;
                    return 5;
                }
                std.debug.assert(ext.certs_address % abi.page_size == 0);
            }
            const resp: *abi.ReportResponse = @ptrFromInt(guest.resp_data);
            @memcpy(resp.data[32..][0..report.size], @embedFile("testdata/attestation.bin"));
            @memcpy(resp.data[32 + 0x50 ..][0..64], &req.user_data);
            std.mem.writeInt(u32, resp.data[32 + 0x30 ..][0..4], req.vmpl, .little);
            std.mem.writeInt(u32, resp.data[4..8], if (m.mode == .truncated) 0xffffffff else report.size, .little);
            if (m.mode == .status_error) resp.data[0] = 0x16;
            if (m.mode == .mismatch) resp.data[32 + 0x50] ^= 1;
            return 0;
        }
    };
    var mock: Mock = .{};
    var client: Client = .{ .transport = .{ .context = &mock, .ioctl = Mock.ioctl } };
    const raw = try client.getReport(@splat(42), 2);
    try std.testing.expectEqual(2, (try report.parse(&raw)).vmpl);
    var ext = try client.getExtendedReport(std.testing.allocator, @splat(0), 0);
    defer ext.deinit();
    try std.testing.expectEqual(abi.page_size, ext.certificates.len);
    mock.mode = .ioctl_error;
    try std.testing.expectError(error.GuestRequestFailed, client.getReport(@splat(0), 0));
    try std.testing.expectEqual(5, client.diagnostics.linux_errno);
    try std.testing.expectEqual(0x16, client.diagnostics.firmware_error);
    try std.testing.expectEqual(2, client.diagnostics.vmm_error);
    mock.mode = .firmware_error;
    try std.testing.expectError(error.GuestRequestFailed, client.getReport(@splat(0), 0));
    mock.mode = .length_error;
    try std.testing.expectError(error.InvalidCertificateBufferSize, client.getExtendedReport(std.testing.allocator, @splat(0), 0));
    mock.mode = .changed_length;
    try std.testing.expectError(error.CertificateBufferUnstable, client.getExtendedReport(std.testing.allocator, @splat(0), 0));
    mock.mode = .status_error;
    try std.testing.expectError(error.FirmwareResponseFailed, client.getReport(@splat(0), 0));
    try std.testing.expectEqual(0x16, client.diagnostics.response_status);
    mock.mode = .truncated;
    try std.testing.expectError(error.InvalidReportLength, client.getReport(@splat(0), 0));
    mock.mode = .mismatch;
    try std.testing.expectError(error.ResponseMismatch, client.getReport(@splat(0), 0));
    try std.testing.expectError(error.InvalidVmpl, client.getReport(@splat(0), 4));
}

test "closed device and portable guard" {
    var device: Device = .{ .fd = null };
    device.close();
    var client: Client = .{ .transport = device.transport() };
    try std.testing.expectError(error.GuestRequestFailed, client.getReport(@splat(0), 0));
    try std.testing.expectEqual(9, client.diagnostics.linux_errno);
    if (comptime builtin.os.tag != .linux) try std.testing.expectError(error.UnsupportedPlatform, Device.open());
}
