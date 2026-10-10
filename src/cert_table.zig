//! GHCB 56421 rev. 2.04 §4.1.8.1. GUID bytes use RFC 4122 order, not EFI order.
const std = @import("std");
const wire = @import("report.zig");
pub const Guid = [16]u8;
pub const vcek = guid("63da758de6644564adc5f4b93be8accd");
pub const vlek = guid("a8074bc2a25a483eaae639c045a0b8a1");
pub const ask = guid("4ab7b379bbac4fe4a02f05aef327c782");
pub const ark = guid("c0b406a4a803495297433fb6014cd0ae");
pub const crl = guid("92f81bc358114d3d97ffd19f88dc67ea");
fn guid(comptime hex: []const u8) Guid {
    var out: Guid = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

pub const Entry = struct { id: Guid, data: []const u8 };

/// Validated, allocation-free view. Input must stay alive and unmodified.
pub const Table = struct {
    bytes: []const u8,
    count: usize,

    pub fn entry(self: Table, index: usize) Entry {
        std.debug.assert(index < self.count);
        const h = self.bytes[index * 24 ..][0..24];
        const offset = wire.integer(u32, h, 16);
        const len = wire.integer(u32, h, 20);
        return .{ .id = h[0..16].*, .data = self.bytes[offset..][0..len] };
    }

    pub fn find(self: Table, id: Guid) ?[]const u8 {
        for (0..self.count) |i| {
            const e = self.entry(i);
            if (std.mem.eql(u8, &e.id, &id)) return e.data;
        }
        return null;
    }
};

/// Empty input is an absent table; nonempty tables must have a zero terminator.
/// Duplicates, overlaps, offsets into headers and zero-length blobs are rejected.
pub fn parse(bytes: []const u8) !Table {
    if (bytes.len == 0) return .{ .bytes = bytes, .count = 0 };
    if (bytes.len > 1024 * 1024) return error.TableTooLarge;
    var n: usize = 0;
    while (true) : (n += 1) {
        if (n >= 256) return error.TooManyCertificates;
        if (n * 24 + 24 > bytes.len) return error.MissingTerminator;
        const h = bytes[n * 24 ..][0..24];
        if (std.mem.allEqual(u8, h, 0)) break;
        if (std.mem.allEqual(u8, h[0..16], 0)) return error.InvalidGuid;
    }
    const header_end = (n + 1) * 24;
    for (0..n) |i| {
        const h = bytes[i * 24 ..][0..24];
        const start: usize = wire.integer(u32, h, 16);
        const len: usize = wire.integer(u32, h, 20);
        if (start < header_end or start > bytes.len or len == 0 or len > bytes.len - start) return error.InvalidCertificateRange;
        for (0..i) |j| {
            const prev = bytes[j * 24 ..][0..24];
            if (std.mem.eql(u8, h[0..16], prev[0..16])) return error.DuplicateGuid;
            const p: usize = wire.integer(u32, prev, 16);
            const pl: usize = wire.integer(u32, prev, 20);
            if (start < p + pl and p < start + len) return error.OverlappingCertificates;
        }
    }
    return .{ .bytes = bytes, .count = n };
}

test "table bounds terminator duplicate GUIDs and overlapping blobs" {
    var b: [80]u8 = @splat(0);
    @memcpy(b[0..16], &vcek);
    @memcpy(b[24..40], &ask);
    std.mem.writeInt(u32, b[16..20], 72, .little);
    std.mem.writeInt(u32, b[20..24], 4, .little);
    std.mem.writeInt(u32, b[40..44], 76, .little);
    std.mem.writeInt(u32, b[44..48], 4, .little);
    const table = try parse(&b);
    try std.testing.expectEqual(2, table.count);
    try std.testing.expectEqual(4, table.find(vcek).?.len);
    for (1..72) |i| try std.testing.expectError(error.MissingTerminator, parse(b[0..i]));
    b[40] = 74;
    try std.testing.expectError(error.OverlappingCertificates, parse(&b));
    b[40] = 76;
    @memcpy(b[24..40], &vcek);
    try std.testing.expectError(error.DuplicateGuid, parse(&b));
    b[16] = 1;
    try std.testing.expectError(error.InvalidCertificateRange, parse(&b));
    try std.testing.expectEqual(0, (try parse(&.{})).count);
}

test "padded fixture integer overflow and borrowed lookup" {
    const bytes = @embedFile("testdata/synthetic/vcek-table.bin");
    const table = try parse(bytes);
    try std.testing.expectEqual(3, table.count);
    try std.testing.expectEqualSlices(u8, @embedFile("testdata/synthetic/vcek.der"), table.find(vcek).?);
    var invalid = bytes.*;
    @memset(invalid[16..24], 255);
    try std.testing.expectError(error.InvalidCertificateRange, parse(&invalid));
    invalid = bytes.*;
    @memset(invalid[0..16], 0);
    try std.testing.expectError(error.InvalidGuid, parse(&invalid));
    invalid = bytes.*;
    @memset(invalid[20..24], 0);
    try std.testing.expectError(error.InvalidCertificateRange, parse(&invalid));
}

test "fuzz certificate table framing" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) !void {
            var bytes: [8192]u8 = undefined;
            smith.bytes(&bytes);
            const n = smith.valueRangeAtMost(u16, 0, bytes.len);
            if (parse(bytes[0..n])) |table| {
                for (0..table.count) |i| _ = table.entry(i);
            } else |_| {}
        }
    }.run, .{});
}
