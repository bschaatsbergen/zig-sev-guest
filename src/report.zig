//! AMD publication 56860 rev. 1.58, §2.2, §7.2 and §10.
//! Decode explicitly: a report is a little-endian wire format, not a C struct.
const std = @import("std");
pub const size = 0x4a0;
pub const signed_size = 0x2a0;
pub const Signer = enum(u3) { vcek = 0, vlek = 1, none = 7 };
pub const Product = enum {
    milan,
    genoa,
    siena,
    turin,

    pub fn name(self: Product) []const u8 {
        return switch (self) {
            .milan => "Milan",
            .genoa => "Genoa",
            .siena => "Siena",
            .turin => "Turin",
        };
    }
    pub fn rootProduct(self: Product) Product {
        return if (self == .siena) .genoa else self;
    }
};

pub const Cpu = struct {
    family: u8,
    model: u8,
    stepping: u8,

    pub fn product(self: Cpu) !Product {
        if (self.family == 0x19) return switch (self.model >> 4) {
            0 => .milan,
            1 => .genoa,
            0xa => .siena,
            else => error.UnsupportedProduct,
        };
        if (self.family == 0x1a and self.model >> 4 <= 1) return .turin;
        return error.UnsupportedProduct;
    }
};

/// Security patch levels are compared component-wise, never as one integer.
pub const Tcb = struct {
    boot_loader: u8 = 0,
    tee: u8 = 0,
    snp: u8 = 0,
    microcode: u8 = 0,
    fmc: u8 = 0,

    pub fn atLeast(self: Tcb, minimum: Tcb) bool {
        return self.boot_loader >= minimum.boot_loader and self.tee >= minimum.tee and
            self.snp >= minimum.snp and self.microcode >= minimum.microcode and self.fmc >= minimum.fmc;
    }

    pub fn parse(bytes: *const [8]u8, turin: bool) !Tcb {
        if (turin) {
            try zero(bytes[4..7]);
            return .{ .fmc = bytes[0], .boot_loader = bytes[1], .tee = bytes[2], .snp = bytes[3], .microcode = bytes[7] };
        }
        try zero(bytes[2..6]);
        return .{ .boot_loader = bytes[0], .tee = bytes[1], .snp = bytes[6], .microcode = bytes[7] };
    }
};

pub const GuestPolicy = struct {
    raw: u64,
    pub fn debug(self: GuestPolicy) bool {
        return self.raw & (1 << 19) != 0;
    }
    pub fn smt(self: GuestPolicy) bool {
        return self.raw & (1 << 16) != 0;
    }
    pub fn migrationAgent(self: GuestPolicy) bool {
        return self.raw & (1 << 18) != 0;
    }
    pub fn abiMajor(self: GuestPolicy) u8 {
        return @truncate(self.raw >> 8);
    }
    pub fn abiMinor(self: GuestPolicy) u8 {
        return @truncate(self.raw);
    }
};

pub const FirmwareVersion = struct { build: u8, minor: u8, major: u8 };
pub const Signature = struct { r: [48]u8, s: [48]u8 }; // Little-endian scalars.

/// Owned value, with no allocator or borrowed input. `raw` retains the exact signed bytes.
/// Verification reparses raw input; edited decoded fields cannot bypass checks.
pub const Report = struct {
    raw: [size]u8,
    version: u32,
    guest_svn: u32,
    policy: GuestPolicy,
    family_id: [16]u8,
    image_id: [16]u8,
    vmpl: u32,
    current_tcb: Tcb,
    platform_info: u64,
    signer: Signer,
    mask_chip_key: bool,
    author_key_en: bool,
    report_data: [64]u8,
    measurement: [48]u8,
    host_data: [32]u8,
    id_key_digest: [48]u8,
    author_key_digest: [48]u8,
    report_id: [32]u8,
    report_id_ma: [32]u8,
    reported_tcb: Tcb,
    cpu: ?Cpu,
    chip_id: [64]u8,
    committed_tcb: Tcb,
    current_version: FirmwareVersion,
    committed_version: FirmwareVersion,
    launch_tcb: Tcb,
    launch_mitigation_vector: ?u64,
    current_mitigation_vector: ?u64,
    signature: Signature,
};

pub fn integer(comptime T: type, bytes: []const u8, offset: usize) T {
    return std.mem.readInt(T, bytes[offset..][0..@sizeOf(T)], .little);
}

pub fn zero(bytes: []const u8) !void {
    for (bytes) |b| if (b != 0) return error.NonzeroReserved;
}

/// Accept exactly one 1184-byte report (versions 2–5). No implicit trailing data.
pub fn parse(bytes: []const u8) !Report {
    if (bytes.len != size) return error.InvalidReportLength;
    const version = integer(u32, bytes, 0);
    if (version < 2 or version > 5) return error.UnsupportedReportVersion;
    const policy = integer(u64, bytes, 8);
    const policy_bits: u6 = if (version >= 5) 26 else 25;
    if (policy & (1 << 17) == 0 or policy >> policy_bits != 0) return error.InvalidGuestPolicy;
    const vmpl = integer(u32, bytes, 0x30);
    if (vmpl > 3 and !(version >= 3 and vmpl == 0xffffffff)) return error.InvalidVmpl;
    if (integer(u32, bytes, 0x34) != 1) return error.UnsupportedSignatureAlgorithm;
    const platform = integer(u64, bytes, 0x40);
    const platform_mask: u64 = if (version >= 5) 0xbf else if (version >= 3) 0x3f else 0x1f;
    if (platform & ~platform_mask != 0) return error.InvalidPlatformInfo;
    const info = integer(u32, bytes, 0x48);
    if (info >> 5 != 0) return error.InvalidSignerInfo;
    const signer: Signer = switch ((info >> 2) & 7) {
        0 => .vcek,
        1 => .vlek,
        7 => .none,
        else => return error.InvalidSignerInfo,
    };
    try zero(bytes[0x4c..0x50]);
    const cpu: ?Cpu = if (version >= 3) .{ .family = bytes[0x188], .model = bytes[0x189], .stepping = bytes[0x18a] } else null;
    if (cpu) |c| if (c.stepping > 15) return error.InvalidCpuStepping;
    try zero(bytes[if (version >= 3) @as(usize, 0x18b) else 0x188..0x1a0]);
    try zero(bytes[0x1eb..0x1ec]);
    try zero(bytes[0x1ef..0x1f0]);
    try zero(bytes[if (version >= 5) @as(usize, 0x208) else 0x1f8..signed_size]);
    try zero(bytes[0x2d0..0x2e8]);
    try zero(bytes[0x318..size]);
    const turin = if (cpu) |c| (try c.product()) == .turin else false;
    if (turin) try zero(bytes[0x1a8..0x1e0]);
    return .{
        .raw = bytes[0..size].*,
        .version = version,
        .guest_svn = integer(u32, bytes, 4),
        .policy = .{ .raw = policy },
        .family_id = bytes[0x10..0x20].*,
        .image_id = bytes[0x20..0x30].*,
        .vmpl = vmpl,
        .current_tcb = try Tcb.parse(bytes[0x38..0x40], turin),
        .platform_info = platform,
        .signer = signer,
        .mask_chip_key = info & 2 != 0,
        .author_key_en = info & 1 != 0,
        .report_data = bytes[0x50..0x90].*,
        .measurement = bytes[0x90..0xc0].*,
        .host_data = bytes[0xc0..0xe0].*,
        .id_key_digest = bytes[0xe0..0x110].*,
        .author_key_digest = bytes[0x110..0x140].*,
        .report_id = bytes[0x140..0x160].*,
        .report_id_ma = bytes[0x160..0x180].*,
        .reported_tcb = try Tcb.parse(bytes[0x180..0x188], turin),
        .cpu = cpu,
        .chip_id = bytes[0x1a0..0x1e0].*,
        .committed_tcb = try Tcb.parse(bytes[0x1e0..0x1e8], turin),
        .current_version = .{ .build = bytes[0x1e8], .minor = bytes[0x1e9], .major = bytes[0x1ea] },
        .committed_version = .{ .build = bytes[0x1ec], .minor = bytes[0x1ed], .major = bytes[0x1ee] },
        .launch_tcb = try Tcb.parse(bytes[0x1f0..0x1f8], turin),
        .launch_mitigation_vector = if (version >= 5) integer(u64, bytes, 0x1f8) else null,
        .current_mitigation_vector = if (version >= 5) integer(u64, bytes, 0x200) else null,
        .signature = .{ .r = bytes[0x2a0..0x2d0].*, .s = bytes[0x2e8..0x318].* },
    };
}

test "real upstream report and exact boundaries" {
    const bytes = @embedFile("testdata/attestation.bin");
    const r = try parse(bytes);
    try std.testing.expectEqual(2, r.version);
    try std.testing.expectEqual(2, r.reported_tcb.boot_loader);
    try std.testing.expectEqual(5, r.reported_tcb.snp);
    try std.testing.expectEqual(68, r.reported_tcb.microcode);
    for (0..size) |n| try std.testing.expectError(error.InvalidReportLength, parse(bytes[0..n]));
    var large: [size + 1]u8 = @splat(0);
    try std.testing.expectError(error.InvalidReportLength, parse(&large));
}

test "version-dependent fields and malformed reports" {
    var bytes = @embedFile("testdata/attestation.bin").*;
    bytes[0] = 6;
    try std.testing.expectError(error.UnsupportedReportVersion, parse(&bytes));
    for (3..6) |v| {
        bytes[0] = @intCast(v);
        bytes[0x188] = 0x19;
        bytes[0x189] = 1;
        const r = try parse(&bytes);
        try std.testing.expectEqual(Product.milan, try r.cpu.?.product());
        try std.testing.expectEqual(v >= 5, r.launch_mitigation_vector != null);
    }
    bytes[0] = 4;
    bytes[0x1f8] = 1;
    try std.testing.expectError(error.NonzeroReserved, parse(&bytes));
    bytes[0] = 5;
    _ = try parse(&bytes);
    bytes[0x4c] = 1;
    try std.testing.expectError(error.NonzeroReserved, parse(&bytes));
}

test "TCB layout and partial order" {
    const t = try Tcb.parse(&.{ 1, 2, 3, 4, 0, 0, 0, 5 }, true);
    try std.testing.expectEqual(1, t.fmc);
    try std.testing.expectEqual(4, t.snp);
    try std.testing.expect(!t.atLeast(.{ .boot_loader = 3 }));
    try std.testing.expectError(error.NonzeroReserved, Tcb.parse(&.{ 1, 2, 3, 4, 0, 0, 0, 5 }, false));
}

test "reserved fields enums and unsigned report framing" {
    const valid = @embedFile("testdata/attestation.bin").*;
    for ([_]usize{ 0x4c, 0x188, 0x1eb, 0x1ef, 0x1f8, 0x2d0, 0x318, 0x49f }) |offset| {
        var bad = valid;
        bad[offset] = 1;
        try std.testing.expectError(error.NonzeroReserved, parse(&bad));
    }
    var bad = valid;
    bad[0x48] = 8;
    try std.testing.expectError(error.InvalidSignerInfo, parse(&bad));
    bad = valid;
    bad[0x34] = 2;
    try std.testing.expectError(error.UnsupportedSignatureAlgorithm, parse(&bad));
    bad = valid;
    bad[0x30] = 4;
    try std.testing.expectError(error.InvalidVmpl, parse(&bad));
    bad = valid;
    bad[0x40] = 0x40;
    try std.testing.expectError(error.InvalidPlatformInfo, parse(&bad));
    bad = valid;
    bad[0xb] |= 2;
    try std.testing.expectError(error.InvalidGuestPolicy, parse(&bad));
    bad = valid;
    bad[0x48] = 30;
    @memset(bad[signed_size..], 0);
    try std.testing.expectEqual(Signer.none, (try parse(&bad)).signer);
}

test "fuzz report framing" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) !void {
            var bytes: [size + 1]u8 = undefined;
            smith.bytes(&bytes);
            const n = smith.valueRangeAtMost(u16, 0, bytes.len);
            if (parse(bytes[0..n])) |r| {
                try std.testing.expectEqualSlices(u8, bytes[0..n], &r.raw);
            } else |_| {}
        }
    }.run, .{});
}
