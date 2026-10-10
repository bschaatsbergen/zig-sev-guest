//! Workload policy is independent of certificate/signature verification.
const std = @import("std");
const report = @import("report.zig");

pub const Policy = struct {
    // Deliberately required. In particular, no implicit all-zero nonce or measurement.
    report_data: [64]u8,
    measurement: [48]u8,
    vmpl: u2,
    /// Applied to reported, current, committed AND launch TCB, component-wise.
    /// A zero floor is an explicit decision to impose no minimum for that component.
    minimum_tcb: report.Tcb,
    allow_debug: bool = false,
    allow_smt: bool = false,
    allow_migration_agent: bool = false,
    minimum_guest_svn: u32 = 0,
    family_id: ?[16]u8 = null,
    image_id: ?[16]u8 = null,
    host_data: ?[32]u8 = null,
    id_key_digest: ?[48]u8 = null,
    author_key_digest: ?[48]u8 = null,
    report_id: ?[32]u8 = null,
    report_id_ma: ?[32]u8 = null,
    chip_id: ?[64]u8 = null,
    require_author_key: bool = false,
    required_platform_info: u64 = 0,
    required_guest_policy: u64 = 0,
    forbidden_guest_policy: u64 = 0,
    required_launch_mitigations: u64 = 0,
    required_current_mitigations: u64 = 0,
};

/// Acceptance here authenticates nothing: call verify.attestation first, or
/// verify.andValidate to apply both operations to the same bytes.
pub fn validate(r: *const report.Report, p: Policy) !void {
    if (!std.mem.eql(u8, &r.report_data, &p.report_data)) return error.ReportDataMismatch;
    if (!std.mem.eql(u8, &r.measurement, &p.measurement)) return error.MeasurementMismatch;
    if (r.vmpl != p.vmpl) return error.VmplMismatch;
    if (!p.allow_debug and r.policy.debug()) return error.DebugNotAllowed;
    if (!p.allow_smt and (r.policy.smt() or r.platform_info & 1 != 0)) return error.SmtNotAllowed;
    if (!p.allow_migration_agent and r.policy.migrationAgent()) return error.MigrationNotAllowed;
    if (!r.reported_tcb.atLeast(p.minimum_tcb) or !r.current_tcb.atLeast(p.minimum_tcb) or
        !r.committed_tcb.atLeast(p.minimum_tcb) or !r.launch_tcb.atLeast(p.minimum_tcb)) return error.TcbTooOld;
    if (r.guest_svn < p.minimum_guest_svn) return error.GuestSvnTooOld;
    inline for (.{ "family_id", "image_id", "host_data", "id_key_digest", "author_key_digest", "report_id", "report_id_ma", "chip_id" }) |name| {
        if (@field(p, name)) |expected| if (!std.mem.eql(u8, &@field(r, name), &expected)) return error.IdentityMismatch;
    }
    if ((p.require_author_key or p.author_key_digest != null) and !r.author_key_en) return error.AuthorKeyRequired;
    if (r.platform_info & p.required_platform_info != p.required_platform_info) return error.PlatformInfoMismatch;
    if (r.policy.raw & p.required_guest_policy != p.required_guest_policy or r.policy.raw & p.forbidden_guest_policy != 0) return error.GuestPolicyMismatch;
    if (p.required_launch_mitigations != 0) {
        const vector = r.launch_mitigation_vector orelse return error.MitigationsUnavailable;
        if (vector & p.required_launch_mitigations != p.required_launch_mitigations) return error.MitigationsMissing;
    }
    if (p.required_current_mitigations != 0) {
        const vector = r.current_mitigation_vector orelse return error.MitigationsUnavailable;
        if (vector & p.required_current_mitigations != p.required_current_mitigations) return error.MitigationsMissing;
    }
}

test "acceptance and independent policy failures" {
    const r = try report.parse(@embedFile("testdata/attestation.bin"));
    const base: Policy = .{ .report_data = r.report_data, .measurement = r.measurement, .vmpl = @intCast(r.vmpl), .minimum_tcb = .{}, .allow_smt = true, .allow_debug = true };
    try validate(&r, base);
    var p = base;
    p.report_data[0] ^= 1;
    try std.testing.expectError(error.ReportDataMismatch, validate(&r, p));
    p = base;
    p.measurement[0] ^= 1;
    try std.testing.expectError(error.MeasurementMismatch, validate(&r, p));
    p = base;
    p.vmpl = 3;
    try std.testing.expectError(error.VmplMismatch, validate(&r, p));
    p = base;
    p.minimum_tcb.snp = 255;
    try std.testing.expectError(error.TcbTooOld, validate(&r, p));
    p = base;
    p.required_launch_mitigations = 1;
    try std.testing.expectError(error.MitigationsUnavailable, validate(&r, p));
    var debug = r;
    debug.policy.raw |= 1 << 19;
    p = base;
    p.allow_debug = false;
    try std.testing.expectError(error.DebugNotAllowed, validate(&debug, p));
}
