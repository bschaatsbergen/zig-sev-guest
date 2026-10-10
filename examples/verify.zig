const std = @import("std");
const sev = @import("sev_guest");
const common = @import("common.zig");

const PolicyFile = struct {
    product: sev.report.Product,
    report_data: []const u8,
    measurement: []const u8,
    vmpl: u2,
    minimum_tcb: sev.report.Tcb,
    revocation: enum { unchecked, required },
    allow_debug: bool = false,
    allow_smt: bool = false,
    allow_migration_agent: bool = false,
    minimum_guest_svn: u32 = 0,
    required_platform_info: u64 = 0,
    required_launch_mitigations: u64 = 0,
    required_current_mitigations: u64 = 0,
    // Only for deliberate historical validation. Normally use the trusted clock.
    verification_time: ?i64 = null,
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const all_args = try init.minimal.args.toSlice(allocator);
    const table_mode = all_args.len > 1 and std.mem.eql(u8, all_args[1], "--table");
    const args = if (table_mode) all_args[1..] else all_args;
    if (args.len < 4 or args.len > 7) {
        std.debug.print("usage: sev-verify [--table] REPORT LEAF_CERT_OR_TABLE POLICY_JSON [INTERMEDIATE|-] [TRUSTED_ROOT|-] [CRL]\n", .{});
        return error.InvalidArguments;
    }
    const raw = try common.read(init, args[1], sev.report.size + 1);
    const leaf = try common.read(init, args[2], if (table_mode) 1024 * 1024 + 1 else 65537);
    var chain: sev.verify.Chain = if (table_mode)
        try sev.verify.Chain.fromTable(try sev.cert_table.parse(leaf), (try sev.report.parse(raw)).signer)
    else
        .{ .endorsement = leaf };
    const parsed = try std.json.parseFromSlice(PolicyFile, allocator, try common.read(init, args[3], 65537), .{});
    defer parsed.deinit();
    const config = parsed.value;
    const intermediate = if (args.len >= 5 and !std.mem.eql(u8, args[4], "-")) try common.read(init, args[4], 65537) else null;
    if (intermediate) |bytes| chain.intermediate = bytes;
    const root = if (args.len >= 6 and !std.mem.eql(u8, args[5], "-")) try common.read(init, args[5], 65537) else null;
    const roots: [1][]const u8 = .{root orelse ""};
    const revocation: sev.verify.Revocation = switch (config.revocation) {
        .unchecked => blk: {
            if (args.len == 7) return error.UnexpectedCrl;
            break :blk .unchecked;
        },
        .required => blk: {
            if (args.len != 7) return error.CrlRequired;
            break :blk .{ .amd_root_crl = try common.read(init, args[6], 1024 * 1024 + 1) };
        },
    };
    var diagnostics: sev.verify.Diagnostics = .{};
    const r = sev.verify.andValidate(raw, chain, .{
        .product = config.product,
        .now = config.verification_time orelse std.Io.Clock.real.now(init.io).toSeconds(),
        .revocation = revocation,
        .trusted_roots = if (root != null) &roots else null,
    }, .{
        .report_data = try common.hex(64, config.report_data),
        .measurement = try common.hex(48, config.measurement),
        .vmpl = config.vmpl,
        .minimum_tcb = config.minimum_tcb,
        .allow_debug = config.allow_debug,
        .allow_smt = config.allow_smt,
        .allow_migration_agent = config.allow_migration_agent,
        .minimum_guest_svn = config.minimum_guest_svn,
        .required_platform_info = config.required_platform_info,
        .required_launch_mitigations = config.required_launch_mitigations,
        .required_current_mitigations = config.required_current_mitigations,
    }, &diagnostics) catch |err| {
        std.debug.print("REJECTED: {s}; crypto diagnostics={any}\n", .{ @errorName(err), diagnostics });
        return err;
    };
    std.debug.print("ACCEPTED: {s} chain, report signature, certificate binding, and supplied policy; revocation={s}\n", .{ @tagName(r.signer), @tagName(config.revocation) });
}
