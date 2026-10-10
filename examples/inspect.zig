const std = @import("std");
const sev = @import("sev_guest");
const common = @import("common.zig");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) {
        std.debug.print("usage: sev-inspect REPORT_FILE\n", .{});
        return error.InvalidArguments;
    }
    const r = try sev.report.parse(try common.read(init, args[1], sev.report.size + 1));
    var buffer: [4096]u8 = undefined;
    var writer = std.Io.File.Writer.init(.stdout(), init.io, &buffer);
    const out = &writer.interface;
    try out.print("Parsed only; authenticity and policy are UNCHECKED.\nversion={d} signer={s} vmpl={d} guest_svn={d}\npolicy=0x{x} debug={} smt={} platform_info=0x{x}\ncpu={any}\n", .{ r.version, @tagName(r.signer), r.vmpl, r.guest_svn, r.policy.raw, r.policy.debug(), r.policy.smt(), r.platform_info, r.cpu });
    inline for (.{ "measurement", "report_data", "family_id", "image_id", "host_data", "id_key_digest", "author_key_digest", "report_id", "report_id_ma", "chip_id" }) |field| {
        try out.print(field ++ "={s}\n", .{std.fmt.bytesToHex(@field(r, field), .lower)});
    }
    inline for (.{ "reported_tcb", "current_tcb", "committed_tcb", "launch_tcb", "current_version", "committed_version", "launch_mitigation_vector", "current_mitigation_vector" }) |field| {
        try out.print(field ++ "={any}\n", .{@field(r, field)});
    }
    try out.flush();
}
