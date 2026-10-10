//! Opt-in hardware exercise: run inside an x86_64 Linux SEV-SNP guest.
const std = @import("std");
const sev = @import("sev_guest");
const common = @import("common.zig");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 4 and args.len != 5) {
        std.debug.print("usage: sev-fetch REPORT_FILE REPORT_DATA_128_HEX VMPL [CERT_TABLE_FILE]\n", .{});
        return error.InvalidArguments;
    }
    const data = try common.hex(64, args[2]);
    const vmpl = try std.fmt.parseInt(u32, args[3], 10);
    var diagnostics: sev.client.Diagnostics = .{};
    var device = sev.client.Device.openWithDiagnostics(&diagnostics) catch |err| {
        std.debug.print("open failed: {s}; Linux errno={d}\n", .{ @errorName(err), diagnostics.linux_errno });
        return err;
    };
    defer device.close();
    var client: sev.client.Client = .{ .transport = device.transport() };
    errdefer std.debug.print("request diagnostics: {any}\n", .{client.diagnostics});
    if (args.len == 5) {
        var result = try client.getExtendedReport(init.gpa, data, vmpl);
        defer result.deinit();
        try common.save(init, args[1], &result.report);
        try common.save(init, args[4], result.certificates);
        const table = try sev.cert_table.parse(result.certificates);
        std.debug.print("saved raw report and {d} certificate-table entries\n", .{table.count});
    } else {
        const raw = try client.getReport(data, vmpl);
        try common.save(init, args[1], &raw);
        std.debug.print("saved raw report\n", .{});
    }
    std.debug.print("Retrieval only: signature and policy have not been checked.\n", .{});
}
