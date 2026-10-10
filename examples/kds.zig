//! Explicit network operation, separate from all verification entry points.
const std = @import("std");
const sev = @import("sev_guest");
const common = @import("common.zig");

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len != 4) {
        std.debug.print("usage: sev-kds REPORT_FILE PRODUCT OUTPUT_PREFIX\n", .{});
        return error.InvalidArguments;
    }
    const product = std.meta.stringToEnum(sev.report.Product, args[2]) orelse return error.UnsupportedProduct;
    const r = try sev.report.parse(try common.read(init, args[1], sev.report.size + 1));
    var http: sev.kds.Http = .{ .io = init.io };
    const client: sev.kds.Client = .{ .getter = http.getter() };
    errdefer std.debug.print("KDS HTTP status: {any}\n", .{http.last_status});
    if (r.signer == .vcek) {
        const bytes = try client.vcek(init.gpa, &r, product);
        defer init.gpa.free(bytes);
        try common.save(init, try std.fmt.allocPrint(allocator, "{s}.vcek.der", .{args[3]}), bytes);
    } else if (r.signer == .vlek) {
        std.debug.print("VLEK leaf must be supplied by the CSP or certificate table.\n", .{});
    }
    const chain = try client.chain(init.gpa, product, r.signer);
    defer init.gpa.free(chain);
    try common.save(init, try std.fmt.allocPrint(allocator, "{s}.chain.pem", .{args[3]}), chain);
    const crl = try client.crl(init.gpa, product, r.signer);
    defer init.gpa.free(crl);
    try common.save(init, try std.fmt.allocPrint(allocator, "{s}.crl.der", .{args[3]}), crl);
    std.debug.print("Saved KDS responses. Downloading does not establish attestation trust.\n", .{});
}
