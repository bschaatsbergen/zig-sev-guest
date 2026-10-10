//! Slower adversarial checks: zig build security-test.
const std = @import("std");
const sev = @import("sev_guest");

test "every report bit is authenticated or rejected as reserved" {
    if (!sev.crypto_enabled) return error.SkipZigTest;
    const cases = .{
        .{ @embedFile("testdata/attestation.bin"), @embedFile("testdata/vcek.der"), null, null, sev.report.Product.milan, @as(i64, 1669852800) },
        .{ @embedFile("testdata/synthetic/vlek-report.bin"), @embedFile("testdata/synthetic/vlek.der"), @embedFile("testdata/synthetic/vlek-intermediate.der"), @embedFile("testdata/synthetic/root.der"), sev.report.Product.milan, @as(i64, 1767225600) },
        .{ @embedFile("testdata/synthetic/turin-report.bin"), @embedFile("testdata/synthetic/turin.der"), @embedFile("testdata/synthetic/turin-intermediate.der"), @embedFile("testdata/synthetic/turin-root.der"), sev.report.Product.turin, @as(i64, 1767225600) },
    };
    inline for (cases) |case| {
        const chain: sev.verify.Chain = .{ .endorsement = case[1], .intermediate = case[2] };
        const options: sev.verify.Options = .{
            .product = case[4],
            .now = case[5],
            .revocation = .unchecked,
            .trusted_roots = if (@TypeOf(case[3]) == @TypeOf(null)) null else &.{case[3]},
        };
        var d: sev.verify.Diagnostics = .{};
        _ = try sev.verify.attestation(case[0], chain, options, &d);
        for (0..sev.report.size) |offset| {
            for (0..8) |bit| {
                var raw = case[0].*;
                raw[offset] ^= @as(u8, 1) << @intCast(bit);
                if (sev.verify.attestation(&raw, chain, options, &d)) |_| {
                    std.debug.print("accepted report mutation at byte {x}, bit {d}\n", .{ offset, bit });
                    return error.AuthenticatedTamperedReport;
                } else |_| {}
            }
        }
    }
}
