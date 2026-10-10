const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const crypto = b.option(bool, "crypto", "Enable OpenSSL certificate/signature verification") orelse true;
    const openssl = b.option([]const u8, "openssl-prefix", "OpenSSL installation prefix (e.g. brew --prefix openssl@3)");
    const options = b.addOptions();
    options.addOption(bool, "crypto", crypto);
    const mod = b.addModule("sev_guest", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addOptions("build_options", options);
    if (crypto) {
        mod.link_libc = true;
        mod.linkSystemLibrary("crypto", .{});
        if (openssl) |prefix| {
            mod.addIncludePath(.{ .cwd_relative = b.pathJoin(&.{ prefix, "include" }) });
            mod.addLibraryPath(.{ .cwd_relative = b.pathJoin(&.{ prefix, "lib" }) });
            mod.addRPath(.{ .cwd_relative = b.pathJoin(&.{ prefix, "lib" }) });
        }
    }
    const tests = b.addTest(.{ .root_module = mod });
    b.step("test", "Run deterministic, offline tests").dependOn(&b.addRunArtifact(tests).step);
    b.step("check", "Compile tests without executing them").dependOn(&tests.step);
}
