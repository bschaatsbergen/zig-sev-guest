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
        const bindings = b.addTranslateC(.{
            .root_source_file = b.path("src/openssl.h"),
            .target = target,
            .optimize = optimize,
        });
        mod.addImport("openssl", bindings.createModule());
        mod.link_libc = true;
        mod.linkSystemLibrary("crypto", .{ .use_pkg_config = if (openssl != null) .no else .yes });
        if (openssl) |prefix| {
            bindings.addIncludePath(.{ .cwd_relative = b.pathJoin(&.{ prefix, "include" }) });
            mod.addIncludePath(.{ .cwd_relative = b.pathJoin(&.{ prefix, "include" }) });
            mod.addLibraryPath(.{ .cwd_relative = b.pathJoin(&.{ prefix, "lib" }) });
            mod.addRPath(.{ .cwd_relative = b.pathJoin(&.{ prefix, "lib" }) });
        } else bindings.linkSystemLibrary("crypto", .{});
    }
    const test_filter = b.option([]const u8, "test-filter", "Only include tests whose names contain this text");
    const tests = b.addTest(.{
        .root_module = mod,
        .filters = if (test_filter) |filter| &.{filter} else &.{},
    });
    b.step("test", "Run deterministic, offline tests").dependOn(&b.addRunArtifact(tests).step);
    const security_tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("src/security_tests.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "sev_guest", .module = mod }},
    }) });
    b.step("security-test", "Run exhaustive offline report tampering checks").dependOn(&b.addRunArtifact(security_tests).step);
    const check = b.step("check", "Compile tests and examples without executing them");
    check.dependOn(&tests.step);
    const uapi = b.addObject(.{
        .name = "linux-uapi-check",
        .root_module = b.createModule(.{
            .target = b.resolveTargetQuery(.{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .musl }),
            .optimize = .Debug,
            .link_libc = true,
        }),
    });
    uapi.root_module.addCSourceFile(.{ .file = b.path("tests/linux_uapi.c"), .flags = &.{"-std=c11"} });
    b.step("abi-check", "Check sizes offsets and ioctls against Linux UAPI headers").dependOn(&uapi.step);
    check.dependOn(&uapi.step);
    inline for (.{ "fetch", "inspect", "kds", "verify" }) |name| {
        if (!std.mem.eql(u8, name, "verify") or crypto) {
            const exe = b.addExecutable(.{
                .name = "sev-" ++ name,
                .root_module = b.createModule(.{
                    .root_source_file = b.path("examples/" ++ name ++ ".zig"),
                    .target = target,
                    .optimize = optimize,
                    .imports = &.{.{ .name = "sev_guest", .module = mod }},
                }),
            });
            b.installArtifact(exe);
            check.dependOn(&exe.step);
            const run = b.addRunArtifact(exe);
            run.addPassthruArgs();
            b.step(name, "Run the " ++ name ++ " example").dependOn(&run.step);
        }
    }
}
