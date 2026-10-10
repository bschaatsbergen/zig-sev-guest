//! Offline cryptographic verification. Never fetches certificates or reads a clock.
const std = @import("std");
const c = @import("openssl.zig").c;
const report = @import("report.zig");
const certificate = @import("certificate.zig");
const Certificate = certificate.Certificate;
const trust = @import("trust.zig");
const policy = @import("policy.zig");

pub const Chain = struct {
    endorsement: []const u8,
    /// null selects the embedded AMD intermediate for Options.product + signer.
    intermediate: ?[]const u8 = null,

    /// Borrows validated table contents. Guest-provided ARKs are never trusted.
    /// The GHCB ASK slot holds ASVK for a VLEK-signed report as well.
    pub fn fromTable(table: @import("cert_table.zig").Table, signer: report.Signer) !Chain {
        const ct = @import("cert_table.zig");
        const id = switch (signer) {
            .vcek => ct.vcek,
            .vlek => ct.vlek,
            .none => return error.UnsignedReport,
        };
        return .{ .endorsement = table.find(id) orelse return error.MissingEndorsementCertificate, .intermediate = table.find(ct.ask) };
    }
};

pub const Revocation = union(enum) {
    /// Explicit opt-out; certificate time validity and TCB binding still apply.
    unchecked,
    /// DER AMD product CRL signed by the ARK; checks revocation of ASK/ASVK.
    /// Endorsement-key retirement is enforced by caller TCB policy, not this CRL.
    amd_root_crl: []const u8,
};

pub const Options = struct {
    product: report.Product,
    /// Trusted Unix time in seconds. Required so historical tests are deterministic.
    now: i64,
    revocation: Revocation,
    /// null uses the embedded AMD ARK. An empty list trusts nothing.
    /// Explicit roots replace AMD defaults. Never populate this from guest input.
    trusted_roots: ?[]const []const u8 = null,
};

pub const Diagnostics = struct {
    openssl_error: c_ulong = 0,
    chain_error: c_int = 0,
    chain_depth: c_int = 0,
};

fn signatureProfile(cert: Certificate) !void {
    var md: c_int = 0;
    var key: c_int = 0;
    if (c.X509_get_version(cert.handle) != 2 or c.X509_get_signature_info(cert.handle, &md, &key, null, null) != 1 or md != c.NID_sha384 or key != c.NID_rsassaPss) return error.InvalidCertificateAlgorithm;
}

fn endorsementKey(cert: Certificate) !*c.EVP_PKEY {
    const key = c.X509_get_pubkey(cert.handle) orelse return error.InvalidPublicKey;
    errdefer c.EVP_PKEY_free(key);
    var group: [80]u8 = undefined;
    var n: usize = 0;
    if (c.EVP_PKEY_is_a(key, "EC") != 1 or c.EVP_PKEY_get_group_name(key, &group, group.len, &n) != 1 or n > group.len or !std.mem.eql(u8, group[0..n], "secp384r1")) return error.InvalidPublicKey;
    return key;
}

fn caProfile(cert: Certificate) !void {
    try signatureProfile(cert);
    if (c.X509_check_ca(cert.handle) == 0 or
        c.X509_get_extension_flags(cert.handle) & c.EXFLAG_BCONS == 0 or
        c.X509_get_key_usage(cert.handle) == std.math.maxInt(u32) or
        c.X509_get_key_usage(cert.handle) & c.KU_KEY_CERT_SIGN == 0) return error.InvalidCertificateAuthority;
    const key = c.X509_get_pubkey(cert.handle) orelse return error.InvalidPublicKey;
    defer c.EVP_PKEY_free(key);
    if (c.EVP_PKEY_is_a(key, "RSA") != 1 or c.EVP_PKEY_get_bits(key) != 4096) return error.InvalidPublicKey;
}

/// Signature-only primitive. This does NOT establish certificate trust or policy.
pub fn signature(raw: []const u8, cert: Certificate) !void {
    const r = try report.parse(raw);
    if (r.signer == .none or r.mask_chip_key) return error.UnsignedReport;
    const key = try endorsementKey(cert);
    defer c.EVP_PKEY_free(key);
    const sig = c.ECDSA_SIG_new() orelse return error.OutOfMemory;
    defer c.ECDSA_SIG_free(sig);
    const rn = c.BN_lebin2bn(&r.signature.r, 48, null) orelse return error.OutOfMemory;
    const sn = c.BN_lebin2bn(&r.signature.s, 48, null) orelse {
        c.BN_free(rn);
        return error.OutOfMemory;
    };
    // set0 transfers both BIGNUM allocations to sig on success.
    if (c.ECDSA_SIG_set0(sig, rn, sn) != 1) {
        c.BN_free(rn);
        c.BN_free(sn);
        return error.InvalidSignature;
    }
    var der: [104]u8 = undefined;
    var ptr: [*c]u8 = &der;
    const len = c.i2d_ECDSA_SIG(sig, &ptr);
    if (len <= 0 or len > der.len) return error.InvalidSignature;
    const ctx = c.EVP_MD_CTX_new() orelse return error.OutOfMemory;
    defer c.EVP_MD_CTX_free(ctx);
    if (c.EVP_DigestVerifyInit(ctx, null, c.EVP_sha384(), null, key) != 1) return error.CryptoFailed;
    if (c.EVP_DigestVerify(ctx, &der, @intCast(len), raw.ptr, report.signed_size) != 1) return error.InvalidSignature;
}

/// Authenticates the chain, endorsement TCB/HWID binding, and report signature.
/// The returned report still needs workload policy validation and freshness checks.
pub fn attestation(raw: []const u8, chain: Chain, options: Options, diagnostics: *Diagnostics) !report.Report {
    diagnostics.* = .{};
    c.ERR_clear_error();
    errdefer diagnostics.openssl_error = c.ERR_peek_last_error();
    const r = try report.parse(raw);
    if (r.signer == .none or r.mask_chip_key) return error.UnsignedReport;
    if (options.now < 0) return error.InvalidVerificationTime;
    if (r.cpu == null and options.product == .turin) return error.UnsupportedReportProduct;
    if (r.cpu) |cpu| if (try cpu.product() != options.product) return error.ReportProductMismatch;
    const defaults = try certificate.splitChain(try trust.amd(options.product, r.signer));
    const leaf = try Certificate.parse(chain.endorsement);
    defer leaf.deinit();
    try signatureProfile(leaf);
    if (c.X509_check_ca(leaf.handle) != 0) return error.InvalidEndorsementCertificate;
    const usage = c.X509_get_key_usage(leaf.handle);
    if (usage != std.math.maxInt(u32) and usage & c.KU_DIGITAL_SIGNATURE == 0) return error.InvalidEndorsementKeyUsage;
    try leaf.commonName(if (r.signer == .vcek) "SEV-VCEK" else "SEV-VLEK");
    const extensions = try certificate.endorsements(leaf, r.signer, options.product);
    if (!std.meta.eql(r.reported_tcb, extensions.tcb)) return error.CertificateTcbMismatch;
    if (extensions.hwid) |hwid| if (!std.mem.eql(u8, r.chip_id[0..hwid.len], hwid)) return error.CertificateChipIdMismatch;
    if (!r.current_tcb.atLeast(r.reported_tcb) or !r.current_tcb.atLeast(r.committed_tcb)) return error.InconsistentTcb;
    const intermediate = try Certificate.parse(chain.intermediate orelse defaults.intermediate);
    defer intermediate.deinit();
    try caProfile(intermediate);
    var name_buffer: [64]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buffer, "SEV-{s}{s}", .{ if (r.signer == .vlek) "VLEK-" else "", options.product.rootProduct().name() });
    try intermediate.commonName(name);

    const store = c.X509_STORE_new() orelse return error.OutOfMemory;
    defer c.X509_STORE_free(store);
    const roots = options.trusted_roots orelse &.{defaults.root};
    if (roots.len == 0 or roots.len > 16) return error.InvalidTrustRoots;
    for (roots) |bytes| {
        const root = try Certificate.parse(bytes);
        defer root.deinit();
        try caProfile(root);
        const root_name = try std.fmt.bufPrint(&name_buffer, "ARK-{s}", .{options.product.rootProduct().name()});
        try root.commonName(root_name);
        if (c.X509_NAME_cmp(c.X509_get_subject_name(root.handle), c.X509_get_issuer_name(root.handle)) != 0) return error.InvalidTrustRoot;
        if (c.X509_STORE_add_cert(store, root.handle) != 1) return error.InvalidTrustRoot;
    }
    const untrusted = c.OPENSSL_sk_new_null() orelse return error.OutOfMemory;
    defer c.OPENSSL_sk_free(untrusted);
    if (c.OPENSSL_sk_push(untrusted, intermediate.handle) == 0) return error.OutOfMemory;
    const ctx = c.X509_STORE_CTX_new() orelse return error.OutOfMemory;
    defer c.X509_STORE_CTX_free(ctx);
    if (c.X509_STORE_CTX_init(ctx, store, leaf.handle, @ptrCast(untrusted)) != 1) return error.CryptoFailed;
    const param = c.X509_STORE_CTX_get0_param(ctx) orelse return error.CryptoFailed;
    c.X509_VERIFY_PARAM_set_time(param, @intCast(options.now));
    c.X509_VERIFY_PARAM_set_depth(param, 2);
    c.X509_VERIFY_PARAM_set_auth_level(param, 2);
    // Historic AMD VCEKs omit AuthorityKeyIdentifier (including the real upstream
    // fixture), so X509_STRICT rejects otherwise valid AMD chains. Normal chain
    // validation still enforces signatures, time, CA/path/key-usage constraints,
    // and unknown critical extensions. Never install an error-ignoring callback.
    if (c.X509_VERIFY_PARAM_set_flags(param, c.X509_V_FLAG_CHECK_SS_SIGNATURE) != 1) return error.CryptoFailed;
    if (c.X509_verify_cert(ctx) != 1) {
        diagnostics.chain_error = c.X509_STORE_CTX_get_error(ctx);
        diagnostics.chain_depth = c.X509_STORE_CTX_get_error_depth(ctx);
        return error.InvalidCertificateChain;
    }
    const verified = c.X509_STORE_CTX_get0_chain(ctx) orelse return error.CryptoFailed;
    const stack: *c.OPENSSL_STACK = @ptrCast(verified);
    if (c.OPENSSL_sk_num(stack) != 3) return error.InvalidCertificateChain;
    const root: *c.X509 = @ptrCast(@alignCast(c.OPENSSL_sk_value(stack, 2) orelse return error.CryptoFailed));
    switch (options.revocation) {
        .unchecked => {},
        .amd_root_crl => |bytes| try checkCrl(bytes, root, intermediate.handle, options.now),
    }
    try signature(raw, leaf);
    return r;
}

fn checkCrl(bytes: []const u8, root: *c.X509, intermediate: *c.X509, now: i64) !void {
    if (bytes.len == 0 or bytes.len > 1024 * 1024) return error.InvalidCrl;
    if (c.X509_get_key_usage(root) & c.KU_CRL_SIGN == 0) return error.InvalidCrlIssuer;
    var p: [*c]const u8 = bytes.ptr;
    const crl = c.d2i_X509_CRL(null, &p, @intCast(bytes.len)) orelse return error.InvalidCrl;
    defer c.X509_CRL_free(crl);
    if (@intFromPtr(p) - @intFromPtr(bytes.ptr) != bytes.len) return error.InvalidCrl;
    if (c.X509_NAME_cmp(c.X509_CRL_get_issuer(crl), c.X509_get_subject_name(root)) != 0) return error.InvalidCrlIssuer;
    const key = c.X509_get_pubkey(root) orelse return error.InvalidPublicKey;
    defer c.EVP_PKEY_free(key);
    if (c.X509_CRL_verify(crl, key) != 1) return error.InvalidCrlSignature;
    var time: c.time_t = @intCast(now);
    const last = c.X509_CRL_get0_lastUpdate(crl) orelse return error.InvalidCrl;
    const next = c.X509_CRL_get0_nextUpdate(crl) orelse return error.InvalidCrl;
    if (c.X509_cmp_time(last, &time) != -1 or c.X509_cmp_time(next, &time) != 1) return error.CrlNotCurrent;
    // Only full, direct CRLs are supported. Reject unsupported critical semantics.
    const count = c.X509_CRL_get_ext_count(crl);
    var i: c_int = 0;
    while (i < count) : (i += 1) {
        const ext = c.X509_CRL_get_ext(crl, i) orelse return error.InvalidCrl;
        const nid = c.OBJ_obj2nid(c.X509_EXTENSION_get_object(ext));
        if (c.X509_EXTENSION_get_critical(ext) != 0 or nid == c.NID_delta_crl or nid == c.NID_issuing_distribution_point) return error.UnsupportedCrl;
    }
    if (c.X509_CRL_get_REVOKED(crl)) |entries| {
        const stack: *c.OPENSSL_STACK = @ptrCast(entries);
        var j: c_int = 0;
        while (j < c.OPENSSL_sk_num(stack)) : (j += 1) {
            const entry: *c.X509_REVOKED = @ptrCast(@alignCast(c.OPENSSL_sk_value(stack, j) orelse return error.InvalidCrl));
            // RFC 5280 §5.3: an unhandled critical entry extension makes the
            // entire CRL unusable, even when that entry has a different serial.
            // certificateIssuer changes issuer scope and requires indirect CRL support.
            if (c.X509_REVOKED_get_ext_by_critical(entry, 1, -1) >= 0 or
                c.X509_REVOKED_get_ext_by_NID(entry, c.NID_certificate_issuer, -1) >= 0) return error.UnsupportedCrl;
        }
    }
    var revoked: ?*c.X509_REVOKED = null;
    if (c.X509_CRL_get0_by_cert(crl, &revoked, intermediate) != 0) return error.CertificateRevoked;
}

/// Convenience composition; both layers examine the same authenticated report.
pub fn andValidate(raw: []const u8, chain: Chain, options: Options, expected: policy.Policy, diagnostics: *Diagnostics) !report.Report {
    const r = try attestation(raw, chain, options, diagnostics);
    try policy.validate(&r, expected);
    return r;
}

test "real report signature AMD chain tampering and expiry" {
    const raw = @embedFile("testdata/attestation.bin");
    const chain: Chain = .{ .endorsement = @embedFile("testdata/vcek.der") };
    const options: Options = .{ .product = .milan, .now = 1669852800, .revocation = .unchecked };
    var diagnostics: Diagnostics = .{};
    _ = try attestation(raw, chain, options, &diagnostics);
    var bad = raw.*;
    bad[0x90] ^= 1;
    try std.testing.expectError(error.InvalidSignature, attestation(&bad, chain, options, &diagnostics));
    bad = raw.*;
    bad[0x180] ^= 1;
    try std.testing.expectError(error.CertificateTcbMismatch, attestation(&bad, chain, options, &diagnostics));
    bad = raw.*;
    bad[0x1a0] ^= 1;
    try std.testing.expectError(error.CertificateChipIdMismatch, attestation(&bad, chain, options, &diagnostics));
    var expired = options;
    expired.now = 4102444800;
    try std.testing.expectError(error.InvalidCertificateChain, attestation(raw, chain, expired, &diagnostics));
    var empty = options;
    empty.trusted_roots = &.{};
    try std.testing.expectError(error.InvalidTrustRoots, attestation(raw, chain, empty, &diagnostics));
}

test "synthetic VCEK and VLEK chains CRLs and composed policy" {
    inline for (.{ "vcek", "vlek" }) |kind| {
        const raw = @embedFile("testdata/synthetic/" ++ kind ++ "-report.bin");
        const root = @embedFile("testdata/synthetic/root.der");
        const chain: Chain = .{
            .endorsement = @embedFile("testdata/synthetic/" ++ kind ++ ".der"),
            .intermediate = @embedFile("testdata/synthetic/" ++ kind ++ "-intermediate.der"),
        };
        var options: Options = .{
            .product = .milan,
            .now = 1767225600,
            .trusted_roots = &.{root},
            .revocation = .{ .amd_root_crl = @embedFile("testdata/synthetic/" ++ kind ++ "-valid.crl") },
        };
        var d: Diagnostics = .{};
        const r = try attestation(raw, chain, options, &d);
        const table = try @import("cert_table.zig").parse(@embedFile("testdata/synthetic/" ++ kind ++ "-table.bin"));
        _ = try attestation(raw, try Chain.fromTable(table, r.signer), options, &d);
        var expected: policy.Policy = .{
            .report_data = r.report_data,
            .measurement = r.measurement,
            .vmpl = 0,
            .minimum_tcb = .{ .boot_loader = 2, .snp = 5, .microcode = 68 },
            .required_launch_mitigations = 3,
            .required_current_mitigations = 7,
        };
        _ = try andValidate(raw, chain, options, expected, &d);
        expected.report_data[0] ^= 1;
        try std.testing.expectError(error.ReportDataMismatch, andValidate(raw, chain, options, expected, &d));
        options.revocation = .{ .amd_root_crl = @embedFile("testdata/synthetic/" ++ kind ++ "-revoked.crl") };
        try std.testing.expectError(error.CertificateRevoked, attestation(raw, chain, options, &d));
        inline for (.{ "expired", "future" }) |state| {
            options.revocation = .{ .amd_root_crl = @embedFile("testdata/synthetic/" ++ kind ++ "-" ++ state ++ ".crl") };
            try std.testing.expectError(error.CrlNotCurrent, attestation(raw, chain, options, &d));
        }
        var broken_crl = @embedFile("testdata/synthetic/" ++ kind ++ "-valid.crl").*;
        broken_crl[broken_crl.len - 1] ^= 1;
        options.revocation = .{ .amd_root_crl = &broken_crl };
        try std.testing.expectError(error.InvalidCrlSignature, attestation(raw, chain, options, &d));
        options.revocation = .{ .amd_root_crl = "garbage" };
        try std.testing.expectError(error.InvalidCrl, attestation(raw, chain, options, &d));
        options.revocation = .unchecked;
        options.trusted_roots = null;
        // Attacker-created ARK/ASK/leaf with perfect names are not AMD trust anchors.
        try std.testing.expectError(error.InvalidCertificateChain, attestation(raw, chain, options, &d));
        options.trusted_roots = &.{root};
        var damaged = raw.*;
        damaged[0x2a0] ^= 1;
        try std.testing.expectError(error.InvalidSignature, attestation(&damaged, chain, options, &d));
        var bad_chain = chain;
        bad_chain.intermediate = (try certificate.splitChain(try trust.amd(.milan, r.signer))).intermediate;
        try std.testing.expectError(error.InvalidCertificateChain, attestation(raw, bad_chain, options, &d));
    }
}

test "Turin VCEK uses FMC TCB and eight-byte hardware identity" {
    var d: Diagnostics = .{};
    const r = try attestation(@embedFile("testdata/synthetic/turin-report.bin"), .{
        .endorsement = @embedFile("testdata/synthetic/turin.der"),
        .intermediate = @embedFile("testdata/synthetic/turin-intermediate.der"),
    }, .{
        .product = .turin,
        .now = 1767225600,
        .revocation = .unchecked,
        .trusted_roots = &.{@embedFile("testdata/synthetic/turin-root.der")},
    }, &d);
    try std.testing.expectEqual(1, r.reported_tcb.fmc);
    try std.testing.expectEqual(4, r.reported_tcb.snp);
}

test "embedded AMD CA roles signatures and unsupported products" {
    inline for (.{ report.Product.milan, report.Product.genoa, report.Product.turin }) |product| {
        inline for (.{ report.Signer.vcek, report.Signer.vlek }) |signer| {
            if (!(product == .turin and signer == .vlek)) {
                const parts = try certificate.splitChain(try trust.amd(product, signer));
                const root = try Certificate.parse(parts.root);
                defer root.deinit();
                const intermediate = try Certificate.parse(parts.intermediate);
                defer intermediate.deinit();
                try caProfile(root);
                try caProfile(intermediate);
                const key = c.X509_get_pubkey(root.handle) orelse return error.InvalidPublicKey;
                defer c.EVP_PKEY_free(key);
                try std.testing.expectEqual(1, c.X509_verify(root.handle, key));
                try std.testing.expectEqual(1, c.X509_verify(intermediate.handle, key));
            }
        }
    }
    try std.testing.expectError(error.UnsupportedSigningProduct, trust.amd(.turin, .vlek));
    try std.testing.expectError(error.UnsupportedSigningProduct, trust.amd(.siena, .vlek));
    var d: Diagnostics = .{};
    try std.testing.expectError(error.UnsupportedReportProduct, attestation(@embedFile("testdata/attestation.bin"), .{
        .endorsement = @embedFile("testdata/vcek.der"),
    }, .{ .product = .turin, .now = 1767225600, .revocation = .unchecked }, &d));
}

test "fuzz signed report tampering cannot authenticate" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) !void {
            var raw = @embedFile("testdata/attestation.bin").*;
            const offset = smith.index(raw.len);
            raw[offset] ^= smith.valueRangeAtMost(u8, 1, 255);
            var d: Diagnostics = .{};
            if (attestation(&raw, .{ .endorsement = @embedFile("testdata/vcek.der") }, .{
                .product = .milan,
                .now = 1669852800,
                .revocation = .unchecked,
            }, &d)) |_| {
                return error.AuthenticatedTamperedReport;
            } else |_| {}
        }
    }.run, .{});
}

test "fuzz CRL decoding and revocation checks" {
    const root = try Certificate.parse(@embedFile("testdata/synthetic/root.der"));
    defer root.deinit();
    const intermediate = try Certificate.parse(@embedFile("testdata/synthetic/vcek-intermediate.der"));
    defer intermediate.deinit();
    try std.testing.fuzz(.{ root, intermediate }, struct {
        fn run(certs: struct { Certificate, Certificate }, smith: *std.testing.Smith) !void {
            var bytes: [4096]u8 = undefined;
            var n: usize = undefined;
            if (smith.value(bool)) {
                n = smith.valueRangeAtMost(u16, 0, bytes.len);
                smith.bytes(bytes[0..n]);
            } else {
                const seed = @embedFile("testdata/synthetic/vcek-valid.crl");
                @memcpy(bytes[0..seed.len], seed);
                n = if (smith.value(bool)) seed.len else smith.index(seed.len + 1);
                for (0..smith.valueRangeAtMost(u8, 1, 8)) |_| {
                    bytes[smith.index(seed.len)] ^= smith.valueRangeAtMost(u8, 1, 255);
                }
            }
            checkCrl(bytes[0..n], certs[0].handle, certs[1].handle, 1767225600) catch {};
        }
    }.run, .{});
}

test "critical CRL entry semantics reject the entire signed CRL" {
    const root = try Certificate.parse(@embedFile("testdata/synthetic/crl-critical-root.der"));
    defer root.deinit();
    const intermediate = try Certificate.parse(@embedFile("testdata/synthetic/crl-critical-intermediate.der"));
    defer intermediate.deinit();
    try checkCrl(@embedFile("testdata/synthetic/crl-critical-control.crl"), root.handle, intermediate.handle, 1767225600);
    try std.testing.expectError(error.UnsupportedCrl, checkCrl(
        @embedFile("testdata/synthetic/crl-critical-entry.crl"),
        root.handle,
        intermediate.handle,
        1767225600,
    ));
}
