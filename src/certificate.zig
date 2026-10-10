//! Bounded X.509 decoding and AMD endorsement certificate extensions.
const std = @import("std");
const c = @import("openssl.zig").c;
const report = @import("report.zig");

pub const Certificate = struct {
    handle: *c.X509,

    /// Exactly one DER or PEM certificate. OpenSSL owns the decoded allocation.
    pub fn parse(bytes: []const u8) !Certificate {
        if (bytes.len == 0 or bytes.len > 65536) return error.InvalidCertificateLength;
        const trimmed = std.mem.trim(u8, bytes, " \r\n\t");
        if (std.mem.startsWith(u8, trimmed, "-----BEGIN CERTIFICATE-----")) {
            const bio = c.BIO_new_mem_buf(bytes.ptr, @intCast(bytes.len)) orelse return error.OutOfMemory;
            defer _ = c.BIO_free(bio);
            const cert = c.PEM_read_bio_X509(bio, null, null, null) orelse return error.InvalidCertificate;
            errdefer c.X509_free(cert);
            var remaining: [256]u8 = undefined;
            while (true) {
                const n = c.BIO_read(bio, &remaining, remaining.len);
                if (n <= 0) break;
                if (std.mem.trim(u8, remaining[0..@intCast(n)], " \r\n\t").len != 0) return error.TrailingCertificateData;
            }
            return .{ .handle = cert };
        }
        var ptr: [*c]const u8 = bytes.ptr;
        const cert = c.d2i_X509(null, &ptr, @intCast(bytes.len)) orelse return error.InvalidCertificate;
        errdefer c.X509_free(cert);
        if (@intFromPtr(ptr) - @intFromPtr(bytes.ptr) != bytes.len) return error.TrailingCertificateData;
        return .{ .handle = cert };
    }

    pub fn deinit(self: Certificate) void {
        c.X509_free(self.handle);
    }

    /// Borrowed extension bytes remain valid until the certificate is freed.
    pub fn extension(self: Certificate, oid: [:0]const u8) !?[]const u8 {
        const object = c.OBJ_txt2obj(oid, 1) orelse return error.OutOfMemory;
        defer c.ASN1_OBJECT_free(object);
        const index = c.X509_get_ext_by_OBJ(self.handle, object, -1);
        if (index < 0) return null;
        if (c.X509_get_ext_by_OBJ(self.handle, object, index) >= 0) return error.DuplicateExtension;
        const ext = c.X509_get_ext(self.handle, index) orelse return error.InvalidCertificate;
        const value = c.X509_EXTENSION_get_data(ext) orelse return error.InvalidCertificate;
        const len = c.ASN1_STRING_length(value);
        if (len < 0 or len > 4096) return error.InvalidExtension;
        return c.ASN1_STRING_get0_data(value)[0..@intCast(len)];
    }

    pub fn required(self: Certificate, oid: [:0]const u8) ![]const u8 {
        return (try self.extension(oid)) orelse error.MissingExtension;
    }

    pub fn commonName(self: Certificate, expected: []const u8) !void {
        const subject = c.X509_get_subject_name(self.handle) orelse return error.InvalidCertificate;
        const i = c.X509_NAME_get_index_by_NID(subject, c.NID_commonName, -1);
        if (i < 0 or c.X509_NAME_get_index_by_NID(subject, c.NID_commonName, i) >= 0) return error.CertificateRoleMismatch;
        const entry = c.X509_NAME_get_entry(subject, i) orelse return error.InvalidCertificate;
        const value = c.X509_NAME_ENTRY_get_data(entry) orelse return error.InvalidCertificate;
        const len = c.ASN1_STRING_length(value);
        if (len < 0 or !std.mem.eql(u8, c.ASN1_STRING_get0_data(value)[0..@intCast(len)], expected)) return error.CertificateRoleMismatch;
    }
};

/// Split the KDS's ASK/ASVK + ARK PEM response. Both slices borrow input.
pub fn splitChain(pem: []const u8) !struct { intermediate: []const u8, root: []const u8 } {
    if (pem.len > 2 * 65536) return error.InvalidCertificateLength;
    const end = "-----END CERTIFICATE-----";
    const first = (std.mem.indexOf(u8, pem, end) orelse return error.InvalidCertificate) + end.len;
    const second = std.mem.trim(u8, pem[first..], " \r\n\t");
    var a = try Certificate.parse(pem[0..first]);
    defer a.deinit();
    var b = try Certificate.parse(second);
    defer b.deinit();
    return .{ .intermediate = pem[0..first], .root = second };
}

/// A constrained DER value decoder for AMD's primitive extension values only.
/// X.509 and all signatures are decoded/verified by OpenSSL.
fn content(bytes: []const u8, tag: u8) ![]const u8 {
    if (bytes.len < 2 or bytes[0] != tag) return error.InvalidExtension;
    var header: usize = 2;
    var len: usize = bytes[1];
    if (len >= 128) {
        const n = len & 0x7f;
        if (n == 0 or n > 2 or bytes.len < 2 + n or bytes[2] == 0) return error.InvalidExtension;
        len = 0;
        for (bytes[2..][0..n]) |b| len = len * 256 + b;
        if (len < 128) return error.InvalidExtension;
        header += n;
    }
    if (len != bytes.len - header) return error.InvalidExtension;
    return bytes[header..];
}

fn number(bytes: []const u8) !u8 {
    const v = try content(bytes, 2);
    if (v.len == 1 and v[0] < 128) return v[0];
    if (v.len == 2 and v[0] == 0 and v[1] >= 128) return v[1];
    return error.InvalidExtension;
}

fn text(bytes: []const u8) ![]const u8 {
    const v = try content(bytes, 0x16);
    if (v.len == 0) return error.InvalidExtension;
    for (v) |b| if (b < 0x20 or b > 0x7e) return error.InvalidExtension;
    return v;
}

pub const Extensions = struct {
    struct_version: u8,
    product_name: []const u8,
    tcb: report.Tcb,
    hwid: ?[]const u8,
    csp_id: ?[]const u8,
};

/// Validate AMD's extension schema, including reserved SPLs and identity type.
pub fn endorsements(cert: Certificate, signer: report.Signer, product: report.Product) !Extensions {
    const version = try number(try cert.required("1.3.6.1.4.1.3704.1.1"));
    const turin = product == .turin;
    if (version != @as(u8, if (turin) 1 else 0)) return error.UnsupportedCertificateVersion;
    // AMD 58369 documents the VLEK v0 schema for Milan and Genoa.
    if ((turin or product == .siena) and signer == .vlek) return error.UnsupportedSigningProduct;
    const name = try text(try cert.required("1.3.6.1.4.1.3704.1.2"));
    const prefix = product.name();
    if (!std.mem.startsWith(u8, name, prefix)) return error.CertificateProductMismatch;
    if (signer == .vcek) {
        if (name.len != prefix.len + 3 or name[prefix.len] != '-' or name[prefix.len + 1] < 'A' or name[prefix.len + 1] > 'Z' or !std.ascii.isDigit(name[prefix.len + 2])) return error.CertificateProductMismatch;
    } else if (!std.mem.eql(u8, name, prefix)) return error.CertificateProductMismatch;
    const bl = try number(try cert.required("1.3.6.1.4.1.3704.1.3.1"));
    const tee = try number(try cert.required("1.3.6.1.4.1.3704.1.3.2"));
    const snp = try number(try cert.required("1.3.6.1.4.1.3704.1.3.3"));
    const ucode = try number(try cert.required("1.3.6.1.4.1.3704.1.3.8"));
    const fmc = if (turin) try number(try cert.required("1.3.6.1.4.1.3704.1.3.9")) else 0;
    if (bl > 127 or tee > 127 or snp > 127 or fmc > 127) return error.InvalidExtension;
    inline for (.{ "1.3.6.1.4.1.3704.1.3.5", "1.3.6.1.4.1.3704.1.3.6", "1.3.6.1.4.1.3704.1.3.7" }) |oid| {
        if (try number(try cert.required(oid)) != 0) return error.NonzeroReserved;
    }
    if (!turin and try number(try cert.required("1.3.6.1.4.1.3704.1.3.4")) != 0) return error.NonzeroReserved;
    const hwid_value = try cert.extension("1.3.6.1.4.1.3704.1.4");
    const csp_value = try cert.extension("1.3.6.1.4.1.3704.1.5");
    var hwid: ?[]const u8 = null;
    var csp: ?[]const u8 = null;
    switch (signer) {
        .vcek => {
            if (csp_value != null) return error.InvalidEndorsementIdentity;
            const v = hwid_value orelse return error.MissingExtension;
            const len: usize = if (turin) 8 else 64;
            // Historic AMD certificates contain raw octets without the inner tag.
            hwid = if (v.len == len) v else try content(v, 4);
            if (hwid.?.len != len) return error.InvalidEndorsementIdentity;
        },
        .vlek => {
            if (hwid_value != null) return error.InvalidEndorsementIdentity;
            csp = try text(csp_value orelse return error.MissingExtension);
        },
        .none => return error.UnsignedReport,
    }
    return .{ .struct_version = version, .product_name = name, .tcb = .{ .boot_loader = bl, .tee = tee, .snp = snp, .microcode = ucode, .fmc = fmc }, .hwid = hwid, .csp_id = csp };
}

test "real AMD certificate schema and malformed DER" {
    const bytes = @embedFile("testdata/vcek.der");
    const cert = try Certificate.parse(bytes);
    defer cert.deinit();
    const ext = try endorsements(cert, .vcek, .milan);
    try std.testing.expectEqualStrings("Milan-B0", ext.product_name);
    try std.testing.expectEqual(68, ext.tcb.microcode);
    try std.testing.expectEqual(64, ext.hwid.?.len);
    for ([_]usize{ 0, 1, 16, bytes.len - 1 }) |n| {
        if (Certificate.parse(bytes[0..n])) |unexpected| {
            unexpected.deinit();
            return error.AcceptedTruncatedCertificate;
        } else |_| {}
    }
    const bad = try std.testing.allocator.alloc(u8, bytes.len + 1);
    defer std.testing.allocator.free(bad);
    @memcpy(bad[0..bytes.len], bytes);
    bad[bytes.len] = 0;
    try std.testing.expectError(error.TrailingCertificateData, Certificate.parse(bad));
    try std.testing.expectError(error.InvalidExtension, number(&.{ 2, 1, 255 }));
    try std.testing.expectError(error.InvalidExtension, number(&.{ 2, 2, 0, 1 }));
    try std.testing.expectEqual(255, try number(&.{ 2, 2, 0, 255 }));
}
