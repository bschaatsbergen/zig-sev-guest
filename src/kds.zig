//! Explicit AMD KDS retrieval. Verification itself is always offline.
const std = @import("std");
const report = @import("report.zig");

pub const origin = "https://kdsintf.amd.com";

/// Return an allocation owned by `allocator`, at most `max_bytes` bytes.
/// A custom transport must enforce its own network deadlines and TLS policy.
pub const Getter = struct {
    context: *anyopaque,
    get: *const fn (*anyopaque, std.mem.Allocator, []const u8, usize) anyerror![]u8,
};

pub fn vcekUrl(allocator: std.mem.Allocator, r: *const report.Report, product: report.Product) ![]u8 {
    if (r.signer != .vcek) return error.VcekRequired;
    if (r.cpu == null and product == .turin) return error.UnsupportedReportProduct;
    if (r.cpu) |cpu| if (try cpu.product() != product) return error.ReportProductMismatch;
    const t = r.reported_tcb;
    if (t.boot_loader > 127 or t.tee > 127 or t.snp > 127 or t.fmc > 127) return error.InvalidTcb;
    if (std.mem.allEqual(u8, &r.chip_id, 0)) return error.MaskedChipId;
    if (product == .turin) {
        const hex = std.fmt.bytesToHex(r.chip_id[0..8].*, .lower);
        return std.fmt.allocPrint(allocator, origin ++ "/vcek/v1/{s}/{s}?fmcSPL={d}&blSPL={d}&teeSPL={d}&snpSPL={d}&ucodeSPL={d}", .{ product.name(), hex, t.fmc, t.boot_loader, t.tee, t.snp, t.microcode });
    }
    const hex = std.fmt.bytesToHex(r.chip_id, .lower);
    return std.fmt.allocPrint(allocator, origin ++ "/vcek/v1/{s}/{s}?blSPL={d}&teeSPL={d}&snpSPL={d}&ucodeSPL={d}", .{ product.name(), hex, t.boot_loader, t.tee, t.snp, t.microcode });
}

pub fn productUrl(allocator: std.mem.Allocator, product: report.Product, signer: report.Signer, resource: enum { cert_chain, crl }) ![]u8 {
    if (signer == .none) return error.UnsignedReport;
    if ((product == .turin or product == .siena) and signer == .vlek) return error.UnsupportedSigningProduct;
    return std.fmt.allocPrint(allocator, origin ++ "/{s}/v1/{s}/{s}", .{ @tagName(signer), product.rootProduct().name(), @tagName(resource) });
}

pub const Client = struct {
    getter: Getter,

    fn fetch(self: Client, allocator: std.mem.Allocator, url: []const u8, limit: usize) ![]u8 {
        const bytes = try self.getter.get(self.getter.context, allocator, url, limit);
        errdefer allocator.free(bytes);
        if (bytes.len == 0 or bytes.len > limit) return error.InvalidResponseLength;
        return bytes;
    }

    /// VLEK leaf certificates must come from the CSP/extended report, not public KDS.
    pub fn vcek(self: Client, allocator: std.mem.Allocator, r: *const report.Report, product: report.Product) ![]u8 {
        const url = try vcekUrl(allocator, r, product);
        defer allocator.free(url);
        return self.fetch(allocator, url, 65536);
    }

    /// Returned roots are untrusted input: use pinned AMD defaults or configured roots.
    pub fn chain(self: Client, allocator: std.mem.Allocator, product: report.Product, signer: report.Signer) ![]u8 {
        const url = try productUrl(allocator, product, signer, .cert_chain);
        defer allocator.free(url);
        return self.fetch(allocator, url, 131072);
    }

    pub fn crl(self: Client, allocator: std.mem.Allocator, product: report.Product, signer: report.Signer) ![]u8 {
        const url = try productUrl(allocator, product, signer, .crl);
        defer allocator.free(url);
        return self.fetch(allocator, url, 1024 * 1024);
    }
};

/// Opt-in HTTPS implementation using Zig 0.17 std.Io and std.http.
/// System TLS roots, hostname/time checks, no redirects/proxies/retries/cache,
/// 8 KiB header/trailer sections, bounded bodies, and a 30-second overall deadline.
/// Responses must use Content-Length or chunked framing, with a complete body.
/// Allocators must be thread-safe; do not call the same Http concurrently.
pub const Http = struct {
    const max_head_bytes = 8192;

    io: std.Io,
    timeout: std.Io.Duration = .fromSeconds(30),
    last_status: ?std.http.Status = null,

    pub fn getter(self: *Http) Getter {
        return .{ .context = self, .get = get };
    }

    fn get(context: *anyopaque, allocator: std.mem.Allocator, url: []const u8, limit: usize) anyerror![]u8 {
        const self: *Http = @ptrCast(@alignCast(context));
        self.last_status = null;
        if (!std.mem.startsWith(u8, url, origin ++ "/")) return error.InvalidKdsOrigin;
        const Result = union(enum) { response: anyerror![]u8, timeout: std.Io.Cancelable!void };
        var buffer: [2]Result = undefined;
        var select: std.Io.Select(Result) = .init(self.io, &buffer);
        // Both tasks can finish at once: drain and free an unconsumed response.
        defer while (select.cancel()) |pending| switch (pending) {
            .response => |r| if (r) |bytes| {
                allocator.free(bytes);
            } else |_| {},
            .timeout => {},
        };
        try select.concurrent(.timeout, std.Io.sleep, .{ self.io, self.timeout, .awake });
        try select.concurrent(.response, request, .{ self, allocator, url, limit });
        return switch (try select.await()) {
            .response => |r| r,
            .timeout => |r| {
                try r;
                return error.NetworkTimeout;
            },
        };
    }

    fn request(self: *Http, allocator: std.mem.Allocator, url: []const u8, limit: usize) anyerror![]u8 {
        var client: std.http.Client = .{ .allocator = allocator, .io = self.io, .read_buffer_size = max_head_bytes };
        defer client.deinit();
        var req = try client.request(.GET, try std.Uri.parse(url), .{
            .redirect_behavior = .unhandled,
            .keep_alive = false,
            .headers = .{ .accept_encoding = .{ .override = "identity" } },
        });
        defer req.deinit();
        try req.sendBodiless();
        const response = try req.receiveHead(&.{});
        self.last_status = response.head.status;
        return readResponse(allocator, &req.reader, response.head, limit);
    }

    fn readResponse(allocator: std.mem.Allocator, reader: *std.http.Reader, head: std.http.Client.Response.Head, limit: usize) ![]u8 {
        // TLS buffers can contain a complete oversized head before std.http's
        // streaming limit is checked. Enforce the limit on the parsed section too.
        if (head.bytes.len > max_head_bytes) return error.HttpHeadersOversize;
        if (head.status != .ok) return error.HttpStatus;
        if (head.content_encoding != .identity) return error.CompressedResponse;
        if (head.transfer_encoding == .none and head.content_length == null) return error.UnframedResponse;
        if (head.transfer_encoding != .none and head.content_length != null) return error.AmbiguousResponseLength;
        if (head.content_length) |len| if (len > limit) return error.ResponseTooLarge;
        var buffer: [4096]u8 = undefined;
        const bytes = try reader.bodyReader(&buffer, head.transfer_encoding, head.content_length).allocRemaining(allocator, .limited(limit));
        errdefer allocator.free(bytes);
        // Zig 0.17's content-length reader can report EOF before the declared
        // body is complete. TLS also permits missing close_notify for HTTP, so
        // transport EOF alone cannot authenticate the end of a response.
        if (reader.state != .ready) return error.TruncatedResponse;
        if (reader.trailers.len > max_head_bytes) return error.HttpHeadersOversize;
        return bytes;
    }
};

fn readHttpForTest(allocator: std.mem.Allocator, wire: []const u8, limit: usize) ![]u8 {
    var input: std.Io.Reader = .fixed(wire);
    var reader: std.http.Reader = .{ .in = &input, .interface = undefined, .state = .ready, .max_head_len = Http.max_head_bytes };
    const head = try std.http.Client.Response.Head.parse(try reader.receiveHead());
    return Http.readResponse(allocator, &reader, head, limit);
}

test "HTTPS response framing rejects truncation and ambiguous boundaries" {
    const allocator = std.testing.allocator;
    inline for (.{
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n",
    }) |wire| {
        const body = try readHttpForTest(allocator, wire, 4);
        defer allocator.free(body);
        try std.testing.expectEqualStrings("test", body);
    }
    try std.testing.expectError(error.TruncatedResponse, readHttpForTest(allocator, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nx", 10));
    try std.testing.expectError(error.ReadFailed, readHttpForTest(allocator, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nx", 10));
    try std.testing.expectError(error.UnframedResponse, readHttpForTest(allocator, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nx", 10));
    try std.testing.expectError(error.AmbiguousResponseLength, readHttpForTest(allocator, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n", 10));
    try std.testing.expectError(error.ResponseTooLarge, readHttpForTest(allocator, "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n", 10));
    try std.testing.expectError(error.StreamTooLong, readHttpForTest(allocator, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n", 3));
}

test "HTTP header limits apply even when TLS has buffered the entire section" {
    const prefix = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nX-Padding: ";
    const suffix = "\r\n\r\n";
    inline for (.{ 8192, 8193, 32768 }) |len| {
        const padding: [len - prefix.len - suffix.len]u8 = @splat('a');
        const wire = prefix ++ padding ++ suffix ++ "test";
        if (len <= Http.max_head_bytes) {
            const bytes = try readHttpForTest(std.testing.allocator, wire, 4);
            defer std.testing.allocator.free(bytes);
            try std.testing.expectEqualStrings("test", bytes);
        } else {
            try std.testing.expectError(error.HttpHeadersOversize, readHttpForTest(std.testing.allocator, wire, 4));
        }
    }
    const padding: [9000]u8 = @splat('a');
    const trailers = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\nX-Padding: " ++ padding ++ "\r\n\r\n";
    try std.testing.expectError(error.HttpHeadersOversize, readHttpForTest(std.testing.allocator, trailers, 4));
}

test "KDS URLs mock retrieval and allocator failure cleanup" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            const Mock = struct {
                fn get(_: *anyopaque, a: std.mem.Allocator, url: []const u8, limit: usize) ![]u8 {
                    try std.testing.expect(std.mem.startsWith(u8, url, origin ++ "/vcek/v1/Milan/"));
                    try std.testing.expect(std.mem.endsWith(u8, url, "?blSPL=2&teeSPL=0&snpSPL=5&ucodeSPL=68"));
                    try std.testing.expectEqual(65536, limit);
                    return a.dupe(u8, @embedFile("testdata/vcek.der"));
                }
            };
            var context: u8 = 0;
            const client: Client = .{ .getter = .{ .context = &context, .get = Mock.get } };
            const r = try report.parse(@embedFile("testdata/attestation.bin"));
            const bytes = try client.vcek(allocator, &r, .milan);
            defer allocator.free(bytes);
            try std.testing.expectEqualSlices(u8, @embedFile("testdata/vcek.der"), bytes);
        }
    }.run, .{});
    const url = try productUrl(std.testing.allocator, .genoa, .vlek, .cert_chain);
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings(origin ++ "/vlek/v1/Genoa/cert_chain", url);
    // Force the real HTTP implementation to be compiled without using the network.
    var http: Http = .{ .io = std.testing.io };
    const getter = http.getter();
    try std.testing.expectError(error.InvalidKdsOrigin, getter.get(getter.context, std.testing.allocator, "http://evil.invalid", 10));
}

test "Turin URL and invalid KDS responses" {
    var r = try report.parse(@embedFile("testdata/synthetic/turin-report.bin"));
    const url = try vcekUrl(std.testing.allocator, &r, .turin);
    defer std.testing.allocator.free(url);
    const hex = std.fmt.bytesToHex(r.chip_id[0..8].*, .lower);
    const expected = try std.fmt.allocPrint(std.testing.allocator, origin ++ "/vcek/v1/Turin/{s}?fmcSPL=1&blSPL=2&teeSPL=3&snpSPL=4&ucodeSPL=200", .{hex});
    defer std.testing.allocator.free(expected);
    try std.testing.expectEqualStrings(expected, url);
    r.signer = .vlek;
    try std.testing.expectError(error.VcekRequired, vcekUrl(std.testing.allocator, &r, .turin));
    r.signer = .vcek;
    r.chip_id = @splat(0);
    try std.testing.expectError(error.MaskedChipId, vcekUrl(std.testing.allocator, &r, .turin));
    const Mock = struct {
        oversized: bool = false,
        fn get(ctx: *anyopaque, allocator: std.mem.Allocator, _: []const u8, max: usize) ![]u8 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            return allocator.alloc(u8, if (self.oversized) max + 1 else 0);
        }
    };
    var mock: Mock = .{};
    const client: Client = .{ .getter = .{ .context = &mock, .get = Mock.get } };
    try std.testing.expectError(error.InvalidResponseLength, client.chain(std.testing.allocator, .milan, .vcek));
    mock.oversized = true;
    try std.testing.expectError(error.InvalidResponseLength, client.chain(std.testing.allocator, .milan, .vcek));
}
