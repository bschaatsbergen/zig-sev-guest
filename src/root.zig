//! SEV-SNP retrieval, parsing, cryptographic verification, and policy validation.
//! These are separate operations: retrieval or parsing alone establishes no trust.
pub const abi = @import("abi.zig");
pub const report = @import("report.zig");
pub const cert_table = @import("cert_table.zig");
pub const report_data = @import("report_data.zig");
pub const client = @import("client.zig");
pub const policy = @import("policy.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
