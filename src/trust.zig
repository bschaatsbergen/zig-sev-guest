//! AMD public trust anchors vendored from go-sev-guest; see NOTICE.
const report = @import("report.zig");

/// ASK/ASVK then ARK PEM chain. Only the ARK is installed as a trust anchor.
pub fn amd(product: report.Product, signer: report.Signer) ![]const u8 {
    if (signer == .none) return error.UnsignedReport;
    if ((product == .turin or product == .siena) and signer == .vlek) return error.UnsupportedSigningProduct;
    return switch (product.rootProduct()) {
        .milan => if (signer == .vcek) @embedFile("trust/ask_ark_milan.pem") else @embedFile("trust/ask_ark_milan_vlek.pem"),
        .genoa => if (signer == .vcek) @embedFile("trust/ask_ark_genoa.pem") else @embedFile("trust/ask_ark_genoa_vlek.pem"),
        .turin => if (signer == .vcek) @embedFile("trust/ask_ark_turin_vcek.pem") else return error.UnsupportedSigningProduct,
        .siena => unreachable,
    };
}
