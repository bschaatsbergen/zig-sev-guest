# zig-sev-guest

A Zig 0.17.0 library for retrieving and verifying AMD SEV-SNP attestation reports.
Retrieval requires an x86_64 Linux SNP guest; saved reports can be parsed and
verified on other systems.

Retrieval, parsing, signature verification, and policy validation are separate
operations. Parsing a report does not make it trustworthy.

## Build

Install Zig 0.17.0, OpenSSL 3 or 4 development headers, and `pkg-config`.
There are no Zig dependencies. Tests run offline without SNP hardware.

```sh
# Debian / Ubuntu dependencies
sudo apt install libssl-dev pkg-config

zig build
zig build test

# Cross-compile Linux device code without OpenSSL or executing it
zig build check -Dcrypto=false -Dtarget=x86_64-linux-musl
```

Use equivalent packages on other systems. For a custom OpenSSL installation,
pass `-Dopenssl-prefix=/path/to/openssl` to the build commands.

The fuzz workflow runs each native Zig fuzz target separately on PRs and pushes
to `main`. Longer campaigns are available through manual workflow dispatch.
To run a target locally:

```sh
zig build test -Doptimize=ReleaseSafe -Dtest-filter="fuzz report framing" --fuzz=1M
```

## Use

Add this package to your Zig dependencies and import its `sev_guest` module.
The verifier must supply the expected report data, measurement, VMPL, and minimum
TCB. Debug, SMT, and migration are denied unless explicitly allowed.

```zig
const sev = @import("sev_guest");

var diagnostics: sev.verify.Diagnostics = .{};
const report = try sev.verify.andValidate(report_bytes, .{
    .endorsement = vcek_bytes,
}, .{
    .product = .milan,
    .now = trusted_unix_time,
    .revocation = .{ .amd_root_crl = crl_bytes },
}, expected_policy, &diagnostics);
```

AMD roots are embedded; custom roots replace them explicitly. Certificate validity
uses the caller's trusted time. The CRL checks ASK/ASVK revocation; `.unchecked`
explicitly skips it. TCB floors apply to reported, current, committed, and launch
TCBs. Use a fresh verifier challenge and an independently approved measurement.

Verification is offline. Optional KDS retrieval uses HTTPS, a 30-second deadline,
bounded responses, and no redirects or retries. VLEK leaves come from the guest
or CSP. Downloaded roots are never trusted automatically.

## Examples

Inspect a saved report:

```sh
zig build inspect -Dcrypto=false -- src/testdata/attestation.bin
```

Verify the included synthetic VLEK report, certificate table, CRL, and policy:

```sh
zig build verify -- --table \
  src/testdata/synthetic/vlek-report.bin src/testdata/synthetic/vlek-table.bin \
  examples/synthetic-policy.json - src/testdata/synthetic/root.der \
  src/testdata/synthetic/vlek-valid.crl
```

Inside a Linux SNP guest, save a report and certificate table. Supply a fresh
64-byte challenge as 128 hexadecimal characters and the guest's actual VMPL:

```sh
zig build -Dcrypto=false
sudo ./zig-out/bin/sev-fetch report.bin "$REPORT_DATA_HEX" "$VMPL" certs.bin
```

Retrieve certificates explicitly, then verify against your own `policy.json`:

```sh
./zig-out/bin/sev-kds report.bin milan amd
./zig-out/bin/sev-verify --table report.bin certs.bin policy.json - - amd.crl.der
```

Build with cryptography enabled to obtain `sev-verify`. The example policy format
is in `examples/synthetic-policy.json`; omit its historical `verification_time`
for normal clock-based verification. File-writing examples overwrite their outputs.

Report versions 2–5 are supported. VCEK verification supports Milan, Genoa, Siena,
and Turin; VLEK supports Milan and Genoa. Version 2 uses the family-19h TCB layout.
Turin needs signed CPUID fields. Version 6 and Turin VLEK are rejected. Real Milan
version-5 retrieval and verification were tested on a GCP SNP guest at VMPL 2;
VLEK and Turin have offline signed-fixture coverage.

Public API comments cover ownership and protocol details. Apache-2.0;
see [NOTICE](NOTICE) for fixture provenance.

Inspired by [google/go-sev-guest](https://github.com/google/go-sev-guest).
