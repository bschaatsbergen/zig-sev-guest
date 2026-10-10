#!/usr/bin/env python3
"""Exercise signed adversarial inputs against sev-verify (cryptography >= 42).

Usage: python3 tools/security_matrix.py zig-out/bin/sev-verify /new/results/path
All keys are disposable, in-memory test keys. No network or AMD credentials.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import struct
import subprocess
import sys
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID, ObjectIdentifier

START = datetime(2024, 1, 1, tzinfo=timezone.utc)
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
END = datetime(2034, 1, 1, tzinfo=timezone.utc)
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)
DER = serialization.Encoding.DER
AMD = "1.3.6.1.4.1.3704.1."
UNKNOWN = ObjectIdentifier("1.2.3.4.5.6.7")


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def issue(cn, key, issuer, issuer_key, serial, ca, exts=(), **options):
    b = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(name(issuer))
         .public_key(key.public_key()).serial_number(serial)
         .not_valid_before(options.get("start", START))
         .not_valid_after(options.get("end", END)))
    if not options.get("no_bc"):
        b = b.add_extension(x509.BasicConstraints(ca, options.get("path", 1 if serial == 1 else 0) if ca else None), True)
    if not options.get("no_ku"):
        b = b.add_extension(x509.KeyUsage(
            not ca and options.get("digital_signature", True), False, False,
            False, False, ca and options.get("key_cert_sign", True),
            ca and options.get("crl_sign", True), None, None), True)
    b = b.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
    b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False)
    for ext, critical in exts:
        b = b.add_extension(ext, critical)
    return b.sign(issuer_key, hashes.SHA384(), rsa_padding=options.get("padding", PSS))


def extension(suffix, value):
    return x509.UnrecognizedExtension(ObjectIdentifier(AMD + suffix), value), False


def main():
    binary = Path(sys.argv[1]).resolve()
    output = Path(sys.argv[2]).resolve()
    output.mkdir(parents=True, exist_ok=False)
    repo = Path(__file__).resolve().parents[1]
    raw = bytearray((repo / "src/testdata/synthetic/vcek-report.bin").read_bytes())
    root_key = rsa.generate_private_key(65537, 4096)
    ask_key = rsa.generate_private_key(65537, 4096)
    key = ec.generate_private_key(ec.SECP384R1())
    root = issue("ARK-Milan", root_key, "ARK-Milan", root_key, 1, True)
    ask = issue("SEV-Milan", ask_key, "ARK-Milan", root_key, 2, True)
    exts = [extension("1", b"\x02\x01\x00"), extension("2", b"\x16\x08Milan-B0")]
    exts += [extension(f"3.{i}", bytes([2, 1, {1: 2, 3: 5, 8: 68}.get(i, 0)])) for i in range(1, 9)]
    exts += [extension("4", bytes(raw[0x1a0:0x1e0]))]
    leaf = issue("SEV-VCEK", key, "SEV-Milan", ask_key, 3, False, exts)
    policy = {
        "product": "milan", "report_data": raw[0x50:0x90].hex(),
        "measurement": raw[0x90:0xc0].hex(), "vmpl": 0,
        "minimum_tcb": {"boot_loader": 2, "snp": 5, "microcode": 68},
        "revocation": "required", "verification_time": int(NOW.timestamp()),
    }

    def sign_report(data):
        data = bytearray(data)
        r, s = decode_dss_signature(key.sign(bytes(data[:0x2a0]), ec.ECDSA(hashes.SHA384())))
        data[0x2a0:] = r.to_bytes(72, "little") + s.to_bytes(72, "little") + bytes(368)
        return data

    raw = sign_report(raw)

    def crl(*, serial=None, extensions=(), entry_extensions=(), signing_key=root_key,
            start=START, end=END):
        b = x509.CertificateRevocationListBuilder().issuer_name(name("ARK-Milan")).last_update(start).next_update(end)
        for ext, critical in extensions:
            b = b.add_extension(ext, critical)
        if serial is not None:
            entry = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(START)
            for ext, critical in entry_extensions:
                entry = entry.add_extension(ext, critical)
            b = b.add_revoked_certificate(entry.build())
        return b.sign(signing_key, hashes.SHA384(), rsa_padding=PSS)

    valid_crl = crl()
    results = []

    def check(label, expected=False, *, report=raw, endorsement=leaf, intermediate=ask,
              anchor=root, revocations=valid_crl, config=None, table=False, trust=True):
        folder = output / label
        folder.mkdir()
        (folder / "report.bin").write_bytes(report)
        (folder / "policy.json").write_text(json.dumps(policy if config is None else config))
        (folder / "leaf.der").write_bytes(endorsement.public_bytes(DER))
        (folder / "ask.der").write_bytes(intermediate.public_bytes(DER))
        (folder / "root.der").write_bytes(anchor.public_bytes(DER))
        (folder / "crl.der").write_bytes(revocations.public_bytes(DER))
        args = [str(binary)]
        if table:
            entries = [
                ("63da758d-e664-4564-adc5-f4b93be8accd", endorsement),
                ("4ab7b379-bbac-4fe4-a02f-05aef327c782", intermediate),
                ("c0b406a4-a803-4952-9743-3fb6014cd0ae", anchor),
            ]
            data = bytearray(24 * 4)
            for i, (guid, cert) in enumerate(entries):
                blob = cert.public_bytes(DER)
                struct.pack_into("<16sII", data, i * 24, uuid.UUID(guid).bytes, len(data), len(blob))
                data.extend(blob)
            (folder / "table.bin").write_bytes(data)
            args += ["--table", "report.bin", "table.bin", "policy.json", "-"]
        else:
            args += ["report.bin", "leaf.der", "policy.json", "ask.der"]
        args += ["root.der" if trust else "-", "crl.der"]
        run = subprocess.run(args, cwd=folder, capture_output=True, text=True, timeout=10)
        message = run.stdout + run.stderr
        (folder / "result.txt").write_text(message)
        accepted = run.returncode == 0 and "ACCEPTED:" in message
        passed = accepted == expected and run.returncode >= 0
        results.append({"case": label, "expected_accept": expected, "accepted": accepted,
                        "passed": passed, "exit": run.returncode})
        print(f'{"PASS" if passed else "FAIL"} {label}: {message.splitlines()[0] if message else run.returncode}', flush=True)

    check("valid", True)
    check("valid-table", True, table=True)
    check("untrusted-root", trust=False)
    check("injected-table-root", table=True, trust=False)
    for role in ["leaf", "intermediate", "root"]:
        cn, subject_key, issuer, signing_key, serial, ca, extensions, argument = {
            "leaf": ("SEV-VCEK", key, "SEV-Milan", ask_key, 3, False, exts, "endorsement"),
            "intermediate": ("SEV-Milan", ask_key, "ARK-Milan", root_key, 2, True, (), "intermediate"),
            "root": ("ARK-Milan", root_key, "ARK-Milan", root_key, 1, True, (), "anchor"),
        }[role]
        variants = {"expired": {"end": datetime(2025, 1, 1, tzinfo=timezone.utc)},
                    "future": {"start": datetime(2027, 1, 1, tzinfo=timezone.utc)},
                    "wrong-role": {"cn": "WRONG"},
                    "pkcs1-signature": {"padding": padding.PKCS1v15()}}
        if ca:
            variants.update({"not-ca": {"ca": False}, "no-basic-constraints": {"no_bc": True},
                             "no-key-usage": {"no_ku": True}, "no-cert-sign": {"key_cert_sign": False}})
        else:
            variants.update({"ca-leaf": {"ca": True}, "no-digital-signature": {"digital_signature": False}})
        for variant, options in variants.items():
            cert = issue(options.pop("cn", cn), subject_key, issuer, signing_key, serial,
                         options.pop("ca", ca), extensions, **options)
            check(f"{role}-{variant}", **{argument: cert})
        cert = issue(cn, subject_key, issuer, signing_key, serial, ca,
                     [*extensions, (x509.UnrecognizedExtension(UNKNOWN, b"\x05\x00"), True)])
        check(f"{role}-unknown-critical", **{argument: cert})

    check("root-no-crl-sign", anchor=issue("ARK-Milan", root_key, "ARK-Milan", root_key, 1, True, crl_sign=False))
    check("path-length", anchor=issue("ARK-Milan", root_key, "ARK-Milan", root_key, 1, True, path=0))
    for suffix, value in [("1", b"\x02\x01\x01"), ("2", b"\x16\x08Genoa-B0"),
                          ("3.1", b"\x02\x01\x03"), ("3.4", b"\x02\x01\x01"),
                          ("4", bytes(64))]:
        replacements = [extension(suffix, value) if e.oid.dotted_string == AMD + suffix else (e, c) for e, c in exts]
        check("extension-" + suffix, endorsement=issue("SEV-VCEK", key, "SEV-Milan", ask_key, 3, False, replacements))
    check("missing-extension", endorsement=issue("SEV-VCEK", key, "SEV-Milan", ask_key, 3, False, exts[1:]))
    check("wrong-curve", endorsement=issue("SEV-VCEK", ec.generate_private_key(ec.SECP256R1()), "SEV-Milan", ask_key, 3, False, exts))
    check("revoked", revocations=crl(serial=2))
    check("crl-wrong-key", revocations=crl(signing_key=ask_key))
    check("crl-expired", revocations=crl(end=datetime(2025, 1, 1, tzinfo=timezone.utc)))
    check("crl-future", revocations=crl(start=datetime(2027, 1, 1, tzinfo=timezone.utc)))
    check("crl-delta", revocations=crl(extensions=[(x509.DeltaCRLIndicator(1), True)]))
    check("crl-critical", revocations=crl(extensions=[(x509.UnrecognizedExtension(UNKNOWN, b"\x05\x00"), True)]))
    check("crl-entry-critical", revocations=crl(serial=99, entry_extensions=[(x509.UnrecognizedExtension(UNKNOWN, b"\x05\x00"), True)]))
    check("crl-entry-noncritical", True, revocations=crl(serial=99, entry_extensions=[(x509.UnrecognizedExtension(UNKNOWN, b"\x05\x00"), False)]))
    check("crl-entry-reason", True, revocations=crl(serial=99, entry_extensions=[(x509.CRLReason(x509.ReasonFlags.key_compromise), False)]))
    check("crl-entry-issuer", revocations=crl(serial=99, entry_extensions=[(x509.CertificateIssuer([x509.DirectoryName(name("other-issuer"))]), False)]))
    for label, offset, bit in [("debug", 8, 19), ("smt-policy", 8, 16), ("migration", 8, 18), ("smt-platform", 0x40, 0)]:
        altered = bytearray(raw)
        struct.pack_into("<Q", altered, offset, struct.unpack_from("<Q", altered, offset)[0] | (1 << bit))
        check("signed-" + label, report=sign_report(altered))
    for label, offset in [("report-data", 0x50), ("measurement", 0x90), ("vmpl", 0x30)]:
        altered = bytearray(raw)
        altered[offset] ^= 1
        check("signed-" + label, report=sign_report(altered))
    for offset in [0x38, 0x180, 0x1e0, 0x1f0]:
        altered = bytearray(raw)
        altered[offset] = 1
        check(f"signed-old-tcb-{offset:x}", report=sign_report(altered))
    check("wrong-nonce-policy", config={**policy, "report_data": bytes(64).hex()})
    check("wrong-measurement-policy", config={**policy, "measurement": bytes(48).hex()})
    check("wrong-product-policy", config={**policy, "product": "genoa"})
    check("unknown-policy-field", config={**policy, "allow_everything": True})
    check("missing-policy-field", config={k: v for k, v in policy.items() if k != "measurement"})
    (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    failed = sum(not result["passed"] for result in results)
    print(f"{len(results) - failed}/{len(results)} cases passed; artifacts: {output}")
    return bool(failed)


if __name__ == "__main__":
    sys.exit(main())
