#!/usr/bin/env python3
"""Regenerate synthetic AMD-profile fixtures (Python cryptography >= 42).

Keys are generated in memory and discarded. Checked-in outputs make tests offline
and deterministic; regeneration deliberately creates a new synthetic trust root.
No synthetic certificate is an AMD-issued certificate or a default trust anchor.
"""
from datetime import datetime, timezone
from pathlib import Path
import struct
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID, ObjectIdentifier

OUT = Path(__file__).resolve().parents[1] / "src" / "testdata" / "synthetic"
OUT.mkdir(parents=True, exist_ok=True)
START = datetime(2024, 1, 1, tzinfo=timezone.utc)
END = datetime(2034, 1, 1, tzinfo=timezone.utc)
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)


def name(cn):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Santa Clara"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Advanced Micro Devices"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Engineering"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def issue(cn, key, issuer, issuer_key, serial, ca, extensions=()):
    b = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(name(issuer))
         .public_key(key.public_key()).serial_number(serial)
         .not_valid_before(START).not_valid_after(END)
         .add_extension(x509.BasicConstraints(ca, 1 if cn.startswith("ARK") else 0 if ca else None), True)
         .add_extension(x509.KeyUsage(not ca, False, False, False, False, ca, ca, None, None), True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False))
    for oid, value in extensions:
        b = b.add_extension(x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.3704.1." + oid), value), False)
    return b.sign(issuer_key, hashes.SHA384(), rsa_padding=PSS)


def write_cert(filename, cert):
    (OUT / filename).write_bytes(cert.public_bytes(serialization.Encoding.DER))


root_key = rsa.generate_private_key(65537, 4096)
root = issue("ARK-Milan", root_key, "ARK-Milan", root_key, 1, True)
write_cert("root.der", root)
for signer, cn, serial in [("vcek", "SEV-Milan", 2), ("vlek", "SEV-VLEK-Milan", 3)]:
    intermediate_key = rsa.generate_private_key(65537, 4096)
    intermediate = issue(cn, intermediate_key, "ARK-Milan", root_key, serial, True)
    write_cert(signer + "-intermediate.der", intermediate)
    key = ec.generate_private_key(ec.SECP384R1())
    product = b"Milan-B0" if signer == "vcek" else b"Milan"
    exts = [("1", b"\x02\x01\x00"), ("2", bytes([0x16, len(product)]) + product)]
    exts += [(f"3.{i}", bytes([2, 1, {1: 2, 2: 0, 3: 5, 8: 68}.get(i, 0)])) for i in range(1, 9)]
    raw = bytearray((OUT.parent / "attestation.bin").read_bytes())
    struct.pack_into("<I", raw, 0, 5)
    struct.pack_into("<Q", raw, 8, 1 << 17)  # no debug, SMT, or migration
    raw[0x40:0x48] = bytes(8)
    struct.pack_into("<I", raw, 0x48, 4 if signer == "vlek" else 0)
    raw[0x188:0x18b] = bytes([0x19, 1, 0])
    if signer == "vcek":
        exts += [("4", bytes(raw[0x1a0:0x1e0]))]
    else:
        exts += [("5", b"\x16\x0bexample-csp")]
        raw[0x1a0:0x1e0] = bytes(64)
    for offset in [0x38, 0x180, 0x1e0, 0x1f0]:
        raw[offset:offset + 8] = bytes([2, 0, 0, 0, 0, 0, 5, 68])
    raw[0x50:0x90] = bytes(range(64))
    raw[0x90:0xc0] = bytes(range(48))
    struct.pack_into("<Q", raw, 0x1f8, 3)
    struct.pack_into("<Q", raw, 0x200, 7)
    r, s = decode_dss_signature(key.sign(raw[:0x2a0], ec.ECDSA(hashes.SHA384())))
    raw[0x2a0:] = r.to_bytes(72, "little") + s.to_bytes(72, "little") + bytes(368)
    (OUT / (signer + "-report.bin")).write_bytes(raw)
    leaf = issue("SEV-" + signer.upper(), key, cn, intermediate_key, 4 + serial, False, exts)
    write_cert(signer + ".der", leaf)
    entries = [
        ("63da758d-e664-4564-adc5-f4b93be8accd" if signer == "vcek" else "a8074bc2-a25a-483e-aae6-39c045a0b8a1", leaf),
        ("4ab7b379-bbac-4fe4-a02f-05aef327c782", intermediate),
        ("c0b406a4-a803-4952-9743-3fb6014cd0ae", root),
    ]
    table = bytearray(24 * (len(entries) + 1))
    for i, (guid, cert) in enumerate(entries):
        der = cert.public_bytes(serialization.Encoding.DER)
        struct.pack_into("<16sII", table, 24 * i, uuid.UUID(guid).bytes, len(table), len(der))
        table.extend(der)
    table.extend(bytes((-len(table)) % 4096))
    (OUT / (signer + "-table.bin")).write_bytes(table)
    for mode in ["valid", "revoked", "expired", "future"]:
        b = (x509.CertificateRevocationListBuilder().issuer_name(name("ARK-Milan"))
             .last_update(datetime(2027, 1, 1, tzinfo=timezone.utc) if mode == "future" else START)
             .next_update(datetime(2025, 1, 1, tzinfo=timezone.utc) if mode == "expired" else END))
        if mode == "revoked":
            b = b.add_revoked_certificate(x509.RevokedCertificateBuilder()
                .serial_number(serial).revocation_date(START).build())
        crl = b.sign(root_key, hashes.SHA384(), rsa_padding=PSS)
        (OUT / (signer + "-" + mode + ".crl")).write_bytes(crl.public_bytes(serialization.Encoding.DER))
# Family 1Ah changes both TCB packing and HWID size (AMD KDS 57230 rev. 1.05).
root_key = rsa.generate_private_key(65537, 4096)
root = issue("ARK-Turin", root_key, "ARK-Turin", root_key, 10, True)
write_cert("turin-root.der", root)
intermediate_key = rsa.generate_private_key(65537, 4096)
intermediate = issue("SEV-Turin", intermediate_key, "ARK-Turin", root_key, 11, True)
write_cert("turin-intermediate.der", intermediate)
key = ec.generate_private_key(ec.SECP384R1())
raw = bytearray((OUT / "vcek-report.bin").read_bytes())
raw[0x188:0x18b] = bytes([0x1a, 2, 0])
raw[0x1a8:0x1e0] = bytes(56)
for offset in [0x38, 0x180, 0x1e0, 0x1f0]:
    raw[offset:offset + 8] = bytes([1, 2, 3, 4, 0, 0, 0, 200])
r, s = decode_dss_signature(key.sign(raw[:0x2a0], ec.ECDSA(hashes.SHA384())))
raw[0x2a0:] = r.to_bytes(72, "little") + s.to_bytes(72, "little") + bytes(368)
(OUT / "turin-report.bin").write_bytes(raw)
exts = [("1", b"\x02\x01\x01"), ("2", b"\x16\x08Turin-B0"), ("4", bytes(raw[0x1a0:0x1a8]))]
exts += [(f"3.{i}", bytes([2, 1, {1: 2, 2: 3, 3: 4, 9: 1}.get(i, 0)])) for i in [1, 2, 3, 5, 6, 7, 9]]
exts += [("3.8", b"\x02\x02\x00\xc8")]
write_cert("turin.der", issue("SEV-VCEK", key, "SEV-Turin", intermediate_key, 12, False, exts))
print("Generated synthetic reports, certificates, tables, and CRLs in", OUT)
