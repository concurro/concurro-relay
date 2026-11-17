"""Freeze fixture-only TLS records produced and accepted by the Python reference."""

import base64
import datetime
import hashlib
import hmac
import json
import pathlib
import sys
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "native/worker"))
import tls13_joint as codex
import tls13_joint_h2 as claude
from tls13_product_native import Epoch, expand

HOST = "fixture.example"
POINT = bytes.fromhex(
    "04" + "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    + "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)
SERVER_SECRET = bytes(range(32))
CLIENT_SECRET = bytes(range(32, 64))


def encoded(value):
    """Write bytes as compact base64 in the frozen JSON fixture."""
    return base64.b64encode(value).decode("ascii")


def certificate(key, issuer, issuer_key, name, is_ca):
    """Build a long-lived fixture certificate with explicit DNS identity."""
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject if issuer else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2035, 1, 1, tzinfo=datetime.timezone.utc))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.KeyUsage(digital_signature=not is_ca, content_commitment=False,
                                     key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=is_ca, crl_sign=is_ca,
                                     encipher_only=False, decipher_only=False), critical=True)
    )
    if issuer:
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
    if not is_ca:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False
        ).add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    return builder.sign(private_key=issuer_key or key, algorithm=hashes.SHA256())


def profile(name, module, ca, ca_key):
    """Produce and verify one complete Python reference server flight."""
    key = ec.generate_private_key(ec.SECP256R1()) if name == "codex" else rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = certificate(key, ca, ca_key, HOST, False)
    client = module.client_hello(HOST, POINT)
    session = module.validate_client_hello(client, HOST, POINT)
    ext = module.extension(43, b"\x03\x04") + module.extension(51, b"\x00\x17" + module.packed(POINT))
    server = module.handshake(2, b"\x03\x03" + bytes(range(64, 96)) + module.packed(session, 1) + b"\x13\x01\x00" + module.packed(ext))
    module.server_hello(server, session)
    ee = module.handshake(8, module.packed(module.extension(16, module.packed(module.packed(b"h2", 1))) if name == "claude_h2" else b""))
    entry = module.packed(leaf.public_bytes(serialization.Encoding.DER), 3) + module.packed(b"")
    cert = module.handshake(11, b"\x00" + module.packed(entry, 3))
    signed = b" " * 64 + b"TLS 1.3, server CertificateVerify\0" + hashlib.sha256(client + server + ee + cert).digest()
    if name == "codex":
        scheme = b"\x04\x03"
        signature = key.sign(signed, ec.ECDSA(hashes.SHA256()))
    else:
        scheme = b"\x08\x04"
        signature = key.sign(signed, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    cv = module.handshake(15, scheme + module.packed(signature))
    finished_key = expand(SERVER_SECRET, b"finished", 32)
    finished = module.handshake(20, hmac.digest(finished_key, hashlib.sha256(client + server + ee + cert + cv).digest(), "sha256"))
    stream = ee + cert + cv + finished
    chunks = [stream[:2], stream[2:len(stream)//2], stream[len(stream)//2:]]
    epoch = Epoch(SERVER_SECRET)
    records = [epoch.encrypt(chunk, 22) for chunk in chunks]
    with tempfile.TemporaryDirectory() as directory:
        ca_path = pathlib.Path(directory) / "ca.pem"
        ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        flight = module.ServerFlight(client, server, SERVER_SECRET, ca_path, HOST)
        assert [flight.feed(record) for record in records] == [False, False, True]
        client_finished, h3 = flight.client_finished(CLIENT_SECRET)
        bad_alpn = module.handshake(8, module.packed(b"" if name == "claude_h2" else module.extension(16, module.packed(module.packed(b"h2", 1)))))
        bad_alpn_record = Epoch(SERVER_SECRET).encrypt(bad_alpn, 22)
        bad_flight = module.ServerFlight(client, server, SERVER_SECRET, ca_path, HOST)
        try:
            bad_flight.feed(bad_alpn_record)
        except ValueError:
            pass
        else:
            raise AssertionError("reference accepted unsupported ALPN")
    bad = bytearray(finished)
    bad[-1] ^= 1
    bad_stream = ee + cert + cv + bad
    bad_epoch = Epoch(SERVER_SECRET)
    bad_records = [bad_epoch.encrypt(bad_stream[:2], 22), bad_epoch.encrypt(bad_stream[2:len(stream)//2], 22), bad_epoch.encrypt(bad_stream[len(stream)//2:], 22)]
    return {
        "client": encoded(client), "server": encoded(server),
        "records": [encoded(record) for record in records],
        "bad_finished_records": [encoded(record) for record in bad_records],
        "bad_alpn_record": encoded(bad_alpn_record),
        "client_finished": encoded(client_finished), "h3": encoded(h3),
    }


def main():
    """Write both ALPN profiles and post-handshake reference records."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = certificate(ca_key, None, None, "Fixture CA", True)
    other_key = ec.generate_private_key(ec.SECP256R1())
    other = certificate(other_key, None, None, "Other CA", True)
    result = {
        "hostname": HOST,
        "joint_point": encoded(POINT),
        "server_secret": encoded(SERVER_SECRET),
        "client_secret": encoded(CLIENT_SECRET),
        "ca_pem": ca.public_bytes(serialization.Encoding.PEM).decode(),
        "other_ca_pem": other.public_bytes(serialization.Encoding.PEM).decode(),
        "codex": profile("codex", codex, ca, ca_key),
        "claude_h2": profile("claude_h2", claude, ca, ca_key),
    }
    epoch = Epoch(SERVER_SECRET)
    ticket = codex.handshake(4, b"ticket")
    update = b"\x18\0\0\x01\0"
    first = epoch.encrypt(ticket[:3], 22)
    second = epoch.encrypt(ticket[3:] + update, 22)
    next_secret = epoch.updated().secret
    after = epoch.updated().encrypt(b"after update")
    result["post_handshake"] = {"records": [encoded(first), encoded(second), encoded(after)], "next_secret": encoded(next_secret)}
    output = ROOT / "native/port-reference/tls13-fixture.json"
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(f"Wrote {output}")


if __name__ == "__main__":
    main()
