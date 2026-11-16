"""Versioned joint TLS 1.3 handshake offering only HTTP/2 ALPN."""
import hashlib
import hmac
import os
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.verification import PolicyBuilder, Store

from tls13_product_native import Epoch, expand


def take(data, offset, length):
    """Read a fixed-width TLS field with a bounds check."""
    end = offset + length
    if end > len(data):
        raise ValueError('truncated TLS field')
    return data[offset:end], end


def vector(data, offset, width):
    """Read a length-prefixed TLS vector."""
    encoded, offset = take(data, offset, width)
    return take(data, offset, int.from_bytes(encoded, 'big'))


def packed(data, width=2):
    """Encode a bounded TLS vector."""
    if len(data) >= 1 << (8 * width):
        raise ValueError('TLS vector is too long')
    return len(data).to_bytes(width, 'big') + data


def extension(kind, data):
    """Encode one TLS extension."""
    return struct.pack('!H', kind) + packed(data)


def handshake(kind, body):
    """Encode one TLS handshake message."""
    return bytes([kind]) + packed(body, 3)


def record(kind, body):
    """Encode one plaintext TLS record."""
    return bytes([kind]) + b'\x03\x03' + packed(body)


def extensions(data):
    """Parse unique extensions into their type-to-value map."""
    found = {}
    offset = 0
    while offset < len(data):
        raw_kind, offset = take(data, offset, 2)
        value, offset = vector(data, offset, 2)
        kind = int.from_bytes(raw_kind, 'big')
        if kind in found:
            raise ValueError('duplicate TLS extension')
        found[kind] = value
    return found


def client_hello(hostname, joint_point):
    """Offer the single supported P-256 and AES-128-GCM/SHA-256 profile."""
    if len(joint_point) != 65 or joint_point[0] != 4:
        raise ValueError('invalid joint public key encoding')
    host = hostname.encode('ascii')
    session = os.urandom(32)
    server_name = packed(b'\0' + packed(host))
    groups = packed(b'\0\x17')
    signatures = packed(bytes.fromhex('040308040805080605030603'))
    versions = b'\x02\x03\x04'
    key_share = packed(b'\0\x17' + packed(joint_point))
    ext = (extension(0, server_name) + extension(10, groups) +
           extension(13, signatures) + extension(16, packed(packed(b'h2', 1))) +
           extension(43, versions) +
           extension(51, key_share))
    body = (b'\x03\x03' + os.urandom(32) + packed(session, 1) +
            packed(b'\x13\x01') + b'\x01\0' + packed(ext))
    return handshake(1, body)


def validate_client_hello(message, hostname, joint_point):
    """Bind the received ClientHello to the agreed host, key share and profile."""
    if len(message) < 4 or message[0] != 1 or int.from_bytes(message[1:4], 'big') != len(message) - 4:
        raise ValueError('not a complete ClientHello')
    body = message[4:]
    legacy, offset = take(body, 0, 2)
    _, offset = take(body, offset, 32)
    session, offset = vector(body, offset, 1)
    suites, offset = vector(body, offset, 2)
    compression, offset = vector(body, offset, 1)
    ext_raw, offset = vector(body, offset, 2)
    if (offset != len(body) or legacy != b'\x03\x03' or len(session) != 32 or
            suites != b'\x13\x01' or compression != b'\0'):
        raise ValueError('ClientHello profile mismatch')
    ext = extensions(ext_raw)
    if set(ext) != {0, 10, 13, 16, 43, 51}:
        raise ValueError('ClientHello extensions mismatch')
    host_list, end = vector(ext[0], 0, 2)
    name, name_end = vector(host_list, 1, 2)
    if (end != len(ext[0]) or host_list[:1] != b'\0' or name_end != len(host_list) or
            name != hostname.encode('ascii') or ext[10] != packed(b'\0\x17') or
            ext[16] != packed(packed(b'h2', 1)) or ext[43] != b'\x02\x03\x04' or
            ext[51] != packed(b'\0\x17' + packed(joint_point))):
        raise ValueError('ClientHello public binding mismatch')
    algorithms, end = vector(ext[13], 0, 2)
    if end != len(ext[13]) or b'\x04\x03' not in algorithms:
        raise ValueError('ClientHello signature algorithms mismatch')
    return session


def server_hello(message, session):
    """Validate ServerHello's selected profile and return its P-256 point."""
    if len(message) < 4 or message[0] != 2 or int.from_bytes(message[1:4], 'big') != len(message) - 4:
        raise ValueError('not a complete ServerHello')
    body = message[4:]
    legacy, offset = take(body, 0, 2)
    random, offset = take(body, offset, 32)
    echoed, offset = vector(body, offset, 1)
    suite, offset = take(body, offset, 2)
    compression, offset = take(body, offset, 1)
    ext_raw, offset = vector(body, offset, 2)
    if (offset != len(body) or legacy != b'\x03\x03' or echoed != session or
            suite != b'\x13\x01' or compression != b'\0' or
            random == bytes.fromhex('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c')):
        raise ValueError('ServerHello profile mismatch or HelloRetryRequest')
    ext = extensions(ext_raw)
    if set(ext) != {43, 51} or ext[43] != b'\x03\x04':
        raise ValueError('ServerHello extension mismatch')
    point, end = vector(ext[51], 2, 2)
    if ext[51][:2] != b'\0\x17' or end != len(ext[51]) or len(point) != 65 or point[0] != 4:
        raise ValueError('invalid server P-256 point')
    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    return point


def read_record(socket):
    """Read one complete TLS record from the sponsor's provider socket."""
    header = bytearray()
    while len(header) < 5:
        part = socket.recv(5 - len(header))
        if not part:
            raise EOFError('provider closed during handshake')
        header.extend(part)
    if header[1:3] != b'\x03\x03' or int.from_bytes(header[3:5], 'big') > 16640:
        raise ValueError('invalid TLS record header')
    body = bytearray()
    length = int.from_bytes(header[3:5], 'big')
    while len(body) < length:
        part = socket.recv(length - len(body))
        if not part:
            raise EOFError('truncated TLS record')
        body.extend(part)
    return bytes(header + body)


def certificate_chain(body):
    """Decode a TLS 1.3 Certificate message into DER certificates."""
    context, offset = vector(body, 0, 1)
    entries, offset = vector(body, offset, 3)
    if context or offset != len(body):
        raise ValueError('unexpected certificate context')
    certificates = []
    index = 0
    while index < len(entries):
        cert, index = vector(entries, index, 3)
        _, index = vector(entries, index, 2)
        certificates.append(x509.load_der_x509_certificate(cert))
    if not certificates:
        raise ValueError('empty certificate chain')
    return certificates


def verify_signature(body, certificate, transcript):
    """Verify the TLS 1.3 server CertificateVerify signature."""
    scheme_raw, offset = take(body, 0, 2)
    signature, offset = vector(body, offset, 2)
    if offset != len(body):
        raise ValueError('trailing CertificateVerify bytes')
    signed = b' ' * 64 + b'TLS 1.3, server CertificateVerify\0' + hashlib.sha256(transcript).digest()
    scheme = int.from_bytes(scheme_raw, 'big')
    key = certificate.public_key()
    if scheme == 0x0403 and isinstance(key, ec.EllipticCurvePublicKey):
        key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
    elif scheme == 0x0804 and isinstance(key, rsa.RSAPublicKey):
        key.verify(signature, signed, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                  salt_length=32), hashes.SHA256())
    else:
        raise ValueError(f'unsupported certificate signature scheme {scheme:#x}')


class ServerFlight:
    """Authenticate original encrypted server records through Finished."""

    def __init__(self, client_hello_bytes, server_hello_bytes, server_secret, ca_path, hostname):
        """Start transcript validation from the exact public hello messages."""
        self.transcript = bytearray(client_hello_bytes + server_hello_bytes)
        self.epoch = Epoch(server_secret)
        self.hostname = hostname
        self.ca = Store(x509.load_pem_x509_certificates(ca_path.read_bytes()))
        self.buffer = bytearray()
        self.stage = 0
        self.finished = False
        self.leaf = None

    def feed(self, wire):
        """Validate a provider-origin record and report whether Finished is complete."""
        if self.finished:
            raise ValueError('server flight already finished')
        if wire[:5] == b'\x14\x03\x03\0\x01' and wire[5:] == b'\x01':
            return False
        if len(wire) < 5 or wire[0] != 23:
            raise ValueError('unexpected server handshake record')
        kind, plaintext = self.epoch.decrypt(wire)
        if kind != 22:
            raise ValueError('server sent non-handshake content before Finished')
        self.buffer.extend(plaintext)
        expected = (8, 11, 15, 20)
        while len(self.buffer) >= 4:
            size = int.from_bytes(self.buffer[1:4], 'big') + 4
            if len(self.buffer) < size:
                break
            message = bytes(self.buffer[:size])
            del self.buffer[:size]
            if self.stage >= len(expected) or message[0] != expected[self.stage]:
                raise ValueError('unexpected server handshake message order')
            body = message[4:]
            if self.stage == 0:
                ext_raw, end = vector(body, 0, 2)
                parsed = extensions(ext_raw)
                groups = parsed.pop(10, None)
                if groups is not None:
                    values, group_end = vector(groups, 0, 2)
                    if group_end != len(groups) or len(values) % 2 or b'\0\x17' not in [values[i:i + 2] for i in range(0, len(values), 2)]:
                        raise ValueError('invalid EncryptedExtensions supported groups')
                selected = parsed.pop(16, None)
                if selected != packed(packed(b'h2', 1)):
                    raise ValueError('server did not select h2 ALPN')
                if end != len(body) or parsed not in ({}, {0: b''}):
                    raise ValueError(f'unexpected EncryptedExtensions {parsed!r}')
            elif self.stage == 1:
                chain = certificate_chain(body)
                verifier = PolicyBuilder().store(self.ca).build_server_verifier(x509.DNSName(self.hostname))
                verifier.verify(chain[0], chain[1:])
                self.leaf = chain[0]
            elif self.stage == 2:
                verify_signature(body, self.leaf, bytes(self.transcript))
            else:
                if len(body) != 32:
                    raise ValueError('wrong Finished length')
                key = expand(self.epoch.secret, b'finished', 32)
                want = hmac.digest(key, hashlib.sha256(self.transcript).digest(), 'sha256')
                if not hmac.compare_digest(body, want):
                    raise ValueError('server Finished mismatch')
                self.finished = True
            self.transcript.extend(message)
            self.stage += 1
        if self.finished and self.buffer:
            raise ValueError('extra handshake bytes after Finished')
        return self.finished

    def client_finished(self, client_secret):
        """Produce the client Finished record after verified server Finished."""
        if not self.finished:
            raise ValueError('server Finished was not verified')
        h3 = hashlib.sha256(self.transcript).digest()
        key = expand(client_secret, b'finished', 32)
        finished = handshake(20, hmac.digest(key, h3, 'sha256'))
        return Epoch(client_secret).encrypt(finished, 22), h3
