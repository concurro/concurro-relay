"""TLS 1.3 record and WebSocket decoding after the two-party key handoff."""
import hmac
import json
import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def expand(secret, label, size):
    """Apply SHA-256 HKDF-Expand-Label for a single-block TLS 1.3 output."""
    label = b'tls13 ' + label
    info = struct.pack('!H', size) + bytes([len(label)]) + label + b'\0'
    assert size <= 32
    return hmac.digest(secret, info + b'\x01', 'sha256')[:size]


class Epoch:
    """One AES-128-GCM direction with its implicit TLS record sequence."""

    def __init__(self, secret):
        """Derive the record key and IV at sequence zero."""
        self.secret = secret
        self.aead = AESGCM(expand(secret, b'key', 16))
        self.iv = expand(secret, b'iv', 12)
        self.sequence = 0

    def nonce(self):
        """Consume the next sequence number and return its XOR nonce."""
        result = bytes(a ^ b for a, b in zip(self.iv, self.sequence.to_bytes(12, 'big')))
        self.sequence += 1
        return result

    def encrypt(self, content, kind=23):
        """Encode one unpadded authenticated TLSInnerPlaintext record."""
        header = b'\x17\x03\x03' + struct.pack('!H', len(content) + 17)
        return header + self.aead.encrypt(self.nonce(), content + bytes([kind]), header)

    def decrypt(self, record):
        """Authenticate a record and separate its inner content type."""
        assert record[:3] == b'\x17\x03\x03'
        inner = self.aead.decrypt(self.nonce(), record[5:], record[:5]).rstrip(b'\0')
        assert inner
        return inner[-1], inner[:-1]

    def updated(self):
        """Derive the next sending or receiving epoch."""
        return Epoch(expand(self.secret, b'traffic upd', 32))


class Connection:
    """Parse authenticated provider responses over a handoff-owned record link."""

    def receive(self, count):
        """Read application bytes while authenticating tickets and KeyUpdates."""
        while len(self.buffer) < count:
            kind, content = self.read.decrypt(self.read_record())
            if kind == 23:
                self.buffer.extend(content)
            elif kind == 22:
                self.handshake_buffer.extend(content)
                while len(self.handshake_buffer) >= 4:
                    length = int.from_bytes(self.handshake_buffer[1:4], 'big')
                    if len(self.handshake_buffer) < length + 4:
                        break
                    message = bytes(self.handshake_buffer[:length+4])
                    del self.handshake_buffer[:length+4]
                    if message[0] == 4:
                        self.tickets += 1
                    else:
                        assert message == b'\x18\0\0\x01\0', message.hex()
                        assert not self.handshake_buffer
                        self.read = self.read.updated()
                        self.server_updates += 1
            elif kind == 21:
                raise ConnectionError(f'TLS alert {content.hex()}')
            else:
                raise AssertionError(f'unexpected TLS type {kind}')
        result = bytes(self.buffer[:count])
        del self.buffer[:count]
        return result

    def http(self, status=None):
        """Read an HTTP response, including chunked SSE, or a WebSocket upgrade."""
        header = bytearray()
        while not header.endswith(b'\r\n\r\n'):
            header.extend(self.receive(1))
        lines = header.decode().split('\r\n')
        self.http_status = int(lines[0].split()[1])
        if status is not None and self.http_status != status:
            raise ValueError(f'provider status {self.http_status}, expected {status}')
        fields = {name.lower(): value.strip() for name, value in
                  (line.split(':', 1) for line in lines[1:] if line)}
        if fields.get('transfer-encoding', '').lower() == 'chunked':
            body = bytearray()
            while True:
                size_line = bytearray()
                while not size_line.endswith(b'\r\n'):
                    size_line.extend(self.receive(1))
                size = int(size_line[:-2].split(b';', 1)[0], 16)
                if size == 0:
                    while True:
                        trailer = bytearray()
                        while not trailer.endswith(b'\r\n'):
                            trailer.extend(self.receive(1))
                        if trailer == b'\r\n':
                            break
                    break
                body.extend(self.receive(size))
                if self.receive(2) != b'\r\n':
                    raise ValueError('invalid HTTP chunk terminator')
            body = bytes(body)
        elif 'transfer-encoding' in fields:
            raise ValueError('unsupported HTTP transfer encoding')
        elif 'content-length' in fields:
            body = self.receive(int(fields['content-length']))
        elif self.http_status == 101:
            body = b''
        else:
            raise ValueError('response lacks explicit body framing')
        return fields, body

    def frame(self, data, opcode=1):
        """Encode a masked client text or control frame under native TLS."""
        mask = os.urandom(4)
        length = (bytes([0x80 | len(data)]) if len(data) < 126 else
                  b'\xfe' + struct.pack('!H', len(data)) if len(data) < 65536 else
                  b'\xff' + struct.pack('!Q', len(data)))
        self.send(bytes([0x80 | opcode]) + length + mask +
                  bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def event(self):
        """Assemble a server text message across frames and answer pings."""
        message = bytearray()
        continuing = False
        while True:
            head = self.receive(2)
            fin, opcode = bool(head[0] & 0x80), head[0] & 0x0f
            if head[0] & 0x70 or head[1] & 0x80:
                raise ValueError('invalid server WebSocket frame flags')
            size = head[1] & 0x7f
            if size == 126:
                size = int.from_bytes(self.receive(2), 'big')
            elif size == 127:
                size = int.from_bytes(self.receive(8), 'big')
            payload = self.receive(size)
            if opcode >= 8:
                if not fin or size > 125:
                    raise ValueError('fragmented or oversized WebSocket control frame')
                if opcode == 9:
                    self.frame(payload, opcode=10)
                    continue
                if opcode == 10:
                    continue
                if opcode == 8:
                    self.frame(payload, opcode=8)
                    raise EOFError('provider closed WebSocket')
                raise ValueError('unknown WebSocket control opcode')
            if opcode == 1 and not continuing:
                continuing = not fin
            elif opcode != 0 or not continuing:
                raise ValueError('unexpected WebSocket continuation')
            message.extend(payload)
            if fin:
                return json.loads(message)

    def close(self):
        """Close the local fixture socket."""
        self.socket.close()
