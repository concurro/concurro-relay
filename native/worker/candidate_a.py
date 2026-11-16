"""Deterministic HTTP/2 request framing for the indexed-credential experiment."""

import json
import struct

from hpack import Decoder


PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
INITIAL_TABLE_SIZE = 4096
AUTH_INDEX = 62
MAX_FRAME_SIZE = 16384


def integer(value, prefix, first=0):
    """Encode an HPACK integer with the given prefix width."""
    limit = (1 << prefix) - 1
    if value < limit:
        return bytes([first | value])
    encoded = bytearray([first | limit])
    value -= limit
    while value >= 128:
        encoded.append((value & 127) | 128)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def string(value):
    """Encode an uncompressed HPACK string."""
    return integer(len(value), 7) + value


def frame(kind, flags, stream, payload=b''):
    """Encode one bounded HTTP/2 frame."""
    if len(payload) > MAX_FRAME_SIZE or not 0 <= stream < 1 << 31:
        raise ValueError('HTTP/2 frame bounds exceeded')
    return len(payload).to_bytes(3, 'big') + bytes([kind, flags]) + struct.pack('!I', stream) + payload


def public_headers(path=b'/v1/messages', fields=()):
    """Encode public CLI request fields without changing the HPACK table."""
    if not path.startswith(b'/v1/messages') or any(char in path for char in b'\r\n'):
        raise ValueError('unsupported Claude request path')
    block = (b'\x83\x87' + integer(1, 4) + string(b'api.anthropic.com') +
             integer(4, 4) + string(path))
    for name, value in fields:
        name, value = name.lower(), bytes(value)
        if (not name or name.startswith(b':') or name in (b'authorization', b'x-api-key') or
                any(char in name + value for char in b'\r\n') or
                not all(33 <= char <= 126 for char in name)):
            raise ValueError('invalid public Claude header')
        block += integer(0, 4) + string(name) + string(value)
    return block


def bootstrap(credential, path=b'/v1/messages', fields=()):
    """Return the protected c0 HTTP/2 prefix and its private credential slot."""
    if not credential or b'\r' in credential or b'\n' in credential:
        raise ValueError('invalid credential')
    value = b'Bearer ' + credential
    block = public_headers(path, fields) + integer(23, 6, 0x40) + string(value)
    prefix = PREFACE + frame(4, 0, 0) + frame(1, 4, 1, block)
    slot = prefix.index(credential)
    return prefix, slot


class IndexedConnection:
    """Track only public HPACK metadata and serialized request streams."""

    def __init__(self, credential_length, generation=0):
        """Initialize the post-bootstrap shadow table without credential bytes."""
        self.entry_size = 52 + credential_length
        if self.entry_size > INITIAL_TABLE_SIZE:
            raise ValueError('credential exceeds initial HPACK table')
        self.generation = generation
        self.table_size = INITIAL_TABLE_SIZE
        self.next_stream = 3
        self.active_stream = 1
        self.terminal = False
        self.connection_window = 65535
        self.initial_stream_window = 65535
        self.stream_window = 65535

    def require_live(self, generation):
        """Reject stale compression state or a closed connection."""
        if self.terminal or generation != self.generation:
            raise ValueError('stale HTTP/2 connection state')

    def settings(self, header_table_size=None, initial_window_size=None):
        """Invalidate reuse on any table shrink without an HPACK size update."""
        if header_table_size is not None:
            if not 0 <= header_table_size < 1 << 32:
                raise ValueError('invalid header table size')
            if header_table_size < self.table_size:
                self.terminal = True
            self.table_size = header_table_size
        if initial_window_size is not None:
            if not 0 <= initial_window_size <= (1 << 31) - 1:
                raise ValueError('invalid initial stream window')
            self.stream_window += initial_window_size - self.initial_stream_window
            self.initial_stream_window = initial_window_size

    def window_update(self, stream, increment):
        """Apply a provider flow-control credit to this connection or active stream."""
        if not 0 < increment < 1 << 31:
            raise ValueError('invalid provider window increment')
        if stream == 0:
            self.connection_window += increment
        elif stream == self.active_stream:
            self.stream_window += increment

    def consume_window(self, size):
        """Account for a sent DATA payload in both outbound windows."""
        if size > self.connection_window or size > self.stream_window:
            raise ValueError('HTTP/2 flow-control window exhausted')
        self.connection_window -= size
        self.stream_window -= size

    def close(self):
        """Invalidate the indexed credential after GOAWAY or connection loss."""
        self.terminal = True

    def later_headers(self, generation, path=b'/v1/messages', fields=()):
        """Open one subsequent stream using only the opaque credential index."""
        self.require_live(generation)
        if self.active_stream is not None:
            raise ValueError('request stream still active')
        stream = self.next_stream
        self.next_stream += 2
        self.active_stream = stream
        self.stream_window = self.initial_stream_window
        return stream, frame(1, 4, stream, public_headers(path, fields) + integer(AUTH_INDEX, 7, 0x80))

    def data(self, stream, body, generation):
        """Complete the active stream with a bounded JSON request body."""
        self.require_live(generation)
        if stream != self.active_stream or not body or len(body) > MAX_FRAME_SIZE - 9:
            raise ValueError('invalid request DATA stream')
        json.loads(body)
        self.active_stream = None
        return frame(0, 1, stream, body)

    def data_chunk(self, stream, chunk, final, generation):
        """Frame one bounded DATA piece, ending the stream after the final piece."""
        self.require_live(generation)
        if stream != self.active_stream or not chunk or len(chunk) > MAX_FRAME_SIZE:
            raise ValueError('invalid request DATA piece')
        if final:
            self.active_stream = None
        return frame(0, int(final), stream, chunk)


class SponsorAudit:
    """Match proved raw frames to the expected credential-bearing request shape."""

    def __init__(self, credential, generation=0, templates=None):
        """Bind the audit to Sponsor's credential and one connection generation."""
        self.state = IndexedConnection(len(credential), generation)
        self.allow_default_template = templates is None
        self.templates = templates if templates is not None else [(b'/v1/messages', ())]
        self.bootstrap, self.slot = bootstrap(credential, *self.templates[0])
        self.next_stream = 1
        self.waiting_data = True
        self.prompts = []
        self.body = bytearray()

    def accept(self, plaintext, generation):
        """Audit exact HEADERS or DATA bytes after the record proof succeeds."""
        self.state.require_live(generation)
        if plaintext == frame(4, 1, 0):
            return ('control', None)
        if (len(plaintext) == 13 and plaintext[3:5] == b'\x08\0' and
                (plaintext[5:9] == b'\0\0\0\0' or
                 int.from_bytes(plaintext[5:9], 'big') in range(1, self.next_stream, 2)) and
                int.from_bytes(plaintext[9:], 'big') > 0):
            return ('control', None)
        if len(plaintext) == 17 and plaintext[3:9] == b'\x06\x01\0\0\0\0':
            return ('control', None)
        if self.waiting_data:
            stream = self.next_stream
            if (len(plaintext) < 9 or plaintext[3] != 0 or
                    plaintext[4] not in (0, 1) or
                    plaintext[5:9] != frame(0, 0, stream)[5:9]):
                raise ValueError('wrong DATA frame or stream')
            size = int.from_bytes(plaintext[:3], 'big')
            if size != len(plaintext) - 9 or size > MAX_FRAME_SIZE:
                raise ValueError('invalid DATA length')
            self.body.extend(plaintext[9:])
            if not plaintext[4] & 1:
                return ('partial', None)
            body = bytes(self.body)
            json.loads(body)
            self.prompts.append((stream, body))
            self.body.clear()
            self.waiting_data = False
            self.state.active_stream = None
            self.next_stream += 2
            return stream, body
        if not self.allow_default_template and len(self.templates) < (self.next_stream + 1) // 2:
            raise ValueError('missing public request template')
        index = (self.next_stream - 1) // 2
        template = self.templates[index] if index < len(self.templates) else self.templates[0]
        expected_stream, expected = self.state.later_headers(generation, *template)
        if plaintext != expected or expected_stream != self.next_stream:
            self.state.close()
            raise ValueError('unapproved indexed HEADERS')
        self.waiting_data = True
        return None


class ResponseReader:
    """Read authenticated HTTP/2 responses from the handed-off TLS link."""

    def __init__(self, link, state):
        """Keep response HPACK state separate from the request credential entry."""
        self.link = link
        self.state = state
        self.decoder = Decoder()

    def wait_window(self, stream):
        """Read authenticated provider control frames until request DATA can advance."""
        while self.state.connection_window <= 0 or self.state.stream_window <= 0:
            raw = self.link.receive(9)
            size = int.from_bytes(raw[:3], 'big')
            kind, flags = raw[3], raw[4]
            frame_stream = int.from_bytes(raw[5:9], 'big')
            if size > MAX_FRAME_SIZE or frame_stream & (1 << 31):
                raise ValueError('invalid provider control frame')
            payload = self.link.receive(size)
            if kind == 4 and frame_stream == 0 and not flags & 1 and size % 6 == 0:
                for offset in range(0, size, 6):
                    setting = int.from_bytes(payload[offset:offset + 2], 'big')
                    value = int.from_bytes(payload[offset + 2:offset + 6], 'big')
                    if setting == 1:
                        self.state.settings(header_table_size=value)
                    elif setting == 4:
                        self.state.settings(initial_window_size=value)
                self.state.require_live(self.state.generation)
                self.link.send(frame(4, 1, 0))
            elif kind == 4 and frame_stream == 0 and flags == 1 and size == 0:
                continue
            elif kind == 8 and size == 4 and not flags:
                self.state.window_update(frame_stream, int.from_bytes(payload, 'big') & 0x7fffffff)
            elif kind == 6 and frame_stream == 0 and size == 8 and not flags:
                self.link.send(frame(6, 1, 0, payload))
            elif kind == 7:
                self.state.close()
                raise ConnectionError('provider GOAWAY while sending request')
            else:
                raise ValueError(f'unexpected provider frame {kind} during request upload')

    def read_stream(self, stream, on_headers=None, on_data=None):
        """Validate a response, forwarding headers and DATA before completion."""
        self.state.require_live(self.state.generation)
        headers = None
        body = bytearray()
        header_block = bytearray()
        continuation = False
        headers_end_stream = False
        while True:
            raw = self.link.receive(9)
            size = int.from_bytes(raw[:3], 'big')
            kind, flags = raw[3], raw[4]
            frame_stream = int.from_bytes(raw[5:9], 'big')
            if frame_stream & (1 << 31) or size > MAX_FRAME_SIZE:
                raise ValueError('invalid server HTTP/2 frame')
            payload = self.link.receive(size)
            if continuation and (kind != 9 or frame_stream != stream):
                raise ValueError('incomplete response HEADERS')
            if kind == 4:
                if frame_stream or (flags & ~1) or (flags & 1 and size) or size % 6:
                    raise ValueError('invalid server SETTINGS')
                if not flags & 1:
                    for offset in range(0, size, 6):
                        setting = int.from_bytes(payload[offset:offset + 2], 'big')
                        value = int.from_bytes(payload[offset + 2:offset + 6], 'big')
                        if setting == 1:
                            self.state.settings(value)
                        elif setting == 4:
                            self.state.settings(initial_window_size=value)
                    self.state.require_live(self.state.generation)
                    self.link.send(frame(4, 1, 0))
                continue
            if kind == 7:
                self.state.close()
                raise ConnectionError('provider GOAWAY')
            if kind == 3 and frame_stream == stream:
                self.state.close()
                raise ConnectionError('provider reset request stream')
            if kind == 8:
                if size != 4 or flags or payload == b'\0\0\0\0':
                    raise ValueError('invalid WINDOW_UPDATE')
                self.state.window_update(frame_stream, int.from_bytes(payload, 'big') & 0x7fffffff)
                continue
            if kind == 1 or kind == 9:
                if (frame_stream != stream or flags & ~5 or (kind == 1 and headers is not None)
                        or (kind == 9 and (not continuation or flags & 1))):
                    raise ValueError('unexpected response HEADERS')
                if kind == 1:
                    headers_end_stream = bool(flags & 1)
                header_block.extend(payload)
                continuation = not bool(flags & 4)
                if not continuation:
                    decoded = self.decoder.decode(bytes(header_block), raw=True)
                    headers = dict(decoded)
                    header_block.clear()
                    if b':status' not in headers:
                        raise ValueError('missing response status')
                    if on_headers is not None:
                        on_headers(int(headers[b':status']), headers)
                    if headers_end_stream:
                        return int(headers[b':status']), headers, bytes(body)
                continue
            if kind == 0:
                if frame_stream != stream or headers is None or flags & ~1:
                    raise ValueError('unexpected response DATA')
                body.extend(payload)
                if payload and on_data is not None:
                    on_data(payload)
                if size:
                    self.link.send(frame(8, 0, 0, size.to_bytes(4, 'big')))
                    self.link.send(frame(8, 0, stream, size.to_bytes(4, 'big')))
                if flags & 1:
                    return int(headers[b':status']), headers, bytes(body)
                continue
            if kind == 6:
                if frame_stream or size != 8 or flags & ~1:
                    raise ValueError('invalid PING')
                if not flags & 1:
                    self.link.send(frame(6, 1, 0, payload))
                continue
            if kind == 2 and size == 5 and frame_stream:
                continue
            raise ValueError(f'unsupported server HTTP/2 frame {kind}')
