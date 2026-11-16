"""Loopback CLI adapters for the authenticated native TLS worker."""

import base64
import hashlib
import http.server
import json
import os
import queue
import select
import signal
import socket
import struct
import threading

from tls13_product_http_h2 import receive, send

PLACEHOLDER = 'local-relay-placeholder'


def cancel_native(reason):
    """End a canceled native session and all descendants in its process group."""
    print(f'NATIVE_CANCEL {reason}', flush=True)
    if os.getpgrp() == os.getpid():
        os.killpg(os.getpgrp(), signal.SIGTERM)
    else:
        os.kill(os.getpid(), signal.SIGTERM)


def watch_disconnect(connection, done):
    """Abort bootstrap or response work when the local CLI closes its socket."""
    while not done.is_set():
        try:
            ready, _, _ = select.select([connection], [], [], 0.1)
        except (OSError, ValueError):
            return
        if done.is_set():
            return
        if not ready:
            continue
        try:
            data = connection.recv(1, socket.MSG_PEEK)
        except OSError:
            data = b''
        if not data:
            cancel_native('cli_disconnect')
            return
        done.wait(0.1)


class PendingTurns:
    """Keep queued and in-flight Codex work cancelable under one lock."""

    def __init__(self):
        """Create the request queue and its synchronized activity state."""
        self.requests = queue.Queue()
        self.lock = threading.Lock()
        self.active = False

    def enqueue(self, request):
        """Mark a new request active before publishing it to the worker."""
        with self.lock:
            self.active = True
            self.requests.put(request)

    def finished(self):
        """Clear activity only when no next request is already queued."""
        with self.lock:
            if self.requests.empty():
                self.active = False

    def cancel(self):
        """Clear activity and report whether work was queued or in flight."""
        with self.lock:
            active = self.active
            self.active = False
            return active


class Adapter(http.server.ThreadingHTTPServer):
    """Share one proved provider connection across CLI ingress requests."""

    def __init__(self, address, route, bridge):
        """Bind the selected loopback CLI route and its private bridge."""
        handler = CodexRequest if route == 'codex' else ClaudeRequest
        super().__init__(address, handler)
        self.bridge = bridge
        self.lock = threading.Lock()
        self.first = threading.Event()
        self.first_metadata = None
        self.upgraded = False
        self.completed = 0
        self.test_turns = int(os.getenv('CONCURRO_NATIVE_TEST_TURNS', '0'))


class CodexRequest(http.server.BaseHTTPRequestHandler):
    """Carry local Codex WebSocket turns through the Concurro worker."""

    protocol_version = 'HTTP/1.1'

    def exact(self, length):
        """Read a complete WebSocket field from the local CLI."""
        data = self.rfile.read(length)
        if len(data) != length:
            raise EOFError('local WebSocket closed')
        return data

    def send_frame(self, payload, opcode=1):
        """Send one unmasked server WebSocket frame."""
        size = len(payload)
        length = (bytes([size]) if size < 126 else
                  b'\x7e' + struct.pack('!H', size) if size < 65536 else
                  b'\x7f' + struct.pack('!Q', size))
        with self.frame_lock:
            self.wfile.write(bytes([0x80 | opcode]) + length + payload)
            self.wfile.flush()

    def read_message(self):
        """Assemble a masked text message and answer control frames."""
        message = bytearray()
        continuing = False
        while True:
            head = self.exact(2)
            fin, opcode = bool(head[0] & 0x80), head[0] & 15
            if head[0] & 0x70 or not head[1] & 0x80:
                raise ValueError('invalid local WebSocket flags')
            size = head[1] & 127
            if size == 126:
                size = int.from_bytes(self.exact(2), 'big')
            elif size == 127:
                size = int.from_bytes(self.exact(8), 'big')
            if size > 8 * 1024 * 1024:
                raise ValueError('oversize local WebSocket message')
            mask = self.exact(4)
            payload = bytes(value ^ mask[index % 4]
                            for index, value in enumerate(self.exact(size)))
            if opcode == 9:
                self.send_frame(payload, 10)
                continue
            if opcode == 10:
                continue
            if opcode == 8:
                self.send_frame(payload, 8)
                return None
            if opcode == 1 and not continuing:
                continuing = not fin
            elif opcode != 0 or not continuing:
                raise ValueError('unexpected WebSocket continuation')
            message.extend(payload)
            if fin:
                return json.loads(message)

    def do_GET(self):
        """Upgrade the local Responses route and relay complete turns."""
        if (self.path != '/v1/responses' or
                self.headers.get('Authorization') != 'Bearer ' + PLACEHOLDER or
                self.headers.get('Upgrade', '').lower() != 'websocket'):
            self.send_error(403)
            return
        key = self.headers.get('Sec-WebSocket-Key')
        if not key:
            self.send_error(400)
            return
        excluded = {'authorization', 'host', 'connection', 'upgrade', 'sec-websocket-key',
                    'sec-websocket-version', 'sec-websocket-extensions', 'proxy-authorization',
                    'x-api-key', 'cookie', 'chatgpt-account-id', 'content-length'}
        public = [[name, value] for name, value in self.headers.raw_items()
                  if name.lower() not in excluded]
        accept = base64.b64encode(hashlib.sha1(
            key.encode() + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest()).decode()
        self.frame_lock = threading.Lock()
        upgrade_done = threading.Event()
        threading.Thread(target=watch_disconnect,
                         args=(self.connection, upgrade_done), daemon=True).start()
        try:
            with self.server.lock:
                if not self.server.upgraded:
                    self.server.first_metadata = {'headers': public}
                    self.server.first.set()
                    send(self.server.bridge, 'ingress_upgrade', headers=public)
                    try:
                        answer = receive(self.server.bridge)
                    except EOFError:
                        self.send_error(502)
                        return
                    if answer['kind'] != 'upgrade_ok':
                        self.send_error(answer.get('status', 502))
                        return
                    self.server.upgraded = True
        finally:
            upgrade_done.set()
        self.send_response(101)
        self.send_header('Upgrade', 'websocket')
        self.send_header('Connection', 'Upgrade')
        self.send_header('Sec-WebSocket-Accept', accept)
        self.end_headers()
        self.close_connection = True
        pending = PendingTurns()

        def read_cli():
            """Queue local requests while watching for cancellation and EOF."""
            try:
                while True:
                    request = self.read_message()
                    if request is None:
                        if pending.cancel():
                            cancel_native('codex_disconnect')
                        break
                    if request.get('type') == 'response.cancel':
                        if pending.cancel():
                            cancel_native('codex_cancel')
                        continue
                    if request.get('type') != 'response.create':
                        raise ValueError('unexpected local Responses request')
                    pending.enqueue(request)
            except (EOFError, ConnectionResetError, BrokenPipeError, OSError):
                if pending.cancel():
                    cancel_native('codex_disconnect')
            except ValueError:
                cancel_native('codex_protocol')
            finally:
                pending.requests.put(None)

        threading.Thread(target=read_cli, daemon=True).start()
        while True:
            request = pending.requests.get()
            if request is None:
                break
            with self.server.lock:
                send(self.server.bridge, 'request', json.dumps(request, separators=(',', ':')).encode())
                while True:
                    event = receive(self.server.bridge)
                    if event['kind'] == 'turn_done':
                        if request.get('generate') is not False:
                            self.server.completed += 1
                        break
                    if event['kind'] != 'event':
                        raise ValueError('unexpected provider bridge message')
                    self.send_frame(event['data'])
                pending.finished()
                if self.server.test_turns and self.server.completed >= self.server.test_turns:
                    self.send_frame(b'\x03\xe8', opcode=8)
                    self.server.bridge.shutdown(socket.SHUT_WR)
                    return

    def log_message(self, *_args):
        """Avoid printing local CLI authorization or prompt bytes."""


class ClaudeRequest(http.server.BaseHTTPRequestHandler):
    """Carry local Claude HTTP requests through the indexed H2 worker."""

    protocol_version = 'HTTP/1.1'

    def do_POST(self):
        """Forward one request and return its authenticated SSE body."""
        if not self.path.startswith('/v1/messages'):
            self.send_error(404)
            return
        if self.headers.get('Authorization') != 'Bearer ' + PLACEHOLDER:
            self.send_error(403)
            return
        size = int(self.headers['Content-Length'])
        body = self.rfile.read(size)
        if len(body) != size:
            self.send_error(400)
            return
        excluded = {'authorization', 'x-api-key', 'host', 'connection', 'content-length',
                    'transfer-encoding', 'accept-encoding', 'proxy-authorization'}
        headers = [[name.lower(), value] for name, value in self.headers.raw_items()
                   if name.lower() not in excluded]
        done = threading.Event()
        threading.Thread(target=watch_disconnect,
                         args=(self.connection, done), daemon=True).start()
        started = False
        writing = False
        try:
            with self.server.lock:
                if self.server.first_metadata is None:
                    self.server.first_metadata = {'path': self.path, 'headers': headers}
                    self.server.first.set()
                send(self.server.bridge, 'request', body, path=self.path, headers=headers)
                answer = receive(self.server.bridge, 'response_start')
                writing = True
                self.send_response(answer['status'])
                self.send_header('Content-Type', answer['content_type'])
                self.send_header('Transfer-Encoding', 'chunked')
                self.end_headers()
                writing = False
                started = True
                while True:
                    answer = receive(self.server.bridge)
                    if answer['kind'] == 'response_end':
                        writing = True
                        self.wfile.write(b'0\r\n\r\n')
                        self.wfile.flush()
                        writing = False
                        break
                    if answer['kind'] != 'response_chunk':
                        raise ValueError('unexpected Claude response message')
                    payload = answer['data']
                    if payload:
                        writing = True
                        self.wfile.write(b'%X\r\n' % len(payload) + payload + b'\r\n')
                        self.wfile.flush()
                        writing = False
        except OSError:
            if writing:
                cancel_native('cli_write_failed')
            elif not started:
                try:
                    self.send_error(502, 'provider relay failed')
                except OSError:
                    pass
            self.close_connection = True
        except EOFError:
            if not started:
                try:
                    self.send_error(502, 'provider relay failed')
                except OSError:
                    pass
            self.close_connection = True
        finally:
            done.set()

    def log_message(self, *_args):
        """Avoid printing local CLI authorization or prompt bytes."""
