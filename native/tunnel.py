"""Multiplex native MPC TCP streams over one authenticated relay connection."""

import json
import queue
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass, field

HEADER = struct.Struct('!cII')
MAX_FRAME = 65536


def exact(sock, size):
    """Read an entire tunnel frame field or report a closed relay link."""
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise EOFError('authenticated tunnel link closed')
        data.extend(part)
    return bytes(data)


@dataclass
class Channel:
    """Own a local native socket and its ordered inbound writes."""

    socket: socket.socket
    inbound: queue.Queue = field(default_factory=queue.Queue)
    ended: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def finish(self):
        """Close the local native socket after both directions end."""
        with self.lock:
            self.ended += 1
            if self.ended == 2:
                self.socket.close()


class Tunnel:
    """Register Sponsor listeners and carry their byte streams to Concurro."""

    def __init__(self, link, role):
        """Keep framing state on the role's authenticated auxiliary link."""
        if role not in ('sponsor', 'concurro'):
            raise ValueError('unknown native tunnel role')
        self.link = link
        self.role = role
        self.write_lock = threading.Lock()
        self.state_lock = threading.Lock()
        self.registrations = {}
        self.acknowledgements = {}
        self.targets = {}
        self.target_events = {}
        self.channels = {}
        self.listeners = []
        self.next_id = 1
        self.error = None
        self.reader = threading.Thread(target=self._read_loop, daemon=True)

    def start(self):
        """Receive tunnel frames independently of native worker calls."""
        self.reader.start()
        return self

    def _send(self, kind, channel, payload=b''):
        """Serialize one bounded frame on the authenticated auxiliary link."""
        if len(payload) > MAX_FRAME:
            raise ValueError('native tunnel frame too large')
        with self.write_lock:
            self.link.sendall(HEADER.pack(kind, channel, len(payload)) + payload)

    def _number(self):
        """Allocate a connection or registration identifier."""
        with self.state_lock:
            number = self.next_id
            self.next_id += 1
        return number

    def register(self, target_port):
        """Expose a Sponsor local service at a Concurro local port."""
        if self.role != 'sponsor':
            raise ValueError('only Sponsor registers native listeners')
        number = self._number()
        ready = threading.Event()
        self.acknowledgements[number] = [ready, None]
        self.registrations[number] = target_port
        self._send(b'R', number, struct.pack('!H', target_port))
        if not ready.wait(90):
            raise TimeoutError('native tunnel registration timed out')
        if self.error is not None:
            raise RuntimeError('native tunnel failed') from self.error
        port = self.acknowledgements.pop(number)[1]
        if not isinstance(port, int):
            raise RuntimeError('native tunnel registration lacks a port')
        return port

    def wait_target(self, target_port):
        """Wait for Sponsor's named listener to appear on this machine."""
        if self.role != 'concurro':
            raise ValueError('only Concurro waits for registered targets')
        with self.state_lock:
            ready = self.target_events.setdefault(target_port, threading.Event())
        if not ready.wait(90):
            raise TimeoutError('native tunnel target registration timed out')
        if self.error is not None:
            raise RuntimeError('native tunnel failed') from self.error
        return self.targets[target_port]

    def start_admin(self):
        """Accept the existing link_register JSON request on loopback."""
        if self.role != 'sponsor':
            raise ValueError('only Sponsor serves native tunnel registration')
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(8)
        self.listeners.append(listener)
        threading.Thread(target=self._admin_loop, args=(listener,), daemon=True).start()
        return listener.getsockname()[1]

    def _admin_loop(self, listener):
        """Answer each public port registration with its remote loopback port."""
        while True:
            try:
                client, _ = listener.accept()
            except OSError:
                return
            threading.Thread(target=self._admin_request, args=(client,), daemon=True).start()

    def _admin_request(self, client):
        """Translate one existing admin request into a tunnel registration."""
        with client:
            request = json.loads(client.makefile('rb').readline(1024))
            if request.get('kind') != 'register':
                raise ValueError('unsupported native tunnel admin request')
            port = self.register(int(request['port']))
            client.sendall(json.dumps({'port': port}).encode() + b'\n')

    def _accept_loop(self, listener, registration):
        """Open a multiplexed channel for each local native connection."""
        while True:
            try:
                client, _ = listener.accept()
            except OSError:
                return
            number = self._number()
            ready = threading.Event()
            self._start_channel(number, client, ready)
            self._send(b'O', number, struct.pack('!I', registration))
            ready.set()

    def _start_channel(self, number, local, ready=None):
        """Pump both byte directions without blocking the frame reader."""
        local.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        channel = Channel(local)
        self.channels[number] = channel
        threading.Thread(target=self._pump_out, args=(number, channel, ready), daemon=True).start()
        threading.Thread(target=self._pump_in, args=(number, channel), daemon=True).start()

    def _pump_out(self, number, channel, ready):
        """Send local native bytes and their half-close over the relay link."""
        try:
            if ready is not None:
                ready.wait()
            while data := channel.socket.recv(MAX_FRAME):
                self._send(b'D', number, data)
            self._send(b'E', number)
        except OSError as error:
            print(f'NATIVE_TUNNEL outbound {number}: {error!r}', file=sys.stderr,
                  flush=True)
        finally:
            channel.finish()

    def _pump_in(self, _number, channel):
        """Write remote native bytes without blocking other channels."""
        try:
            while (data := channel.inbound.get()) is not None:
                channel.socket.sendall(data)
            channel.socket.shutdown(socket.SHUT_WR)
        except OSError as error:
            print(f'NATIVE_TUNNEL inbound {_number}: {error!r}', file=sys.stderr,
                  flush=True)
        finally:
            channel.finish()

    def _read_loop(self):
        """Dispatch registered ports and data frames from the authenticated link."""
        try:
            while True:
                kind, number, size = HEADER.unpack(exact(self.link, HEADER.size))
                if size > MAX_FRAME:
                    raise ValueError('native tunnel frame too large')
                payload = exact(self.link, size)
                if kind == b'R' and self.role == 'concurro':
                    target, = struct.unpack('!H', payload)
                    listener = socket.socket()
                    listener.bind(('127.0.0.1', 0))
                    listener.listen(8)
                    self.listeners.append(listener)
                    port = listener.getsockname()[1]
                    with self.state_lock:
                        self.targets[target] = port
                        self.target_events.setdefault(target, threading.Event()).set()
                    threading.Thread(target=self._accept_loop,
                                     args=(listener, number), daemon=True).start()
                    self._send(b'A', number, struct.pack('!H', port))
                elif kind == b'A' and self.role == 'sponsor':
                    port, = struct.unpack('!H', payload)
                    acknowledgement = self.acknowledgements[number]
                    acknowledgement[1] = port
                    acknowledgement[0].set()
                elif kind == b'O' and self.role == 'sponsor':
                    registration, = struct.unpack('!I', payload)
                    target = self.registrations[registration]
                    started = time.monotonic()
                    while True:
                        try:
                            local = socket.create_connection(('127.0.0.1', target), timeout=90)
                            break
                        except ConnectionRefusedError:
                            if time.monotonic() - started >= 90:
                                raise
                            time.sleep(.02)
                    if time.monotonic() - started >= .02:
                        print(f'NATIVE_TUNNEL target_ready={target} '
                              f'wait_ms={(time.monotonic() - started) * 1000:.1f}',
                              file=sys.stderr, flush=True)
                    self._start_channel(number, local)
                elif kind == b'D':
                    self.channels[number].inbound.put(payload)
                elif kind == b'E':
                    self.channels[number].inbound.put(None)
                else:
                    raise ValueError('unexpected native tunnel frame')
        except BaseException as error:
            self.error = error
            print(f'NATIVE_TUNNEL reader: {error!r}', file=sys.stderr, flush=True)
            for listener in self.listeners:
                listener.close()
            for channel in self.channels.values():
                channel.inbound.put(None)
            for ready, _ in self.acknowledgements.values():
                ready.set()
            for ready in self.target_events.values():
                ready.set()

    def close(self):
        """End the tunnel and its local listeners."""
        self.link.close()
        for listener in self.listeners:
            listener.close()
        self.reader.join(timeout=5)
