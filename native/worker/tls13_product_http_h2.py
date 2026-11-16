"""Versioned two-process HTTP/2 indexed-credential transport experiment."""
import argparse
import base64
from collections import deque
import fcntl
import hashlib
import hmac
import json
import os
import re
import runpy
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

from cryptography import x509

ROOT = Path(os.environ['HANDOFF_BUILD_ROOT'])

from tls13_product_native import Connection, Epoch, expand
import tls13_joint
import tls13_joint_h2
from tls13_joint_h2 import read_record, record
from candidate_a import IndexedConnection, ResponseReader, SponsorAudit, bootstrap


CHECKOUT = ROOT / 'DiStefano'
HANDOFF_PARTY = Path(os.getenv('HANDOFF_PARTY_BINARY', CHECKOUT / 'build/HandoffParty'))
PROOF = ROOT / 'request-proof/target/release/handoff-request-proof'
MP_SPDZ = ROOT / 'MP-SPDZ'
P256_PRIME = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
CONTROL_TRAFFIC = dict(sent=0, received=0)
BENCHMARK_TIMEOUT = int(os.getenv('HANDOFF_BENCHMARK_TIMEOUT', '0'))


def link_register(port):
    """Publish one sponsor TCP endpoint through the shared WAN link when enabled."""
    admin_port = os.getenv('HANDOFF_LINK_ADMIN')
    if admin_port is None:
        return int(port)
    with socket.create_connection(('127.0.0.1', int(admin_port))) as control:
        control.sendall(json.dumps({'kind': 'register', 'port': int(port)}).encode() + b'\n')
        reply = control.makefile().readline()
    return int(json.loads(reply)['port'])


def exact(control, length):
    """Read a complete framed control message without accepting EOF as data."""
    data = bytearray()
    while len(data) < length:
        part = control.recv(length - len(data))
        if not part:
            raise EOFError('control peer closed')
        data.extend(part)
    return bytes(data)


def send(control, kind, payload=b'', **metadata):
    """Send one bounded JSON control message with optional binary payload."""
    message = json.dumps(dict(kind=kind, data=base64.b64encode(payload).decode(), **metadata),
                         separators=(',', ':')).encode()
    if len(message) > 1000000:
        raise ValueError('control message too large')
    control.sendall(len(message).to_bytes(4, 'big') + message)
    CONTROL_TRAFFIC['sent'] += len(message) + 4


def receive(control, kind=None):
    """Read and check the next control message."""
    length = int.from_bytes(exact(control, 4), 'big')
    if length > 1000000:
        raise ValueError('oversize control message')
    message = json.loads(exact(control, length))
    CONTROL_TRAFFIC['received'] += length + 4
    if kind is not None and message['kind'] != kind:
        raise ValueError(f"expected {kind}, got {message['kind']}")
    message['data'] = base64.b64decode(message['data'], validate=True)
    return message


def authenticate(control, role):
    """Verify the expected interservice certificate before protocol messages."""
    if os.getenv('HANDOFF_REQUIRE_AUTH') != '1':
        return control
    ca = os.environ['HANDOFF_PEER_CA']
    if role == 'sponsor':
        cert = os.environ['HANDOFF_PEER_CERT']
        key = os.environ['HANDOFF_PEER_KEY']
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        context.load_verify_locations(ca)
        context.verify_mode = ssl.CERT_REQUIRED
        channel = context.wrap_socket(control, server_side=True)
        peer = x509.load_der_x509_certificate(channel.getpeercert(binary_form=True))
        names = peer.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if 'concurro.local' not in names.get_values_for_type(x509.DNSName):
            raise ssl.SSLCertVerificationError('unexpected control peer identity')
        return channel
    context = ssl.create_default_context(cafile=ca)
    if os.getenv('HANDOFF_PEER_CERT') and os.getenv('HANDOFF_PEER_KEY'):
        context.load_cert_chain(os.environ['HANDOFF_PEER_CERT'], os.environ['HANDOFF_PEER_KEY'])
    return context.wrap_socket(control, server_hostname='sponsor.local')


def native_share(control, role):
    """Commit public P-256 contributions before either side reveals its offer."""
    helper = subprocess.Popen([str(CHECKOUT / 'build/HandoffKeyShare')],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
    offer = helper.stdout.read(69)
    if len(offer) != 69:
        raise ValueError('native key-share helper failed')
    nonce = os.urandom(16)
    send(control, 'nonce', nonce)
    other_nonce = receive(control, 'nonce')['data']
    session = hashlib.sha256(nonce + other_nonce if role == 'sponsor' else other_nonce + nonce).digest()
    commitment = hashlib.sha256(b'Concurro/joint-dh/v1' + session + offer).digest()
    send(control, 'dh_commit', commitment)
    other_commit = receive(control, 'dh_commit')['data']
    send(control, 'dh_offer', offer)
    other_offer = receive(control, 'dh_offer')['data']
    if (len(other_offer) != 69 or
            not hmac.compare_digest(other_commit, hashlib.sha256(b'Concurro/joint-dh/v1' + session + other_offer).digest())):
        raise ValueError('peer DH offer differs from commitment')
    helper.stdin.write(other_offer); helper.stdin.flush()
    joint = helper.stdout.read(65)
    if len(joint) != 65 or joint[0] != 4:
        raise ValueError('native joint key share failed')
    send(control, 'joint_hash', hashlib.sha256(joint).digest())
    if receive(control, 'joint_hash')['data'] != hashlib.sha256(joint).digest():
        raise ValueError('joint public key differs')
    return helper, joint, session


def contribution(helper, server_point):
    """Obtain this party's private affine contribution to the joint ECDH point."""
    helper.stdin.write(b'\0\x17\0A' + server_point); helper.stdin.flush()
    point = helper.stdout.read(64)
    helper.stdin.close()
    if helper.wait(timeout=5) != 0 or len(point) != 64:
        raise ValueError('native P-256 contribution failed')
    return point


def arithmetic_share(control, role, point, session_id, h2, directory):
    """Privately receive one checked P-256 x share after MASCOT exits cleanly."""
    if role == 'sponsor':
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            base = reservation.getsockname()[1]
            mapped = link_register(base)
            send(control, 'mascot_port', base=base, mapped=mapped,
                 session=session_id.hex())
        port = base
    else:
        assignment = receive(control, 'mascot_port')
        if assignment['session'] != session_id.hex():
            raise ValueError('MASCOT port session differs')
        mapped = assignment['mapped']
        port = mapped
        os.environ['HANDOFF_MASCOT_PROXY_PORT'] = str(port)
    my_port = None
    if role == 'concurro':
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            my_port = reservation.getsockname()[1]
    print(f'NATIVE_MASCOT_PORT role={role} session={session_id.hex()} '
          f'coordination={port} mapped={mapped} own={my_port}',
          file=sys.stderr, flush=True)
    party = 0 if role == 'sponsor' else 1
    runtime = directory / f'{role}-mascot'
    data = runtime / 'Player-Data'
    data.mkdir(parents=True, mode=0o700)
    (runtime / 'Programs').symlink_to(MP_SPDZ / 'Programs', target_is_directory=True)
    for peer in (0, 1):
        shutil.copyfile(directory / 'mascot-certs' / f'P{peer}.pem', data / f'P{peer}.pem')
    shutil.copyfile(directory / 'mascot-certs' / f'P{party}.key', data / f'P{party}.key')
    subprocess.run(['openssl', 'rehash', str(data)], check=True, capture_output=True)
    coordinates = ''.join(f'{int.from_bytes(point[axis:axis + 32], "big")}\n'
                          for axis in (0, 32))
    command = [str(MP_SPDZ / 'mascot-party.x'), '-N', '2', '-I', '-P',
               str(P256_PRIME), '-S', '128', '-pn', str(port), '-h',
               os.getenv('HANDOFF_SPONSOR_HOST', '127.0.0.1'), '-p', str(party),
               'concurro_ectf_field']
    if my_port is not None:
        command[1:1] = ['-mp', str(my_port)]
    environment = dict(os.environ, DYLD_LIBRARY_PATH=str(MP_SPDZ))
    process = subprocess.Popen(command, cwd=runtime, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
    output, errors = process.communicate(coordinates.encode(), timeout=max(120, BENCHMARK_TIMEOUT))
    (directory / f'{role}-arithmetic-metrics.log').write_bytes(errors)
    if process.returncode != 0 or not re.search(rb'^valid 1$', output, re.M):
        raise RuntimeError(f'checked arithmetic conversion failed for {role}: exit {process.returncode}')
    match = re.search(rb'^share (-?\d+)$', output, re.M)
    if not match:
        raise RuntimeError('checked arithmetic private output missing')
    share_value = int(match[1]) % P256_PRIME
    if role == 'concurro' and os.getenv('HANDOFF_TEST_TAMPER_ECTF_SHARE'):
        share_value = (share_value + 1) % P256_PRIME
    share = share_value.to_bytes(32, 'big')
    binding = hashlib.sha256(b'Concurro/Handoff/v1/checked-ectf' + session_id + h2).digest()
    send(control, 'arithmetic_complete', binding)
    if receive(control, 'arithmetic_complete')['data'] != binding:
        raise ValueError('arithmetic session binding differs')
    return share


def circuit_workspace(directory):
    """Give native circuits public relative inputs and isolated private data."""
    source = directory / 'src'
    work = source / 'build'
    (work / 'data').mkdir(parents=True, mode=0o700, exist_ok=True)
    for name in ('emp-tool', '2pc'):
        link = source / name
        if not link.exists():
            try:
                link.symlink_to(CHECKOUT / 'src' / name, target_is_directory=True)
            except FileExistsError:
                pass
    return work


def circuit_pair(control, role, circuit, private_input, directory, phase, session_id):
    """Run one fresh two-process circuit using each party's own private stdin."""
    party = 1 if role == 'sponsor' else 2
    work = circuit_workspace(directory / f'{role}-circuit-work')
    log = directory / f'{role}-{phase}-mpc.log'
    with circuit.open('rb') as source:
        circuit_digest = hashlib.file_digest(source, 'sha256').digest()
    binding = hashlib.sha256(b'Concurro/Handoff/MPC/v1' + session_id +
                             phase.encode() + circuit_digest).hexdigest()
    environment = os.environ.copy()
    environment['HANDOFF_MPC_SESSION_BINDING'] = binding
    with log.open('wb') as errors:
        command = [str(HANDOFF_PARTY), str(party), str(circuit)]
        if party == 1:
            process = subprocess.Popen(command, cwd=work,
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors,
                                       env=environment)
            process.stdin.write(private_input); process.stdin.flush()
            deadline = time.monotonic() + 90
            port = None
            while time.monotonic() < deadline and process.poll() is None:
                match = re.search(r'HANDOFF_READY (\d+)', log.read_text())
                if match:
                    port = match[1]
                    break
                time.sleep(.05)
            if port is None:
                status = process.poll()
                if status is None:
                    process.kill(); process.wait()
                raise RuntimeError(f'MPC sponsor did not bind: exit {status}')
            send(control, 'mpc_port', port=str(link_register(port)), phase=phase)
            output, _ = process.communicate(timeout=max(180, BENCHMARK_TIMEOUT))
        else:
            port = receive(control, 'mpc_port')
            if port['phase'] != phase:
                raise ValueError('MPC phase mismatch')
            command.append(port['port'])
            process = subprocess.Popen(command, cwd=work,
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors,
                                       env=environment)
            output, _ = process.communicate(private_input, timeout=max(120, BENCHMARK_TIMEOUT))
    if process.returncode != 0 or not output or output[0] != 1:
        raise RuntimeError(f'{phase} MPC failed: party {party}, exit {process.returncode}, bytes {len(output)}')
    send(control, 'mpc_hash', hashlib.sha256(output).digest(), phase=phase)
    other = receive(control, 'mpc_hash')
    if other['phase'] != phase or other['data'] != hashlib.sha256(output).digest():
        raise ValueError(f'{phase} MPC public outputs differ')
    return output


def meter_proof(listener, destination, counters, role, failures=None):
    """Forward one proof stream over a certificate-authenticated peer hop."""
    with listener, listener.accept()[0] as local:
        if os.getenv('HANDOFF_REQUIRE_AUTH') == '1':
            ca = os.environ['HANDOFF_PEER_CA']
            cert = os.environ['HANDOFF_PEER_CERT']
            key = os.environ['HANDOFF_PEER_KEY']
            if role == 'sponsor':
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(cert, key)
                context.load_verify_locations(ca)
                context.verify_mode = ssl.CERT_REQUIRED
                remote = context.wrap_socket(local, server_side=True)
                peer = x509.load_der_x509_certificate(remote.getpeercert(binary_form=True))
                names = peer.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                if 'concurro.local' not in names.get_values_for_type(x509.DNSName):
                    raise ssl.SSLCertVerificationError('unexpected proof peer identity')
                local = socket.create_connection(('127.0.0.1', destination))
            else:
                context = ssl.create_default_context(cafile=ca)
                context.load_cert_chain(cert, key)
                remote = context.wrap_socket(socket.create_connection((os.getenv('HANDOFF_SPONSOR_HOST', '127.0.0.1'), destination)),
                                             server_hostname='sponsor.local')
        else:
            remote = socket.create_connection((os.getenv('HANDOFF_SPONSOR_HOST', '127.0.0.1')
                                               if role == 'concurro' else '127.0.0.1', destination))
        with remote:
            local.settimeout(max(90, BENCHMARK_TIMEOUT)); remote.setblocking(True)
            errors = []

            def pump(source, target, direction):
                """Drain one proof direction without blocking the opposite direction."""
                try:
                    if isinstance(source, ssl.SSLSocket):
                        while True:
                            size = int.from_bytes(exact(source, 4), 'big')
                            if size == 0:
                                break
                            if size > 65536:
                                raise ValueError('oversize proof relay frame')
                            data = exact(source, size)
                            target.sendall(data)
                            counters[direction] += len(data)
                        target.shutdown(socket.SHUT_WR)
                    elif isinstance(target, ssl.SSLSocket):
                        while data := source.recv(65536):
                            target.sendall(len(data).to_bytes(4, 'big') + data)
                            counters[direction] += len(data)
                        target.sendall(bytes(4))
                    else:
                        while data := source.recv(65536):
                            target.sendall(data)
                            counters[direction] += len(data)
                        target.shutdown(socket.SHUT_WR)
                except (OSError, ValueError, EOFError) as error:
                    errors.append(error)
                    source.close(); target.close()

            toward_remote = 'sponsor_to_concurro' if role == 'sponsor' else 'concurro_to_sponsor'
            toward_local = 'concurro_to_sponsor' if role == 'sponsor' else 'sponsor_to_concurro'
            forward = threading.Thread(target=pump, args=(local, remote, toward_remote), daemon=True)
            forward.start()
            pump(remote, local, toward_local)
            forward.join(timeout=5)
            if forward.is_alive() or errors:
                failure = RuntimeError(f'proof relay failed: {errors}')
                if failures is None:
                    raise failure
                failures.append(failure)


def request_proof(control, role, claim, directory, turn):
    """Prove one exact TLS application record with fresh QuickSilver OT state."""
    phase = f'request-{turn}'
    log = directory / f'{role}-{phase}-proof.log'
    command = [str(PROOF), 'verifier' if role == 'sponsor' else 'prover']
    with log.open('wb') as errors:
        if role == 'sponsor':
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stderr=errors)
            process.stdin.write(json.dumps(claim).encode()); process.stdin.close()
            deadline = time.monotonic() + 30
            port = None
            while time.monotonic() < deadline and process.poll() is None:
                match = re.search(r'REQUEST_READY (\d+)', log.read_text())
                if match:
                    port = match[1]
                    break
                time.sleep(.05)
            if port is None:
                raise RuntimeError('request verifier did not bind')
            listener = socket.socket()
            listener.bind((os.getenv('HANDOFF_MPC_BIND_HOST', '127.0.0.1'), 0)); listener.listen(1)
            counters = dict(concurro_to_sponsor=0, sponsor_to_concurro=0)
            relay_failures = []
            relay = threading.Thread(target=meter_proof,
                                     args=(listener, int(port), counters, role, relay_failures), daemon=True)
            relay.start()
            send(control, 'proof_port', port=str(link_register(listener.getsockname()[1])), turn=turn)
            process.wait(timeout=max(90, BENCHMARK_TIMEOUT))
            relay.join(timeout=5)
            if relay_failures:
                raise relay_failures[0]
            if relay.is_alive():
                raise RuntimeError('request proof proxy did not close')
            errors.write(('REQUEST_TRAFFIC ' + json.dumps(counters) + '\n').encode())
        else:
            port = receive(control, 'proof_port')
            if port['turn'] != turn:
                raise ValueError('request proof turn mismatch')
            listener = socket.socket()
            listener.bind(('127.0.0.1', 0)); listener.listen(1)
            counters = dict(concurro_to_sponsor=0, sponsor_to_concurro=0)
            relay_failures = []
            relay = threading.Thread(target=meter_proof,
                                     args=(listener, int(port['port']), counters, role, relay_failures), daemon=True)
            relay.start()
            process = subprocess.Popen(command + [str(listener.getsockname()[1])],
                                       stdin=subprocess.PIPE, stderr=errors)
            process.communicate(json.dumps(claim).encode(), timeout=max(90, BENCHMARK_TIMEOUT))
            relay.join(timeout=5)
            if relay_failures:
                raise relay_failures[0]
            if relay.is_alive():
                raise RuntimeError('request proof client proxy did not close')
    if process.returncode != 0 or 'REQUEST_OK' not in log.read_text():
        raise RuntimeError(f'{phase} proof failed for {role}: exit {process.returncode}')
    return counters if role == 'sponsor' else None


def request_claim(h2, h3, key_commitment, key, iv, sequence, plaintext, wire):
    """Name the public record and the private handoff-derived request key."""
    return dict(h2=h2.hex(), h3=h3.hex(), key_commitment=key_commitment.hex(),
                key=key.hex(), iv=iv.hex(), sequence=sequence,
                plaintext=plaintext.hex(), record=wire.hex())


def audited_payload(route, plaintext, turn, tail):
    """Extract a proved prompt after checking the public header continuation."""
    if turn == 0:
        if not plaintext.startswith(tail):
            raise ValueError('request header continuation differs')
        if route == 'codex':
            if plaintext != tail:
                raise ValueError('WebSocket upgrade continuation has extra data')
            return None
        plaintext = plaintext[len(tail):]
    if route == 'claude':
        body = plaintext.rstrip(b' ')
        json.loads(body)
        return body
    if len(plaintext) < 6 or plaintext[0] not in (0x81, 0x88, 0x89, 0x8a) or not plaintext[1] & 0x80:
        raise ValueError('invalid client WebSocket frame')
    size = plaintext[1] & 0x7f
    offset = 2
    if size == 126:
        size = int.from_bytes(plaintext[2:4], 'big')
        offset = 4
    elif size == 127:
        size = int.from_bytes(plaintext[2:10], 'big')
        offset = 10
    if len(plaintext) != offset + 4 + size:
        raise ValueError('WebSocket frame length mismatch')
    if plaintext[0] != 0x81 and size > 125:
        raise ValueError('oversized WebSocket control frame')
    mask = plaintext[offset:offset + 4]
    prompt = bytes(byte ^ mask[index % 4] for index, byte in enumerate(plaintext[offset + 4:]))
    if plaintext[0] != 0x81:
        return None
    json.loads(prompt)
    return prompt


def request_head(route, credential, websocket_key=b'dGhlIHNhbXBsZSBub25jZQ=='):
    """Use public request headers and a private bearer credential of known length."""
    if not credential:
        raise ValueError('empty provider credential')
    if route == 'claude':
        return (b'POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer ' + credential
                + b'\r\nContent-Type: application/json\r\nContent-Length: 2048\r\n\r\n')
    if route == 'codex':
        return (b'GET /backend-api/codex/responses HTTP/1.1\r\nHost: chatgpt.com\r\nAuthorization: Bearer ' + credential
                + b'\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n'
                + b'Sec-WebSocket-Key: ' + websocket_key + b'\r\n\r\n')
    if route == 'codex_http':
        return (b'POST /backend-api/codex/responses HTTP/1.1\r\nHost: chatgpt.com\r\nAuthorization: Bearer '
                + credential + b'\r\n')
    raise ValueError('unknown provider route')


def prefix_circuit(route, credential_bytes, partial_head, token_offset):
    """Generate and cache the circuit for the public credential-prefix shape."""
    cache = Path(os.getenv('HANDOFF_CIRCUIT_CACHE', ROOT / 'prefix-circuits'))
    cache.mkdir(parents=True, exist_ok=True)
    path = cache / f'{route}-{len(partial_head)}-{token_offset}-{credential_bytes}.txt'
    with (cache / (path.name + '.lock')).open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not path.exists():
            temporary = path.with_suffix('.tmp')
            subprocess.run([str(CHECKOUT / 'build/HandoffPrefix'), 'generate', str(len(partial_head)),
                            str(token_offset), str(credential_bytes), str(temporary)],
                           cwd=circuit_workspace(cache / 'workspace'),
                           check=True, timeout=max(240, BENCHMARK_TIMEOUT))
            temporary.replace(path)
    return path


class ForwardedConnection(Connection):
    """Reuse native TLS continuation over the sponsor's record-forwarding channel."""

    def __init__(self, control, client_secret, server_secret, h2, h3, key_commitment, directory):
        """Start at c1 sequence zero and s0 sequence zero after the protected prefix."""
        self.control = control
        self.write = Epoch(client_secret)
        self.read = Epoch(server_secret)
        self.buffer = bytearray()
        self.handshake_buffer = bytearray()
        self.sent = self.received = self.tickets = self.server_updates = 0
        self.h2, self.h3, self.key_commitment = h2, h3, key_commitment
        self.directory = directory
        self.turn = 0

    def send_raw(self, data):
        """Require request proof for application records before sponsor forwarding."""
        raise RuntimeError('unproved client record')

    def send(self, data, fragment=16384):
        """Prove each encrypted request record before the sponsor forwards it."""
        for start in range(0, len(data), fragment):
            plaintext = data[start:start + fragment]
            sequence = self.write.sequence
            wire = self.write.encrypt(plaintext)
            if os.getenv('HANDOFF_TEST_ALTER_REQUEST') and self.turn == 0:
                wire = wire[:6] + bytes([wire[6] ^ 1]) + wire[7:]
            announced = 0 if os.getenv('HANDOFF_TEST_REPLAY_REQUEST') and self.turn == 1 else self.turn
            send(self.control, 'request_offer', wire, plaintext=base64.b64encode(plaintext).decode(),
                 sequence=announced, turn=announced)
            claim = request_claim(self.h2, self.h3, self.key_commitment,
                                  expand(self.write.secret, b'key', 16),
                                  expand(self.write.secret, b'iv', 12), sequence, plaintext, wire)
            request_proof(self.control, 'concurro', claim, self.directory, self.turn)
            receipt = receive(self.control, 'request_accepted')
            if receipt['turn'] != self.turn or receipt['data'] != hashlib.sha256(wire).digest():
                raise ValueError('sponsor forwarded record differs from proved bytes')
            self.sent += len(wire)
            self.turn += 1

    def read_record(self):
        """Request one original provider record from the sponsor."""
        send(self.control, 'need_server_record')
        wire = receive(self.control, 'server_record')['data']
        self.received += len(wire)
        return wire

    def close(self):
        """End the synthetic continuation without owning the provider socket."""


def claude_body(parent):
    """Build one provider-fixture Claude create or continue request of exactly 2048 bytes."""
    value = dict(model='test-model', stream=True, max_tokens=1024,
                 messages=[dict(role='user', content='synthetic prompt')])
    if parent is None:
        value.update(thread=dict(type='create'), system="Answer the user's request.", tools=[])
    else:
        value['thread'] = dict(type='continue', previous_message_id=parent)
    body = json.dumps(value, separators=(',', ':'), sort_keys=True).encode()
    if len(body) > 2048:
        raise ValueError('Claude body exceeds fixed request length')
    return body + b' ' * (2048 - len(body))


def sponsor_claude_login():
    """Read the existing Claude Code OAuth token inside the Sponsor process only."""
    credential = subprocess.run(['security', 'find-generic-password',
                                 '-s', 'Claude Code-credentials', '-w'],
                                capture_output=True, check=True)
    record = json.loads(credential.stdout)
    token = record['claudeAiOauth']['accessToken']
    if not isinstance(token, str):
        raise ValueError('Claude Code login lacks an OAuth access token')
    return token.encode()


def consume_claude(link, body):
    """Send one Claude body and parse the provider's completed SSE event."""
    link.send(body)
    headers, response = link.http(200)
    complete = [json.loads(line[6:]) for line in response.splitlines()
                if line.startswith(b'data: ') and b'"message"' in line]
    if len(complete) != 1 or 'usage' not in complete[0]:
        raise ValueError('missing Claude response completion or usage')
    return dict(message_id=complete[0]['message']['id'], usage=complete[0]['usage'],
                status=200, content_type=headers.get('content-type'))


def consume_codex(link):
    """Complete two WebSocket turns and verify the second names the first response."""
    headers, body = link.http(101)
    if body or headers.get('upgrade', '').lower() != 'websocket':
        raise ValueError('provider did not accept WebSocket upgrade')
    completed = []
    parent = None
    for turn in range(2):
        prompt = json.dumps(dict(type='response.create', store=True,
                                 previous_response_id=parent,
                                 input=f'synthetic Codex turn {turn}'),
                            separators=(',', ':')).encode()
        link.frame(prompt)
        while True:
            event = link.event()
            if event.get('type') == 'response.completed':
                response = event['response']
                if response.get('previous_response_id') != parent:
                    raise ValueError('Codex response parent mismatch')
                parent = response['id']
                completed.append(dict(id=parent, input_bytes=response.get('input_bytes')))
                break
    return dict(status=101, responses=completed)


def sponsor(control, route, provider_port, ca_path, directory, token_file=None, provider_host='127.0.0.1',
            token_bytes=None, account=None):
    """Own provider bytes and credential while gating every release on validation."""
    protocol = tls13_joint_h2 if route == 'claude_h2' else tls13_joint
    ServerFlight = protocol.ServerFlight
    client_hello = protocol.client_hello
    server_hello = protocol.server_hello
    validate_client_hello = protocol.validate_client_hello
    started = time.perf_counter()
    control_start = dict(CONTROL_TRAFFIC)
    tls_sent = tls_received = 0
    handshake_only = os.getenv('HANDOFF_HANDSHAKE_ONLY') == '1'
    token = (b'?' if handshake_only else token_bytes if token_bytes is not None else
             sponsor_claude_login() if os.getenv('HANDOFF_SPONSOR_CLAUDE_KEYCHAIN') == '1' else
             Path(token_file or os.environ['HANDOFF_SPONSOR_TOKEN_FILE']).read_bytes().strip())
    if not token or any(char in token for char in (b'\r', b'\n')):
        raise ValueError('invalid sponsor credential')
    send(control, 'credential_shape', length=len(token), account=account)
    host = 'api.anthropic.com' if route in ('claude', 'claude_h2') else 'chatgpt.com'
    if handshake_only:
        provider_host = os.getenv('HANDOFF_PROVIDER_HOST', provider_host)
    provider = socket.create_connection((provider_host, provider_port), timeout=max(90, BENCHMARK_TIMEOUT))
    provider.settimeout(max(90, BENCHMARK_TIMEOUT))
    helper, joint, session_id = native_share(control, 'sponsor')
    ch = client_hello(host, joint)
    validate_client_hello(ch, host, joint)
    hello_wire = record(22, ch)
    provider.sendall(hello_wire)
    tls_sent += len(hello_wire)
    send(control, 'client_hello', ch)
    sh_wire = read_record(provider)
    tls_received += len(sh_wire)
    if sh_wire[0] != 22:
        raise ValueError('provider did not send ServerHello')
    sh = sh_wire[5:]
    point = server_hello(sh, validate_client_hello(ch, host, joint))
    send(control, 'server_hello', sh)
    h2 = hashlib.sha256(ch + sh).digest()
    private_point = contribution(helper, point)
    handshake_secret = (arithmetic_share(control, 'sponsor', private_point, session_id, h2, directory)
                        if os.getenv('HANDOFF_ARITHMETIC_ECTF') == '1' else private_point)
    master_mask = os.urandom(32)
    handshake_input = handshake_secret + h2 + master_mask + os.urandom(64)
    public = circuit_pair(control, 'sponsor', CHECKOUT / os.getenv('HANDOFF_HANDSHAKE_CIRCUIT', 'handoff-handshake-v3.txt'),
                          handshake_input, directory, 'handshake', session_id)
    if len(public) != 193:
        raise ValueError('handshake output shape mismatch')
    records = []
    while True:
        wire = read_record(provider)
        tls_received += len(wire)
        records.append(wire)
        disclosed = wire
        if os.getenv('HANDOFF_TEST_CORRUPT_FLIGHT') and wire[0] == 23:
            disclosed = wire[:-1] + bytes([wire[-1] ^ 1])
        send(control, 'server_flight_record', disclosed)
        answer = receive(control)
        if answer['kind'] == 'flight_more':
            continue
        if answer['kind'] != 'flight_keys' or len(answer['data']) != 64:
            raise ValueError('Concurro did not validate provider flight')
        chts, shts = answer['data'][:32], answer['data'][32:]
        binding = hashlib.sha256(b'Concurro/Handoff/v2/handshake-keys' + h2 + chts + shts).digest()
        if not hmac.compare_digest(public[161:193], binding):
            raise ValueError('released handshake keys differ from MPC commitment')
        flight = ServerFlight(ch, sh, shts, ca_path, host)
        for observed in records:
            flight.feed(observed)
        if not flight.finished:
            raise ValueError('retained provider flight is incomplete')
        own_finished, h3 = flight.client_finished(chts)
        if answer['h3'] != h3.hex():
            raise ValueError('parties computed different server Finished transcript')
        send(control, 'flight_approved', h3)
        peer_finished = receive(control, 'client_finished')['data']
        if peer_finished != own_finished:
            raise ValueError('client Finished differs')
        provider.sendall(own_finished)
        tls_sent += len(own_finished)
        if handshake_only:
            (directory / 'sponsor-result.json').write_text(json.dumps({
                'route': route, 'h2': h2.hex(), 'h3': h3.hex(),
                'session_id': session_id.hex(), 'server_finished_verified': True,
                'client_finished_sent': True, 'provider_flight_records': len(records),
                'provider_tls_bytes': {'sent': tls_sent, 'received': tls_received},
            }, indent=2) + '\n')
            provider.close()
            return
        break
    websocket_key = b'dGhlIHNhbXBsZSBub25jZQ=='
    if route == 'codex':
        websocket_key = receive(control, 'websocket_key')['data']
    if route == 'claude_h2':
        template = receive(control, 'h2_template')
        templates = [(template['path'].encode(),
                      tuple((name.encode(), value.encode()) for name, value in template['headers']))]
        head, slot = bootstrap(token, *templates[0])
    else:
        head = request_head(route, token, websocket_key)
        slot = head.index(token)
    partial_head = head if route == 'claude_h2' else head[:slot + len(token) + 2]
    dynamic = os.getenv('HANDOFF_DYNAMIC_REQUEST') == '1' and route != 'claude_h2'
    tail = (receive(control, 'request_tail')['data'] if dynamic else head[len(partial_head):])
    expected_body = None
    if dynamic:
        if not tail.endswith(b'\r\n\r\n'):
            raise ValueError('incomplete admitted request headers')
        fields = {}
        for line in tail[:-4].split(b'\r\n'):
            name, separator, value = line.partition(b':')
            if not separator or not re.fullmatch(rb'[!#$%&\x27*+.^_`|~0-9A-Za-z-]+', name):
                raise ValueError('invalid admitted HTTP header')
            fields.setdefault(name.lower(), []).append(value.strip())
        forbidden = (b'authorization', b'host', b'proxy-authorization', b'transfer-encoding')
        if any(name in fields for name in forbidden):
            raise ValueError('conflicting admitted HTTP header')
        if route == 'codex':
            if (fields.get(b'connection') != [b'Upgrade'] or fields.get(b'upgrade') != [b'websocket']
                    or fields.get(b'sec-websocket-version') != [b'13']
                    or fields.get(b'sec-websocket-key') != [websocket_key]
                    or b'content-length' in fields):
                raise ValueError('invalid admitted WebSocket upgrade')
            expected_body = 0
        else:
            if b'connection' in fields or b'upgrade' in fields:
                raise ValueError('conflicting admitted HTTP header')
            lengths = fields.get(b'content-length', [])
            if len(lengths) != 1 or not lengths[0].isdigit():
                raise ValueError('ambiguous admitted Content-Length')
            expected_body = int(lengths[0])
    request_bytes = bytearray()
    request_complete = False
    pending_wires = []
    binding = h2 + h3 + public[97:161]
    prefix_input = master_mask + bytes(64) + binding + partial_head
    prefix = circuit_pair(control, 'sponsor', prefix_circuit(route, len(token), partial_head, slot),
                          prefix_input, directory, 'prefix', session_id)
    if len(prefix) <= 97 or (slot not in (75, 84, 85) and route != 'claude_h2'):
        raise ValueError('protected prefix shape mismatch')
    provider.sendall(prefix[97:])
    tls_sent += len(prefix[97:])
    send(control, 'prefix_forwarded')
    audit = dict(route=route, prompts=[], usage=[])
    pending_prompts = deque()
    h2_audit = SponsorAudit(token, templates=templates) if route == 'claude_h2' else None
    indexed_headers_accepted = 0
    next_sequence = 0
    response_mutated = False
    while True:
        message = receive(control)
        kind = message['kind']
        if kind == 'h2_template' and h2_audit is not None:
            h2_audit.templates.append((message['path'].encode(),
                                       tuple((name.encode(), value.encode())
                                             for name, value in message['headers'])))
        elif kind == 'request_offer':
            wire = message['data']
            plaintext = base64.b64decode(message['plaintext'], validate=True)
            if message['sequence'] != next_sequence or message['turn'] != next_sequence:
                raise ValueError('unproved or repeated client record sequence')
            if h2_audit is not None:
                prompt = None
            elif dynamic:
                request_bytes.extend(plaintext)
                if route != 'codex' and len(request_bytes) > len(tail) + expected_body:
                    raise ValueError('request exceeds admitted Content-Length')
                prompt = None
                if not request_complete and len(request_bytes) == len(tail) + expected_body:
                    if not request_bytes.startswith(tail):
                        raise ValueError('proved request differs from admitted headers')
                    if route != 'codex':
                        prompt = bytes(request_bytes[len(tail):])
                        json.loads(prompt)
                    request_complete = True
                    request_bytes.clear()
                elif route == 'codex' and request_complete:
                    if len(request_bytes) >= 2:
                        size = request_bytes[1] & 0x7f
                        offset = 2 if size < 126 else 4 if size == 126 else 10
                        if len(request_bytes) >= offset:
                            if size == 126:
                                size = int.from_bytes(request_bytes[2:4], 'big')
                            elif size == 127:
                                size = int.from_bytes(request_bytes[2:10], 'big')
                            if len(request_bytes) > offset + 4 + size:
                                raise ValueError('WebSocket request exceeds declared frame')
                            if len(request_bytes) == offset + 4 + size:
                                prompt = audited_payload(route, bytes(request_bytes), next_sequence, tail)
                                request_bytes.clear()
            else:
                prompt = audited_payload(route, plaintext, next_sequence, tail)
            claim = request_claim(h2, h3, prefix[1:33], bytes(16), bytes(12),
                                  next_sequence, plaintext, wire)
            traffic = request_proof(control, 'sponsor', claim, directory, next_sequence)
            pending_wires.append(wire)
            if h2_audit is not None:
                event = h2_audit.accept(plaintext, 0)
                if event is None:
                    indexed_headers_accepted += 1
                release = event is not None
                if event is not None and isinstance(event[0], int):
                    prompt = event[1]
            else:
                release = request_complete and not request_bytes
            if prompt is not None:
                entry = dict(turn=next_sequence, sha256=hashlib.sha256(prompt).hexdigest(),
                             wire_sha256=hashlib.sha256(wire).hexdigest(),
                             proof='QuickSilver/real-OT', proof_traffic=traffic)
                if os.getenv('HANDOFF_REDACT_PROMPTS') != '1':
                    entry['text'] = prompt.decode('utf8')
                audit['prompts'].append(entry)
                pending_prompts.append((entry, prompt.decode('utf8')))
            if release:
                for proved_wire in pending_wires:
                    provider.sendall(proved_wire)
                    tls_sent += len(proved_wire)
                pending_wires.clear()
            send(control, 'request_accepted', hashlib.sha256(wire).digest(), turn=next_sequence)
            next_sequence += 1
        elif kind == 'need_server_record':
            if dynamic and (not request_complete or pending_wires):
                raise ValueError('provider response requested before complete admitted request')
            wire = read_record(provider)
            tls_received += len(wire)
            fault = os.getenv('HANDOFF_TEST_RESPONSE_FAULT')
            if fault and not response_mutated and wire[0] == 23 and (
                    not fault.endswith('_inference') or next_sequence > 1):
                original = wire
                wire = (wire[:-1] + bytes([wire[-1] ^ 1])
                        if fault.startswith('corrupt') else wire[:-1])
                print('HANDOFF_RESPONSE_FAULT ' + json.dumps({
                    'fault': fault, 'original_bytes': len(original), 'mutated_bytes': len(wire),
                    'original_sha256': hashlib.sha256(original).hexdigest(),
                    'mutated_sha256': hashlib.sha256(wire).hexdigest()}), file=sys.stderr, flush=True)
                response_mutated = True
            send(control, 'server_record', wire)
        elif kind == 'audit_usage':
            usage = dict(source='Concurro-reported provider field', value=message['usage'])
            audit['usage'].append(usage)
            if not pending_prompts:
                raise ValueError('provider usage arrived without a proved request')
            prompt, text = pending_prompts.popleft()
            print('NATIVE_AUDIT ' + json.dumps({
                'turn': prompt['turn'], 'prompt': text, 'sha256': prompt['sha256'],
                'proof': prompt['proof'], 'usage': message['usage'],
                'session_id': session_id.hex(),
            }, separators=(',', ':')), flush=True)
        elif kind == 'complete':
            if pending_wires or pending_prompts or (h2_audit is not None and
                    len(h2_audit.prompts) != len(audit['usage'])):
                raise ValueError('incomplete audited continuation')
            break
        else:
            raise ValueError(f'unexpected sponsor control message {kind}')
    audit.update(h2=h2.hex(), h3=h3.hex(), server_flight_sha256=hashlib.sha256(b''.join(records)).hexdigest(),
                 indexed_headers_accepted=indexed_headers_accepted,
                 protected_bootstrap_count=1, provider_connection_count=1,
                 request_proof_records=next_sequence,
                 handshake_commitment=public[161:193].hex(), prefix_key_commitment=prefix[1:33].hex(),
                 session_id=session_id.hex(), provider_flight_records=len(records),
                 mascot_proxy_enabled='HANDOFF_MASCOT_PROXY_PORT' in os.environ,
                 elapsed_ms=round((time.perf_counter() - started) * 1000, 1),
                 provider_tls_bytes=dict(sent=tls_sent, received=tls_received),
                 control_payload_bytes={key: CONTROL_TRAFFIC[key] - control_start[key]
                                        for key in control_start})
    (directory / 'sponsor-result.json').write_text(json.dumps(audit, indent=2) + '\n')
    provider.close()


def concurro(control, route, parent, ca_path, directory, request_file=None, client_socket=None, account=None,
             ingress_socket=None):
    """Validate provider bytes, run the private circuits and continue native TLS."""
    protocol = tls13_joint_h2 if route == 'claude_h2' else tls13_joint
    ServerFlight = protocol.ServerFlight
    server_hello = protocol.server_hello
    validate_client_hello = protocol.validate_client_hello
    if route == 'claude_h2' and client_socket is not None:
        raise ValueError('Claude HTTP/2 does not use the WebSocket client channel')
    started = time.perf_counter()
    control_start = dict(CONTROL_TRAFFIC)
    shape = receive(control, 'credential_shape')
    credential_bytes = shape['length']
    account = account or shape.get('account')
    if not isinstance(credential_bytes, int) or credential_bytes <= 0:
        raise ValueError('invalid public credential length')
    host = 'api.anthropic.com' if route in ('claude', 'claude_h2') else 'chatgpt.com'
    helper, joint, session_id = native_share(control, 'concurro')
    ch = receive(control, 'client_hello')['data']
    session = validate_client_hello(ch, host, joint)
    sh = receive(control, 'server_hello')['data']
    point = server_hello(sh, session)
    h2 = hashlib.sha256(ch + sh).digest()
    private_point = contribution(helper, point)
    handshake_secret = (arithmetic_share(control, 'concurro', private_point, session_id, h2, directory)
                        if os.getenv('HANDOFF_ARITHMETIC_ECTF') == '1' else private_point)
    master_mask = os.urandom(32)
    handshake_masks = os.urandom(64)
    handshake_input = handshake_secret + h2 + master_mask + handshake_masks
    public = circuit_pair(control, 'concurro', CHECKOUT / os.getenv('HANDOFF_HANDSHAKE_CIRCUIT', 'handoff-handshake-v3.txt'),
                          handshake_input, directory, 'handshake', session_id)
    if len(public) != 193:
        raise ValueError('handshake output shape mismatch')
    chts = bytes(a ^ b for a, b in zip(public[1:33], handshake_masks[:32]))
    shts = bytes(a ^ b for a, b in zip(public[33:65], handshake_masks[32:]))
    flight = ServerFlight(ch, sh, shts, ca_path, host)
    while not flight.finished:
        wire = receive(control, 'server_flight_record')['data']
        flight.feed(wire)
        if not flight.finished:
            send(control, 'flight_more')
    finished, h3 = flight.client_finished(chts)
    send(control, 'flight_keys', chts + shts, h3=h3.hex())
    approval = receive(control, 'flight_approved')['data']
    if approval != h3:
        raise ValueError('sponsor computed different server transcript')
    send(control, 'client_finished', finished)
    if os.getenv('HANDOFF_HANDSHAKE_ONLY') == '1':
        (directory / 'concurro-result.json').write_text(json.dumps({
            'route': route, 'h2': h2.hex(), 'h3': h3.hex(),
            'session_id': session_id.hex(), 'server_finished_verified': True,
            'client_finished_sent': True,
        }, indent=2) + '\n')
        return
    first_request = receive(ingress_socket, 'request') if ingress_socket is not None else None
    if route == 'claude_h2' and first_request is not None:
        send(control, 'h2_template', path=first_request['path'], headers=first_request['headers'])
    elif route == 'claude_h2':
        send(control, 'h2_template', path='/v1/messages',
             headers=[['content-type', 'application/json'], ['anthropic-version', '2023-06-01']])
    websocket_key = b'dGhlIHNhbXBsZSBub25jZQ=='
    if route == 'codex':
        websocket_key = base64.b64encode(os.urandom(16))
        send(control, 'websocket_key', websocket_key)
    if route == 'claude_h2':
        template = first_request or {'path': '/v1/messages', 'headers':
                                     [['content-type', 'application/json'],
                                      ['anthropic-version', '2023-06-01']]}
        head, slot = bootstrap(bytes(credential_bytes), template['path'].encode(),
                               tuple((name.encode(), value.encode())
                                     for name, value in template['headers']))
    else:
        head = request_head(route, bytes(credential_bytes), websocket_key)
        slot = head.index(bytes(credential_bytes))
    partial_head = head if route == 'claude_h2' else head[:slot + credential_bytes + 2]
    request = json.loads(request_file.read_text()) if request_file else None
    tail = base64.b64decode(request['tail']) if request else head[len(partial_head):]
    if client_socket is not None:
        if not account or any(char in account for char in '\r\n'):
            raise ValueError('missing provider account identity')
        if os.getenv('HANDOFF_LIVE_CLI_ADAPTER') == '1':
            ingress = receive(client_socket, 'ingress_upgrade')
            for name, value in ingress['headers']:
                if (not re.fullmatch(r'[!#$%&\x27*+.^_`|~0-9A-Za-z-]+', name)
                        or any(char in value for char in '\r\n')
                        or name.lower() in ('authorization', 'host', 'connection', 'upgrade',
                                            'sec-websocket-key', 'sec-websocket-version',
                                            'sec-websocket-extensions', 'proxy-authorization')):
                    raise ValueError('invalid public CLI upgrade header')
                tail = tail[:-2] + name.encode() + b': ' + value.encode() + b'\r\n\r\n'
        tail = tail[:-2] + b'ChatGPT-Account-Id: ' + account.encode() + b'\r\n\r\n'
    if request or os.getenv('HANDOFF_DYNAMIC_REQUEST') == '1':
        send(control, 'request_tail', tail)
    master_share = bytes(a ^ b for a, b in zip(public[65:97], master_mask))
    binding = h2 + h3 + public[97:161]
    prefix_masks = os.urandom(64)
    prefix_input = master_share + prefix_masks + binding + partial_head
    prefix = circuit_pair(control, 'concurro', prefix_circuit(route, credential_bytes, partial_head, slot),
                          prefix_input, directory, 'prefix', session_id)
    if len(prefix) <= 97:
        raise ValueError('protected prefix shape mismatch')
    private = bytes(a ^ b for a, b in zip(prefix[33:97], prefix_masks))
    receive(control, 'prefix_forwarded')
    link = ForwardedConnection(control, private[:32], private[32:], h2, h3, prefix[1:33], directory)
    if client_socket is not None:
        link.send(tail)
        headers, body = link.http()
        if link.http_status != 101:
            send(client_socket, 'upgrade_error', status=link.http_status)
            raise ValueError(f'provider rejected WebSocket upgrade: HTTP {link.http_status}')
        accept = base64.b64encode(hashlib.sha1(websocket_key +
                          b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest()).decode()
        if body or headers.get('sec-websocket-accept') != accept:
            raise ValueError('provider WebSocket upgrade is not bound to request key')
        send(client_socket, 'upgrade_ok')
        responses = []
        while True:
            try:
                message = receive(client_socket, 'request')
            except EOFError:
                break
            request_value = json.loads(message['data'])
            if request_value.get('type') != 'response.create':
                raise ValueError('unexpected client WebSocket request')
            parent_id = request_value.get('previous_response_id')
            link.frame(message['data'])
            created_id = None
            while True:
                event = link.event()
                kind = event.get('type')
                if kind == 'response.created':
                    created_id = event['response']['id']
                    if event['response'].get('previous_response_id') != parent_id:
                        raise ValueError('provider response parent differs from client request')
                if kind == 'response.completed':
                    response = event['response']
                    if response.get('id') != created_id or response.get('previous_response_id') != parent_id:
                        raise ValueError('provider response identity differs')
                    responses.append({'id': created_id, 'usage': response.get('usage')})
                send(client_socket, 'event', json.dumps(event, separators=(',', ':')).encode())
                if kind in ('response.completed', 'response.failed', 'response.incomplete', 'error'):
                    send(control, 'audit_usage', usage=responses[-1]['usage'] if kind == 'response.completed' else None)
                    send(client_socket, 'turn_done', response_id=created_id)
                    break
        outcome = dict(status=101, responses=responses)
    elif request:
        link.send(tail + base64.b64decode(request['body']))
        headers, response = link.http()
        (directory / 'provider-response.bin').write_bytes(response)
        protocol = runpy.run_path(os.environ['CONCURRO_PROVIDER_PROTOCOL'])
        binding_route = 'claude-subscription' if route == 'claude' else 'chatgpt-subscription'
        observation = protocol['Observation'](binding_route, link.http_status)
        if 'text/event-stream' in headers.get('content-type', ''):
            for event in response.split(b'\n\n'):
                if event.strip():
                    value, error = protocol['event_value'](event)
                    observation.accept(value)
                    if error:
                        observation.result['category'] = observation.result['category'] or 'unknown'
        else:
            observation.accept(json.loads(response))
        outcome = dict(status=link.http_status, content_type=headers.get('content-type'),
                       usage=observation.finish()['usage'])
        send(control, 'audit_usage', usage=outcome['usage'])
    elif route == 'claude_h2':
        state = IndexedConnection(credential_bytes)
        reader = ResponseReader(link, state)
        parent_id = None
        responses = []
        test_turns = int(os.getenv('CONCURRO_NATIVE_TEST_TURNS', '0')) if ingress_socket is not None else int(os.getenv('HANDOFF_H2_REQUESTS', '2'))
        turn = 0
        while not test_turns or turn < test_turns:
            request_started = time.perf_counter()
            sent_before, received_before, proofs_before = link.sent, link.received, link.turn
            try:
                current_request = (first_request if turn == 0 else receive(ingress_socket, 'request')
                                   if ingress_socket is not None else None)
            except EOFError:
                break
            if turn == 0:
                stream = 1
                head_bytes = len(partial_head)
            else:
                if current_request is not None:
                    send(control, 'h2_template', path=current_request['path'],
                         headers=current_request['headers'])
                template = current_request or {'path': '/v1/messages', 'headers':
                                               [['content-type', 'application/json'],
                                                ['anthropic-version', '2023-06-01']]}
                stream, headers = state.later_headers(0, template['path'].encode(),
                                                      tuple((name.encode(), value.encode())
                                                            for name, value in template['headers']))
                head_bytes = len(headers)
                link.send(headers)
            body = current_request['data'] if current_request is not None else claude_body(parent_id)
            json.loads(body)
            offset = 0
            while offset < len(body):
                reader.wait_window(stream)
                size = min(16375, len(body) - offset,
                           state.connection_window, state.stream_window)
                chunk = body[offset:offset + size]
                state.consume_window(size)
                offset += size
                link.send(state.data_chunk(stream, chunk, offset == len(body), 0))
            if ingress_socket is not None:
                def forward_headers(status, headers):
                    """Open the local response after authenticated H2 headers."""
                    send(ingress_socket, 'response_start', status=status,
                         content_type=headers.get(b'content-type', b'application/octet-stream').decode(
                             'ascii', errors='replace'))

                def forward_data(payload):
                    """Release each authenticated DATA fragment before window credit."""
                    send(ingress_socket, 'response_chunk', payload)
            else:
                forward_headers = forward_data = None
            status, headers, response = reader.read_stream(
                stream, on_headers=forward_headers, on_data=forward_data)
            if b'text/event-stream' not in headers.get(b'content-type', b''):
                content_type = headers.get(b'content-type', b'').decode('ascii', errors='replace')
                try:
                    error_type = json.loads(response).get('error', {}).get('type')
                except (ValueError, AttributeError):
                    error_type = None
                (directory / 'provider-error.json').write_text(json.dumps({
                    'status': status, 'content_type': content_type,
                    'error_type': error_type, 'response_sha256': hashlib.sha256(response).hexdigest(),
                }, indent=2) + '\n')
                if ingress_socket is not None:
                    send(ingress_socket, 'response_end')
                raise ValueError(f'provider returned HTTP {status} {content_type} '
                                 f'error_type={error_type}')
            events = [json.loads(line[6:]) for line in response.splitlines()
                      if line.startswith(b'data: ')]
            starts = [event for event in events if event.get('type') == 'message_start']
            deltas = [event for event in events if event.get('type') == 'message_delta']
            if status == 200 and (len(starts) != 1 or len(deltas) != 1):
                raise ValueError('missing Claude message_start or message_delta')
            parent_id = starts[0]['message']['id'] if starts else None
            usage = (dict(starts[0]['message'].get('usage', {}),
                          **deltas[0].get('usage', {})) if starts and deltas else None)
            responses.append(dict(stream=stream, message_id=parent_id, usage=usage, status=status,
                                  head_bytes=head_bytes, body_bytes=len(body),
                                  client_tls_bytes=link.sent - sent_before,
                                  server_tls_bytes=link.received - received_before,
                                  proof_records=link.turn - proofs_before,
                                  elapsed_ms=round((time.perf_counter() - request_started) * 1000, 1)))
            send(control, 'audit_usage', usage=usage)
            if ingress_socket is not None:
                send(ingress_socket, 'response_end')
            turn += 1
        outcome = dict(status=200, responses=responses)
    elif route == 'claude':
        body = claude_body(parent)
        outcome = consume_claude(link, tail + body)
        send(control, 'audit_usage', usage=outcome['usage'])
    else:
        link.send(tail)
        outcome = consume_codex(link)
        send(control, 'audit_usage', usage=[item['input_bytes'] for item in outcome['responses']])
    send(control, 'complete')
    outcome.update(route=route, h2=h2.hex(), h3=h3.hex(), session_id=session_id.hex(),
                   handshake_commitment=public[161:193].hex(), prefix_key_commitment=prefix[1:33].hex(),
                   mascot_proxy_enabled='HANDOFF_MASCOT_PROXY_PORT' in os.environ,
                   provider_records_received=link.received, client_records_sent=link.sent,
                   elapsed_ms=round((time.perf_counter() - started) * 1000, 1),
                   control_payload_bytes={key: CONTROL_TRAFFIC[key] - control_start[key]
                                          for key in control_start})
    (directory / 'concurro-result.json').write_text(json.dumps(outcome, indent=2) + '\n')


def run_peers(directory, route, port, ca, parent=None, request_file=None,
              provider_host='127.0.0.1', ingress_socket=None):
    """Execute peers with all control bytes on the shared interparty WAN link."""
    started = time.perf_counter()
    directory.mkdir()
    listener = socket.socket()
    listener.settimeout(30)
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    routed_port = link_register(listener.getsockname()[1])
    right = socket.create_connection(('127.0.0.1', routed_port), timeout=30)
    left, _ = listener.accept()
    listener.close()
    for channel in (left, right):
        channel.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    peers = []
    try:
        for role, channel in (('sponsor', left), ('concurro', right)):
            command = [sys.executable, str(Path(__file__).resolve()), '--role', role,
                       '--fd', str(channel.fileno()), '--route', route,
                       '--provider-port', str(port), '--provider-host', provider_host,
                       '--ca', str(ca),
                       '--output', str(directory)]
            if parent is not None and route == 'claude':
                command += ['--parent-id', parent]
            if request_file is not None and role == 'concurro':
                command += ['--request-file', str(request_file)]
            if ingress_socket is not None and role == 'concurro':
                command += ['--ingress-fd', str(ingress_socket.fileno())]
            environment = os.environ.copy()
            if request_file is not None:
                environment['HANDOFF_DYNAMIC_REQUEST'] = '1'
            peer_dir = environment.get('HANDOFF_PEER_DIR')
            if peer_dir:
                environment.update(HANDOFF_REQUIRE_AUTH='1',
                                   HANDOFF_PEER_CA=str(Path(peer_dir) / 'internal-ca.pem'),
                                   HANDOFF_PEER_CERT=str(Path(peer_dir) / f'internal-{role}.pem'),
                                   HANDOFF_PEER_KEY=str(Path(peer_dir) / f'internal-{role}.key'))
            if role == 'concurro':
                environment.pop('HANDOFF_SPONSOR_TOKEN_FILE', None)
                environment.pop('HANDOFF_SPONSOR_CLAUDE_KEYCHAIN', None)
            else:
                environment.pop('HANDOFF_MASCOT_PROXY_PORT', None)
            with (directory / f'{role}.log').open('wb') as log:
                passed = (channel.fileno(),) + ((ingress_socket.fileno(),)
                                                if ingress_socket is not None and role == 'concurro' else ())
                peers.append(subprocess.Popen(command, pass_fds=passed,
                                              stdout=log, stderr=log, env=environment))
        left.close(); right.close()
        for peer in peers:
            peer.wait(timeout=max(240, BENCHMARK_TIMEOUT))
        if any(peer.returncode for peer in peers):
            raise RuntimeError(f'{route} peer exits: {[peer.returncode for peer in peers]}')
        result = json.loads((directory / 'concurro-result.json').read_text())
        sponsor_result = json.loads((directory / 'sponsor-result.json').read_text())
        if result['h3'] != sponsor_result['h3']:
            raise ValueError('party transcript hashes differ')
        return dict(elapsed_ms=round((time.perf_counter() - started) * 1000, 1),
                    concurro=result, sponsor=sponsor_result)
    finally:
        for peer in peers:
            if peer.poll() is None:
                peer.kill(); peer.wait()
        left.close(); right.close()


def harness(output):
    """Run Claude create/continue and two Codex WebSocket turns with separate peers."""
    output.mkdir(exist_ok=False)
    ca = output / 'ca.pem'
    environment = dict(os.environ, CB_BENCH='1', TLS13_CA_PATH=str(ca))
    with (output / 'provider.log').open('wb') as provider_log:
        provider = subprocess.Popen([os.getenv('HANDOFF_SYNTHETIC_PROVIDER',
                                           '/private/tmp/concurro-tls13-component/tls13-fixture')],
                                    stdout=subprocess.PIPE, stderr=provider_log, env=environment)
        try:
            port = int(provider.stdout.readline())
            for _ in range(100):
                if ca.exists():
                    break
                time.sleep(.01)
            if not ca.exists():
                raise RuntimeError('fixture CA was not generated')
            parent = None
            results = []
            for name, route in (('claude-create', 'claude'), ('claude-continue', 'claude'), ('codex-websocket', 'codex')):
                row = run_peers(output / name, route, port, ca, parent)
                if route == 'claude':
                    parent = row['concurro']['message_id']
                results.append(dict(name=name, **row))
                (output / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
            print(json.dumps([row['name'] for row in results]))
        finally:
            provider.terminate(); provider.wait(timeout=5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', choices=['harness', 'external', 'sponsor', 'concurro', 'concurro-external'], default='harness')
    parser.add_argument('--fd', type=int)
    parser.add_argument('--route', choices=['claude', 'claude_h2', 'codex', 'codex_http'])
    parser.add_argument('--provider-port', type=int)
    parser.add_argument('--provider-host', default='127.0.0.1')
    parser.add_argument('--ca', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--parent-id')
    parser.add_argument('--request-file', type=Path)
    parser.add_argument('--client-fd', type=int)
    parser.add_argument('--ingress-fd', type=int)
    parser.add_argument('--account')
    parser.add_argument('--binding')
    parser.add_argument('--sponsor-port', type=int)
    parser.add_argument('--sponsor-host', default='127.0.0.1')
    parser.add_argument('--session-id')
    args = parser.parse_args()
    if args.role == 'harness':
        harness(args.output)
    elif args.role == 'external':
        args.output.mkdir(exist_ok=False)
        print(json.dumps(run_peers(args.output / 'session', args.route, args.provider_port,
                                   args.ca, request_file=args.request_file)))
    elif args.role == 'concurro-external':
        args.output.mkdir(exist_ok=False)
        raw = socket.create_connection((args.sponsor_host, args.sponsor_port), timeout=max(240, BENCHMARK_TIMEOUT))
        channel = authenticate(raw, 'concurro')
        send(channel, 'session_start', route=args.route, session_id=args.session_id,
             binding=json.loads(args.binding) if args.binding else None, account=args.account)
        client_socket = socket.socket(fileno=args.client_fd) if args.client_fd is not None else None
        concurro(channel, args.route, args.parent_id, args.ca, args.output, args.request_file,
                 client_socket, args.account)
        channel.close()
    else:
        channel = socket.socket(fileno=args.fd)
        channel.settimeout(max(240, BENCHMARK_TIMEOUT))
        channel = authenticate(channel, args.role)
        if args.role == 'sponsor':
            sponsor(channel, args.route, args.provider_port, args.ca, args.output,
                    provider_host=args.provider_host)
        else:
            ingress = socket.socket(fileno=args.ingress_fd) if args.ingress_fd is not None else None
            concurro(channel, args.route, args.parent_id, args.ca, args.output, args.request_file,
                     ingress_socket=ingress)
