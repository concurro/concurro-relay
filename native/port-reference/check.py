"""Compare credential-free port vectors with the accepted Python reference."""

import argparse
import hashlib
import json
import os
import socket
import sys
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
NATIVE = HERE.parent
sys.path[:0] = [str(NATIVE / 'worker'), str(NATIVE)]
os.environ.setdefault('HANDOFF_BUILD_ROOT', str(HERE))

import candidate_a
import ingress
import tls13_joint
import tls13_joint_h2
import tls13_product_http_h2 as worker
import tls13_product_native
import tunnel
from hpack import Decoder


def vectors():
    """Exercise production codecs with fixture-only data and return stable outputs."""
    result = {}
    left, right = socket.socketpair()
    with left, right:
        worker.send(left, 'fixture', b'\x00\xff', turn=2)
        wire = right.recv(4096)
        left.sendall(wire)
        decoded = worker.receive(right, 'fixture')
    result['control'] = {'wire': wire.hex(), 'kind': decoded['kind'],
                         'data': decoded['data'].hex(), 'turn': decoded['turn']}
    result['tunnel'] = (tunnel.HEADER.pack(b'D', 7, 3) + b'abc').hex()

    point = bytes.fromhex('04' + '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296' +
                          '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5')
    hellos = {}
    for name, module in [('codex', tls13_joint), ('claude_h2', tls13_joint_h2)]:
        hello = module.client_hello('fixture.example', point)
        session = module.validate_client_hello(hello, 'fixture.example', point)
        hellos[name] = {'session_length': len(session), 'message_type': hello[0],
                        'alpn': 'http/1.1' if name == 'codex' else 'h2'}
    result['handshake'] = hellos
    secret = bytes(range(32))
    epoch = tls13_product_native.Epoch(secret)
    encrypted = epoch.encrypt(b'fixture body')
    decrypted = tls13_product_native.Epoch(secret).decrypt(encrypted)
    result['record'] = {'wire': encrypted.hex(), 'kind': decrypted[0],
                        'content': decrypted[1].decode(), 'next_secret': epoch.updated().secret.hex()}

    claim = worker.request_claim(b'\x01' * 32, b'\x02' * 32, b'\x03' * 32,
                                 b'\x04' * 16, b'\x05' * 12, 3, b'fixture', encrypted)
    result['claim'] = claim
    token = b'fixture-only-token'
    prefix, slot = candidate_a.bootstrap(token)
    state = candidate_a.IndexedConnection(len(token))
    state.active_stream = None
    stream, indexed = state.later_headers(0)
    result['indexed_request'] = {'bootstrap_sha256': hashlib.sha256(prefix).hexdigest(),
                                 'credential_slot': slot, 'stream': stream,
                                 'indexed_headers': indexed.hex(), 'auth_index': candidate_a.AUTH_INDEX}
    decoder = Decoder()
    first = decoder.decode(b'\x40\x03foo\x03bar', raw=True)
    second = decoder.decode(b'\xbe', raw=True)
    huffman = Decoder().decode(bytes.fromhex('828684418cf1e3c2e5f23a6ba0ab90f4ff'), raw=True)
    result['hpack'] = {'first': [[a.decode(), b.decode()] for a, b in first],
                       'indexed': [[a.decode(), b.decode()] for a, b in second],
                       'huffman_authority': dict(huffman)[b':authority'].decode()}

    audit = candidate_a.SponsorAudit(token)
    body = b'{"messages":[{"content":"fixture prompt"}]}'
    accepted = audit.accept(candidate_a.frame(0, 1, 1, body), 0)
    result['audit'] = {'stream': accepted[0], 'body_sha256': hashlib.sha256(accepted[1]).hexdigest(),
                       'prompt_count': len(audit.prompts)}
    pending = ingress.PendingTurns()
    pending.enqueue({'turn': 1})
    pending.requests.get()
    pending.enqueue({'turn': 2})
    pending.finished()
    result['cancellation'] = {'next_queued_remains_cancelable': pending.cancel(),
                              'queued_turn': pending.requests.get()['turn']}
    return result


def main():
    """Freeze vectors once or compare current reference behavior with the frozen file."""
    parser = argparse.ArgumentParser()
    parser.add_argument('--freeze', action='store_true')
    args = parser.parse_args()
    path = HERE / 'vectors.json'
    actual = vectors()
    if args.freeze:
        path.write_text(json.dumps(actual, indent=2, sort_keys=True) + '\n')
        print(f'frozen {len(actual)} vector groups in {path}')
        return
    expected = json.loads(path.read_text())
    if actual != expected:
        raise AssertionError('reference vector drift; inspect vectors.json and production code')
    print(f'{len(actual)} reference vector groups match')


if __name__ == '__main__':
    main()
