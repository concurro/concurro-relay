"""Run one native TLS 1.3 role over authenticated relay link sockets."""

import argparse
import json
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tunnel import Tunnel


def exchange_mascot_identity(control, role, output):
    """Generate a fresh MASCOT transport key and bind public certs to this link."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from tls13_product_http_h2 import receive, send

    party = 0 if role == 'sponsor' else 1
    directory = output / 'mascot-certs'
    directory.mkdir(mode=0o700)
    key = directory / f'P{party}.key'
    cert = directory / f'P{party}.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', str(key), '-out', str(cert), '-days', '1',
                    '-subj', f'/CN=P{party}', '-addext', f'subjectAltName=DNS:P{party}'],
                   check=True, capture_output=True)
    key.chmod(0o600)
    send(control, 'mascot_certificate', cert.read_bytes(), party=party)
    other = receive(control, 'mascot_certificate')
    if other.get('party') != 1 - party:
        raise ValueError('MASCOT peer certificate party differs from authenticated role')
    peer_cert = x509.load_pem_x509_certificate(other['data'])
    names = peer_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(names) != 1 or names[0].value != f'P{1 - party}':
        raise ValueError('MASCOT peer certificate subject differs from authenticated role')
    (directory / f'P{1 - party}.pem').write_bytes(other['data'])


def main():
    """Connect one role to its Rust link bridge and run one provider session."""
    arguments = argparse.ArgumentParser()
    arguments.add_argument('--role', choices=('sponsor', 'concurro'), required=True)
    arguments.add_argument('--route', choices=('codex', 'claude_h2'), required=True)
    arguments.add_argument('--control', required=True)
    arguments.add_argument('--aux', required=True)
    arguments.add_argument('--runtime', type=Path, required=True)
    arguments.add_argument('--output', type=Path, required=True)
    arguments.add_argument('--provider-host', default='127.0.0.1')
    arguments.add_argument('--provider-port', type=int, default=443)
    arguments.add_argument('--provider-ca', type=Path, default=Path('/etc/ssl/cert.pem'))
    arguments.add_argument('--listen', default='127.0.0.1:7050')
    args = arguments.parse_args()

    runtime = args.runtime.resolve()
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    redact = '0' if os.getenv('CONCURRO_NATIVE_AUDIT_TEXT') == '1' else '1'
    os.environ.update(HANDOFF_BUILD_ROOT=str(runtime),
                      HANDOFF_PARTY_BINARY=str(runtime / 'DiStefano/build/HandoffPartyKrrw'),
                      HANDOFF_HANDSHAKE_CIRCUIT='handoff-handshake-shares-cached-hkdf.txt',
                      HANDOFF_CIRCUIT_CACHE=str(output.parent / 'public-circuits'),
                      HANDOFF_ARITHMETIC_ECTF='1',
                      HANDOFF_LIVE_CLI_ADAPTER='1', HANDOFF_REDACT_PROMPTS=redact,
                      HANDOFF_H2_REDACT_PROMPTS=redact, HANDOFF_BENCHMARK_TIMEOUT='900')
    if args.route == 'codex':
        os.environ['HANDOFF_DYNAMIC_REQUEST'] = '1'
    else:
        os.environ.pop('HANDOFF_DYNAMIC_REQUEST', None)
    test_turns = os.getenv('CONCURRO_NATIVE_TEST_TURNS_CODEX' if args.route == 'codex'
                           else 'CONCURRO_NATIVE_TEST_TURNS_CLAUDE')
    if test_turns is not None:
        os.environ['CONCURRO_NATIVE_TEST_TURNS'] = test_turns
    from ingress import Adapter
    from tls13_product_http_h2 import (concurro, prefix_circuit, receive, request_head,
                                       send, sponsor)
    from candidate_a import bootstrap

    with socket.socket(socket.AF_UNIX) as control, socket.socket(socket.AF_UNIX) as auxiliary:
        control.connect(args.control)
        auxiliary.connect(args.aux)
        tunnel = Tunnel(auxiliary, args.role).start()
        if args.role == 'sponsor':
            credential = json.load(sys.stdin)
            token = credential['token'].encode()
            account = credential.get('account')
            del credential
            os.environ['HANDOFF_LINK_ADMIN'] = str(tunnel.start_admin())
            exchange_mascot_identity(control, args.role, output)
            send(control, 'native_shape', length=len(token), account=account)
            template = receive(control, 'native_template')
            if args.route == 'claude_h2':
                head, slot = bootstrap(token, template['path'].encode(),
                                       tuple((name.encode(), value.encode())
                                             for name, value in template['headers']))
                partial = head
            else:
                head = request_head('codex', token)
                slot = head.index(token)
                partial = head[:slot + len(token) + 2]
            prefix_circuit(args.route, len(token), partial, slot)
            sponsor(control, args.route, args.provider_port, args.provider_ca, output,
                    provider_host=args.provider_host, token_bytes=token, account=account)
        else:
            exchange_mascot_identity(control, args.role, output)
            shape = receive(control, 'native_shape')
            length = shape['length']
            ingress_local, ingress_worker = socket.socketpair()
            host, port = args.listen.rsplit(':', 1)
            adapter = Adapter((host, int(port)), args.route, ingress_local)
            threading.Thread(target=adapter.serve_forever, daemon=True).start()
            print(f'NATIVE_READY {adapter.server_address[0]}:{adapter.server_port}', flush=True)
            if not adapter.first.wait(900):
                raise TimeoutError('no local CLI request reached the native adapter')
            template = adapter.first_metadata
            if args.route == 'claude_h2':
                head, slot = bootstrap(bytes(length), template['path'].encode(),
                                       tuple((name.encode(), value.encode())
                                             for name, value in template['headers']))
                partial = head
            else:
                head = request_head('codex', bytes(length))
                slot = head.index(bytes(length))
                partial = head[:slot + length + 2]
            prefix_circuit(args.route, length, partial, slot)
            send(control, 'native_template', **template)
            if args.route == 'codex':
                concurro(control, args.route, None, args.provider_ca, output,
                         client_socket=ingress_worker, account=shape.get('account'))
            else:
                concurro(control, args.route, None, args.provider_ca, output,
                         ingress_socket=ingress_worker)
            adapter.shutdown()


if __name__ == '__main__':
    main()
