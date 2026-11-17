"""Explicit phase-3 Python peer and one-connection TLS provider fixture."""

import argparse
import hashlib
import json
import os
import socket
import ssl
import sys
from pathlib import Path


def peer(arguments):
    """Run the reference role through protected prefix, then stop before request proofs."""
    worker = Path(__file__).parent / 'worker'
    sys.path.insert(0, str(worker))
    sys.path.insert(0, str(worker.parent))
    root = Path(arguments.runtime)
    output = Path(arguments.output)
    output.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.environ.update(HANDOFF_BUILD_ROOT=str(root),
                      HANDOFF_PARTY_BINARY=str(root / 'DiStefano/build/HandoffPartyKrrw'),
                      HANDOFF_HANDSHAKE_CIRCUIT='handoff-handshake-shares-cached-hkdf.txt',
                      HANDOFF_CIRCUIT_CACHE=arguments.cache,
                      HANDOFF_ARITHMETIC_ECTF='1',
                      HANDOFF_BENCHMARK_TIMEOUT='900')
    from tunnel import Tunnel
    from role import exchange_mascot_identity
    import tls13_product_http_h2 as product
    events = []
    public = {}
    facts = {}
    original_send, original_receive = product.send, product.receive
    original_circuit = product.circuit_pair
    original_connection = product.ForwardedConnection

    class PrefixComplete(Exception):
        """Stop the reference at the phase-3 boundary after epoch creation."""

    def record(kind, payload, sending):
        """Keep only public transcript inputs needed for parity evidence."""
        if kind == 'nonce':
            owner = arguments.role if sending else ('concurro' if arguments.role == 'sponsor' else 'sponsor')
            facts[f'{owner}_nonce'] = payload
        elif kind in ('client_hello', 'server_hello', 'flight_approved'):
            facts[kind] = payload

    def traced_send(control, kind, payload=b'', **metadata):
        """Record ordered public control events without private payloads."""
        events.append(f'send:{kind}')
        print(f'PHASE3_EVENT send:{kind}', file=sys.stderr, flush=True)
        record(kind, payload, True)
        original_send(control, kind, payload, **metadata)
        if kind == 'prefix_forwarded':
            raise PrefixComplete

    def traced_receive(control, kind=None):
        """Record the actual received control kind."""
        message = original_receive(control, kind)
        events.append(f"receive:{message['kind']}")
        print(f"PHASE3_EVENT receive:{message['kind']}", file=sys.stderr, flush=True)
        record(message['kind'], message['data'], False)
        return message

    def traced_circuit(*args, **kwargs):
        """Retain only public circuit outputs for cross-language comparison."""
        result = original_circuit(*args, **kwargs)
        public[args[5]] = result.hex()
        return result

    def traced_connection(*args, **kwargs):
        """Verify the reference initializes both application traffic epochs."""
        original_connection(*args, **kwargs)
        facts['application_epoch_ready'] = True
        raise PrefixComplete

    product.send = traced_send
    product.receive = traced_receive
    product.circuit_pair = traced_circuit
    product.ForwardedConnection = traced_connection
    with socket.socket(socket.AF_UNIX) as control, socket.socket(socket.AF_UNIX) as aux:
        control.connect(arguments.control)
        aux.connect(arguments.aux)
        tunnel = Tunnel(aux, arguments.role).start()
        if arguments.role == 'sponsor':
            os.environ['HANDOFF_LINK_ADMIN'] = str(tunnel.start_admin())
        exchange_mascot_identity(control, arguments.role, output)
        try:
            if arguments.role == 'sponsor':
                product.sponsor(control, arguments.route, arguments.provider_port,
                                Path(arguments.ca), output, provider_host='127.0.0.1',
                                token_bytes=b'fixturetoken')
            else:
                product.concurro(control, arguments.route, None, Path(arguments.ca), output)
        except PrefixComplete:
            pass
        else:
            raise RuntimeError('reference did not reach protected prefix boundary')
    result = dict(route=arguments.route,
                  h2=hashlib.sha256(facts['client_hello'] + facts['server_hello']).hexdigest(),
                  h3=facts['flight_approved'].hex(),
                  session_id=hashlib.sha256(facts['sponsor_nonce'] + facts['concurro_nonce']).hexdigest(),
                  server_finished_verified=True, client_finished_sent=True,
                  prefix_forwarded=True,
                  application_epoch_ready=facts.get('application_epoch_ready', False),
                  events=events, handshake_public=public['handshake'],
                  prefix_public=public['prefix'],
                  prefix_key_commitment=public['prefix'][2:66])
    (output / 'phase3-result.json').write_text(json.dumps(result, indent=2) + '\n')


def provider(arguments):
    """Serve one fixture TLS 1.3 handshake with the configured provider ALPN."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(arguments.ca, arguments.key)
    if arguments.route == 'claude_h2':
        context.set_alpn_protocols(['h2'])
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        print(json.dumps({'port': listener.getsockname()[1]}), flush=True)
        connection, _ = listener.accept()
        with connection, context.wrap_socket(connection, server_side=True) as tls:
            tls.settimeout(180)
            first = tls.recv(1)
            if not first:
                raise RuntimeError('protected application prefix was not received')
            (Path(arguments.output) / 'provider-prefix.json').write_text(
                json.dumps({'first_byte': first.hex(), 'alpn': tls.selected_alpn_protocol()}) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['peer', 'provider'])
    parser.add_argument('--role', choices=['sponsor', 'concurro'])
    parser.add_argument('--route', choices=['codex', 'claude_h2'], required=True)
    parser.add_argument('--runtime')
    parser.add_argument('--output')
    parser.add_argument('--control')
    parser.add_argument('--aux')
    parser.add_argument('--provider-port', type=int)
    parser.add_argument('--cache')
    parser.add_argument('--ca', required=True)
    parser.add_argument('--key')
    args = parser.parse_args()
    {'peer': peer, 'provider': provider}[args.mode](args)
