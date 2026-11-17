"""Serve one local TLS 1.3 provider connection for native bootstrap tests."""

import argparse
import json
import socket
import ssl
from pathlib import Path


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
    parser.add_argument('--route', choices=['codex', 'claude_h2'], required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--ca', required=True)
    parser.add_argument('--key', required=True)
    provider(parser.parse_args())
