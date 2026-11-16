"""Serve accepted Claude events with fragmented TLS records and delayed completion."""

import argparse
import hashlib
import json
import runpy
import socket
import ssl
import sys
import time
from pathlib import Path


def send_fragments(connection, payload):
    """Split one HTTP/2 write across several TLS records."""
    for size in (1, 2, 5):
        if not payload:
            return
        connection.sendall(payload[:size])
        payload = payload[size:]
    if payload:
        connection.sendall(payload)


def main():
    """Keep provider egress available across a canceled and a recovered link."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--certs', required=True, type=Path)
    parser.add_argument('--delay', type=float, default=2)
    parser.add_argument('--responses', type=int, default=2)
    parser.add_argument('--max-connections', type=int, default=3)
    args = parser.parse_args()
    sys.path.insert(0, str(args.source))
    accepted = runpy.run_path(str(args.source / 'run_cli.py'))
    H2Configuration = accepted['H2Configuration']
    H2Connection = accepted['H2Connection']
    RequestReceived = accepted['RequestReceived']
    DataReceived = accepted['DataReceived']
    StreamEnded = accepted['StreamEnded']
    claude_events = accepted['claude_events']
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(['h2'])
    context.load_cert_chain(args.certs / 'chain-provider.pem',
                            args.certs / 'chain-provider.key')
    context.set_ecdh_curve('prime256v1')
    result = {'connections': 0, 'requests': [], 'responses': 0}
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(8)
        listener.settimeout(120)
        print(json.dumps({'port': listener.getsockname()[1]}), flush=True)
        started = time.monotonic()
        while result['responses'] < args.responses and result['connections'] < args.max_connections:
            raw, _ = listener.accept()
            result['connections'] += 1
            print(json.dumps({'fixture_event': 'connected',
                              'connection': result['connections']}), file=sys.stderr, flush=True)
            try:
                with context.wrap_socket(raw, server_side=True) as connection:
                    connection.settimeout(120)
                    h2 = H2Connection(config=H2Configuration(client_side=False,
                                                             header_encoding=None))
                    h2.initiate_connection()
                    send_fragments(connection, h2.data_to_send())
                    pending = {}
                    while True:
                        data = connection.recv(65536)
                        if not data:
                            break
                        for event in h2.receive_data(data):
                            if isinstance(event, RequestReceived):
                                fields = dict(event.headers)
                                if fields.get(b'authorization') != b'Bearer ' + b'X' * 44:
                                    raise ValueError('provider Authorization differs from Sponsor token')
                                pending[event.stream_id] = bytearray()
                            elif isinstance(event, DataReceived):
                                pending[event.stream_id].extend(event.data)
                                h2.acknowledge_received_data(event.flow_controlled_length,
                                                             event.stream_id)
                            elif isinstance(event, StreamEnded):
                                body = bytes(pending.pop(event.stream_id))
                                request = json.loads(body)
                                item = {'connection': result['connections'],
                                        'stream': event.stream_id,
                                        'auth_matches': True,
                                        'body_sha256': hashlib.sha256(body).hexdigest()}
                                result['requests'].append(item)
                                print(json.dumps({'fixture_event': 'request', **item}),
                                      file=sys.stderr, flush=True)
                                events = claude_events(request, 'OK')
                                encoded = [b'event: ' + value['type'].encode() + b'\n' +
                                           b'data: ' + json.dumps(value).encode() + b'\n\n'
                                           for value in events]
                                h2.send_headers(event.stream_id,
                                                [(b':status', b'200'),
                                                 (b'content-type', b'text/event-stream')])
                                h2.send_data(event.stream_id, encoded[0], end_stream=False)
                                send_fragments(connection, h2.data_to_send())
                                item['first_event_ms'] = round(
                                    (time.monotonic() - started) * 1000, 1)
                                if len(result['requests']) == 1:
                                    time.sleep(args.delay)
                                for index, chunk in enumerate(encoded[1:], 1):
                                    h2.send_data(event.stream_id, chunk,
                                                 end_stream=index == len(encoded) - 1)
                                    send_fragments(connection, h2.data_to_send())
                                item['final_event_ms'] = round(
                                    (time.monotonic() - started) * 1000, 1)
                                result['responses'] += 1
                                print(json.dumps({'fixture_event': 'response_sent',
                                                  'connection': result['connections'],
                                                  'stream': event.stream_id}),
                                      file=sys.stderr, flush=True)
                        outgoing = h2.data_to_send()
                        if outgoing:
                            send_fragments(connection, outgoing)
            except Exception as error:
                result.setdefault('closed_connections', []).append(
                    {'connection': result['connections'], 'error': type(error).__name__})
                print(json.dumps({'fixture_event': 'connection_error',
                                  'connection': result['connections'],
                                  'error': repr(error)}), file=sys.stderr, flush=True)
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
