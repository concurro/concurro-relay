"""Serve concurrent accepted Claude H2 fixture sessions for mixed-route tests."""

import argparse
import hashlib
import json
import runpy
import socket
import ssl
import sys
import threading
import time
from pathlib import Path

from fixture_delayed_sse import send_fragments


def serve_connection(raw, number, context, accepted, result, lock, started, delay):
    """Answer one authenticated H2 connection and record only request hashes."""
    H2Configuration = accepted['H2Configuration']
    H2Connection = accepted['H2Connection']
    RequestReceived = accepted['RequestReceived']
    DataReceived = accepted['DataReceived']
    StreamEnded = accepted['StreamEnded']
    claude_events = accepted['claude_events']
    try:
        with context.wrap_socket(raw, server_side=True) as connection:
            connection.settimeout(120)
            h2 = H2Connection(config=H2Configuration(client_side=False, header_encoding=None))
            h2.initiate_connection()
            send_fragments(connection, h2.data_to_send())
            pending = {}
            while data := connection.recv(65536):
                for event in h2.receive_data(data):
                    if isinstance(event, RequestReceived):
                        fields = dict(event.headers)
                        if fields.get(b'authorization') != b'Bearer ' + b'X' * 44:
                            raise ValueError('provider Authorization differs from Sponsor token')
                        pending[event.stream_id] = bytearray()
                    elif isinstance(event, DataReceived):
                        pending[event.stream_id].extend(event.data)
                        h2.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, StreamEnded):
                        body = bytes(pending.pop(event.stream_id))
                        request = json.loads(body)
                        row = {'connection': number, 'stream': event.stream_id,
                               'auth_matches': True,
                               'body_sha256': hashlib.sha256(body).hexdigest(),
                               'request_ms': round((time.monotonic() - started) * 1000, 1)}
                        with lock:
                            result['requests'].append(row)
                        print(json.dumps({'fixture_event': 'request', **row}),
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
                        row['first_event_ms'] = round((time.monotonic() - started) * 1000, 1)
                        time.sleep(delay)
                        for index, chunk in enumerate(encoded[1:], 1):
                            h2.send_data(event.stream_id, chunk,
                                         end_stream=index == len(encoded) - 1)
                            send_fragments(connection, h2.data_to_send())
                        row['final_event_ms'] = round((time.monotonic() - started) * 1000, 1)
                        with lock:
                            result['responses'] += 1
                        print(json.dumps({'fixture_event': 'response', **row}),
                              file=sys.stderr, flush=True)
                outgoing = h2.data_to_send()
                if outgoing:
                    send_fragments(connection, outgoing)
    except Exception as error:
        with lock:
            result['errors'].append({'connection': number, 'error': type(error).__name__})
        print(f'fixture connection {number}: {error!r}', file=sys.stderr, flush=True)
    finally:
        with lock:
            result['active_connections'] -= 1


def main():
    """Start a concurrent TLS fixture and stop after the requested responses."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--certs', required=True, type=Path)
    parser.add_argument('--responses', required=True, type=int)
    parser.add_argument('--delay', type=float, default=2)
    args = parser.parse_args()
    sys.path.insert(0, str(args.source))
    accepted = runpy.run_path(str(args.source / 'run_cli.py'))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(['h2'])
    context.load_cert_chain(args.certs / 'chain-provider.pem',
                            args.certs / 'chain-provider.key')
    context.set_ecdh_curve('prime256v1')
    result = {'connections': 0, 'active_connections': 0, 'peak_connections': 0,
              'requests': [], 'responses': 0, 'errors': []}
    lock = threading.Lock()
    started = time.monotonic()
    workers = []
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        listener.settimeout(.25)
        print(json.dumps({'port': listener.getsockname()[1]}), flush=True)
        while True:
            with lock:
                if result['responses'] >= args.responses:
                    break
            try:
                raw, _ = listener.accept()
            except TimeoutError:
                continue
            with lock:
                result['connections'] += 1
                number = result['connections']
                result['active_connections'] += 1
                result['peak_connections'] = max(result['peak_connections'],
                                                 result['active_connections'])
            worker = threading.Thread(target=serve_connection,
                                      args=(raw, number, context, accepted, result, lock,
                                            started, args.delay), daemon=True)
            worker.start()
            workers.append(worker)
    for worker in workers:
        worker.join(timeout=30)
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
