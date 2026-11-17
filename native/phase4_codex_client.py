"""Exercise local preflight, fragmented messages and queued-turn cancellation."""

import argparse
import json
import os
from pathlib import Path
import socket
import struct
import sys
import time

DOCS = Path('/Users/cylwit/Code/github.com/concurro/concurro/.worktrees/sponsor-relay-design/docs/proposals/sponsor-relay')
sys.path.insert(0, str(DOCS / 'tls13-concurrent-v16'))
from run_synthetic_codex_reconnect import completed, connect
sys.path.insert(0, str(DOCS / 'tls13-packaged-v13'))
from run_codex_cancel_offline import event, frame


def fragmented_frame(connection, value):
    """Send one JSON message as two masked WebSocket fragments and short TCP writes."""
    payload = json.dumps(value, separators=(',', ':')).encode()
    middle = max(1, len(payload) // 2)
    for index, part in enumerate((payload[:middle], payload[middle:])):
        mask = os.urandom(4)
        size = (bytes([0x80 | len(part)]) if len(part) < 126 else
                b'\xfe' + struct.pack('!H', len(part)) if len(part) < 65536 else
                b'\xff' + struct.pack('!Q', len(part)))
        wire = bytes([0x01 if index == 0 else 0x80]) + size + mask + bytes(
            byte ^ mask[offset % 4] for offset, byte in enumerate(part))
        for start in range(0, len(wire), 7):
            connection.sendall(wire[start:start + 7])


def preflight(ingress):
    """Check the loopback OPTIONS route without bootstrapping a provider turn."""
    host, port = ingress.rsplit(':', 1)
    with socket.create_connection((host, int(port)), timeout=30) as connection:
        connection.sendall(f'OPTIONS /v1/responses HTTP/1.1\r\nHost: {ingress}\r\n\r\n'.encode())
        reply = bytearray()
        while not reply.endswith(b'\r\n\r\n'):
            reply.extend(connection.recv(1))
        assert reply.startswith(b'HTTP/1.1 204 '), reply


def run_fragmented(ingress):
    """Complete a tool call while each local JSON message crosses frame boundaries."""
    preflight(ingress)
    with connect(ingress) as connection:
        fragmented_frame(connection, {'type': 'response.create', 'model': 'gpt-6.1-terra',
                                      'generate': False, 'input': []})
        warmup = completed(connection)
        fragmented_frame(connection, {'type': 'response.create', 'model': 'gpt-6.1-terra',
                                      'previous_response_id': warmup['id'],
                                      'input': [{'role': 'user', 'content': 'Reply for session 1.'}]})
        tool = completed(connection)
        call = next(item for item in tool['output'] if item['type'] == 'custom_tool_call')
        fragmented_frame(connection, {'type': 'response.create', 'model': 'gpt-6.1-terra',
                                      'previous_response_id': tool['id'],
                                      'input': [{'type': 'custom_tool_call_output', 'call_id': call['call_id'],
                                                 'output': 'step-01\nWall time: 0.001 seconds'}]})
        final = completed(connection)
    assert final['previous_response_id'] == tool['id']
    assert 'TOOL_LOOP_DONE' in json.dumps(final['output'])
    return {'returncode': 0, 'preflight': 204, 'fragmented_messages': 3,
            'response_ids': [warmup['id'], tool['id'], final['id']], 'answer': 'TOOL_LOOP_DONE'}


def run_pending_cancel(ingress):
    """Cancel while a generated turn is active and its successor is queued."""
    with connect(ingress) as connection:
        frame(connection, {'type': 'response.create', 'model': 'gpt-6.1-terra',
                           'generate': False, 'input': []})
        warmup = completed(connection)
        request = {'type': 'response.create', 'model': 'gpt-6.1-terra',
                   'previous_response_id': warmup['id'],
                   'input': [{'role': 'user', 'content': 'Reply for session 1.'}]}
        frame(connection, request)
        frame(connection, request)
        while event(connection)['type'] != 'response.created':
            pass
        frame(connection, {'type': 'response.cancel'})
        time.sleep(.2)
    return {'returncode': 0, 'active_cancel': True, 'queued_successor': True}


def run_bootstrap_disconnect(ingress):
    """Close a valid upgrade before provider authentication completes."""
    host, port = ingress.rsplit(':', 1)
    with socket.create_connection((host, int(port)), timeout=30) as connection:
        connection.sendall((
            'GET /v1/responses HTTP/1.1\r\n'
            f'Host: {ingress}\r\n'
            'Authorization: Bearer local-relay-placeholder\r\n'
            'Connection: Upgrade\r\n'
            'Upgrade: websocket\r\n'
            'Sec-WebSocket-Version: 13\r\n'
            'Sec-WebSocket-Key: AQIDBAUGBwgJCgsMDQ4PEA==\r\n\r\n'
        ).encode())
        time.sleep(.2)
    return {'returncode': 0, 'closed_before_upgrade': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['fragmented', 'pending_cancel', 'bootstrap_disconnect'])
    parser.add_argument('--ingress', required=True)
    parser.add_argument('--output', type=Path, required=True)
    arguments = parser.parse_args()
    arguments.output.mkdir(parents=True, exist_ok=True)
    runner = {'fragmented': run_fragmented, 'pending_cancel': run_pending_cancel,
              'bootstrap_disconnect': run_bootstrap_disconnect}[arguments.mode]
    result = runner(arguments.ingress)
    (arguments.output / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result), flush=True)
