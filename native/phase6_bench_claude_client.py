"""Measure two identical local Claude requests over one native provider session."""

import argparse
import http.client
import json
from pathlib import Path
import time


def main():
    """Record first authenticated body byte and completion for cold and warm turns."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('index', type=int)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--ingress', required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    host, port = args.ingress.rsplit(':', 1)
    body = json.dumps({'model': 'claude-sonnet-5-5', 'max_tokens': 8,
                       'stream': True, 'messages': [{'role': 'user',
                       'content': f'Reply OK {args.index}.'}]}).encode()
    headers = {'Authorization': 'Bearer local-relay-placeholder',
               'Content-Type': 'application/json', 'anthropic-version': '2023-06-01'}
    turns = []
    for phase in ('cold', 'warm'):
        connection = http.client.HTTPConnection(host, int(port), timeout=600)
        started = time.monotonic()
        try:
            connection.request('POST', '/v1/messages', body=body, headers=headers)
            response = connection.getresponse()
            headers_ms = round((time.monotonic() - started) * 1000, 1)
            first = response.read(1)
            first_body_ms = round((time.monotonic() - started) * 1000, 1)
            data = first + response.read()
            total_ms = round((time.monotonic() - started) * 1000, 1)
        finally:
            connection.close()
        assert response.status == 200 and b'event: message_stop' in data
        turns.append({'phase': phase, 'status': response.status,
                      'first_headers_ms': headers_ms, 'first_body_ms': first_body_ms,
                      'complete_ms': total_ms, 'response_bytes': len(data)})
    summary = {'request': args.index, 'returncode': 0, 'status': 200,
               'message_stop': True, 'turns': turns}
    (output / f'cli-{args.index}-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary), flush=True)


if __name__ == '__main__':
    main()
