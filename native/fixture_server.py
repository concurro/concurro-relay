"""Run accepted synthetic providers for offline native-link acceptance tests."""

import argparse
import json
import os
import runpy
import socket
import sys
import threading
import time
from pathlib import Path


def main():
    """Run the requested accepted fixture on one local TLS 1.3 socket."""
    parser = argparse.ArgumentParser()
    parser.add_argument('--route', choices=('codex', 'claude'), required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--certs', type=Path, required=True)
    parser.add_argument('--tool-loop', action='store_true')
    parser.add_argument('--calls', type=int, default=2)
    parser.add_argument('--delay-inference', type=float, default=0)
    args = parser.parse_args()
    sys.path.insert(0, str(args.source))
    fixture = runpy.run_path(str(args.source / ('run_codex_cli.py' if args.route == 'codex'
                                               else 'run_cli.py')))
    if args.tool_loop:
        if args.route != 'codex':
            parser.error('--tool-loop requires --route codex')
        sys.path.insert(0, str(args.source.parents[1] / 'tls13-runnable-mvp'))
        from codex_tool_loop_lite_provider import ToolLoopProvider
        connections = {'active': 0, 'peak': 0}
        connections_lock = threading.Lock()

        class CountingToolLoopProvider(ToolLoopProvider):
            """Record peak concurrent provider connections in the local fixture."""

            def do_GET(self):
                """Count this authenticated WebSocket until its handler returns."""
                with connections_lock:
                    connections['active'] += 1
                    connections['peak'] = max(connections['peak'], connections['active'])
                try:
                    super().do_GET()
                finally:
                    with connections_lock:
                        connections['active'] -= 1

        ToolLoopProvider = CountingToolLoopProvider
        if args.delay_inference:
            class DelayedToolLoopProvider(ToolLoopProvider):
                """Pause after the first generated event for cancellation tests."""

                def send_frame(self, payload, *extra):
                    """Send the authenticated event before delaying completion."""
                    super().send_frame(payload, *extra)
                    event = json.loads(payload)
                    if (not getattr(self, '_native_delayed', False) and
                            event.get('type') == 'response.created' and
                            event.get('response', {}).get('generate') is not False):
                        self._native_delayed = True
                        time.sleep(args.delay_inference)

            ToolLoopProvider = DelayedToolLoopProvider
        fixture['serve_fixture'].__globals__['ProviderWebSocket'] = ToolLoopProvider
        os.environ['TOOL_LOOP_STEPS'] = '1'
        os.environ['TOOL_LOOP_OUTPUT_BYTES'] = '[200]'
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(8)
    print(json.dumps({'port': listener.getsockname()[1]}), flush=True)
    result = {'requests': []} if args.route == 'claude' else {}
    token = (b'SYNTHETIC_CODEX_' + b'X' * 69 if args.route == 'codex' else b'X' * 44)
    parameters = (listener, args.certs / 'chain-provider.pem',
                  args.certs / 'chain-provider.key', token)
    if args.route == 'codex':
        parameters += ('synthetic-account-101', result)
    else:
        parameters += (result,)
    if args.route == 'codex':
        def finish_after_calls():
            """End the accepted fixture after the expected provider calls."""
            while 'server' not in result:
                time.sleep(.05)
            provider = result['server']
            while len([call for call in provider.state.calls if 'body' in call]) < args.calls:
                time.sleep(.05)
            provider.shutdown()
        threading.Thread(target=finish_after_calls, daemon=True).start()
    fixture['serve_fixture'](*parameters)
    if args.tool_loop:
        calls = result['server'].state.calls
        result['provider_connections'] = len([call for call in calls
                                              if call.get('kind') == 'connection'])
        result['peak_connections'] = connections['peak']
        result['bindings'] = [{'connection': call['connection'],
                               'request_index': call['request_index'],
                               'parent': call.get('previous_response_id'),
                               'response_id': call.get('response_id'),
                               'issued_call_id': call.get('issued_call_id'),
                               'validated_output_sha256': call.get('validated_tool_output_sha256')}
                              for call in calls if call.get('kind') == 'request']
    result.pop('server', None)
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
