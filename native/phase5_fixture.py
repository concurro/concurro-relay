"""Run successive Claude requests through mixed native roles and a local TLS fixture."""

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
from phase4_fixture import BUNDLE, DOCS, free_port, pump, stop, wait_text


HERE = Path(__file__).resolve().parent


def role_command(kind, role, sockets, output, provider_port, ca, ingress, worker):
    """Launch the selected Claude role through its existing boundary."""
    package = BUNDLE / role / 'native-runtime'
    command = ([str(worker)] if kind == 'rust' else
               [str(package / 'python'), str(package / 'worker/role.py')])
    command += ['--role', role, '--route', 'claude_h2', '--control', str(sockets[role][0]),
                '--aux', str(sockets[role][1]), '--runtime', str(package / 'runtime'),
                '--output', str(output / role), '--provider-host', '127.0.0.1',
                '--provider-port', str(provider_port), '--provider-ca', str(ca)]
    if role == 'concurro':
        command += ['--listen', ingress]
    return command


def main():
    """Retain all local provider, CLI, role and proof evidence for one pairing."""
    parser = argparse.ArgumentParser()
    parser.add_argument('--sponsor', choices=['python', 'rust'], required=True)
    parser.add_argument('--concurro', choices=['python', 'rust'], required=True)
    parser.add_argument('--client', choices=['synthetic', 'claude', 'large', 'bootstrap_disconnect', 'streaming_cancel', 'error401', 'error429'], default='synthetic')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--worker', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    for role in ('sponsor', 'concurro'):
        (output / role).mkdir()
    certs = output / 'certs'
    subprocess.run(['sh', str(DOCS / 'tls13-runnable-mvp/source/generate_synthetic_certs.sh'),
                    str(certs)], check=True, capture_output=True)
    socket_dir = Path(tempfile.mkdtemp(prefix='phase5-', dir='/private/tmp'))
    sockets = {}
    listeners = {}
    for role in ('sponsor', 'concurro'):
        paths = [socket_dir / f'{role[0]}-{name}.sock' for name in ('control', 'aux')]
        sockets[role] = paths
        for path in paths:
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(str(path))
            listener.listen(1)
            listeners[path] = listener
    provider = sponsor = concurro = None
    logs = []
    try:
        provider_log = (output / 'provider.log').open('w')
        provider_error = (output / 'provider-error.log').open('w')
        logs += [provider_log, provider_error]
        source = DOCS / 'claude-h2-prototype/v4-cli/source'
        provider_command = ([sys.executable, str(HERE / 'fixture_delayed_sse.py'),
                             '--source', str(source), '--certs', str(certs),
                             '--delay', '3', '--responses',
                             '2' if args.client == 'streaming_cancel' else '1',
                             '--max-connections', '1'] +
                            (['--error-status', args.client[-3:]]
                             if args.client in ('error401', 'error429') else [])
                            if args.client in ('streaming_cancel', 'error401', 'error429') else
                            [sys.executable, str(HERE / 'fixture_server.py'),
                             '--route', 'claude', '--source', str(source), '--certs', str(certs)])
        provider = subprocess.Popen(provider_command,
            stdout=subprocess.PIPE, stderr=provider_error, text=True, start_new_session=True,
            env=dict(os.environ, PYTHONPATH='/private/tmp/concurro-h2-deps'))
        port_line = provider.stdout.readline()
        (output / 'provider-port.json').write_text(port_line)
        provider_port = json.loads(port_line)['port']

        def provider_output():
            """Retain the fixture's completed stream projection."""
            for line in provider.stdout:
                provider_log.write(line)
                provider_log.flush()

        threading.Thread(target=provider_output, daemon=True).start()
        ingress = f'127.0.0.1:{free_port()}'
        credential = {'token': 'X' * 44, 'account': None}
        roles = {}
        for role, kind in [('sponsor', args.sponsor), ('concurro', args.concurro)]:
            log = (output / f'{role}.log').open('w')
            logs.append(log)
            environment = dict(os.environ, PATH='/opt/homebrew/bin:/usr/bin:/bin',
                               CONCURRO_NATIVE_TEST_TURNS='2',
                               CONCURRO_NATIVE_TEST_TURNS_CLAUDE='2',
                               HANDOFF_BENCHMARK_TIMEOUT='900')
            command = role_command(kind, role, sockets, output, provider_port,
                                   certs / 'chain-ca.pem', ingress, args.worker)
            roles[role] = subprocess.Popen(command,
                                           stdin=subprocess.PIPE if role == 'sponsor' else subprocess.DEVNULL,
                                           stdout=log, stderr=subprocess.STDOUT,
                                           env=environment, start_new_session=True)
        sponsor, concurro = roles['sponsor'], roles['concurro']
        sponsor.stdin.write(json.dumps(credential).encode())
        sponsor.stdin.close()
        links = {}
        for role in ('sponsor', 'concurro'):
            links[role] = [listeners[path].accept()[0] for path in sockets[role]]
        for left, right in zip(links['sponsor'], links['concurro']):
            threading.Thread(target=pump, args=(left, right), daemon=True).start()
            threading.Thread(target=pump, args=(right, left), daemon=True).start()
        wait_text(output / 'concurro.log', 'NATIVE_READY ', [provider, sponsor, concurro])
        client_dir = output / 'cli'
        if args.client in ('bootstrap_disconnect', 'streaming_cancel'):
            body = json.dumps({'model': 'claude-sonnet-5-5', 'max_tokens': 8,
                               'stream': True, 'messages': [{'role': 'user',
                               'content': 'Reply OK.'}]}).encode()
            host, port = ingress.rsplit(':', 1)
            with socket.create_connection((host, int(port)), timeout=30) as connection:
                request = (f'POST /v1/messages HTTP/1.1\r\nHost: {ingress}\r\n'
                           'Authorization: Bearer local-relay-placeholder\r\n'
                           'Content-Type: application/json\r\n'
                           'anthropic-version: 2023-06-01\r\n'
                           f'Content-Length: {len(body)}\r\n\r\n').encode() + body
                connection.sendall(request)
                if args.client == 'bootstrap_disconnect':
                    time.sleep(.2)
                else:
                    connection.settimeout(30)
                    received = bytearray()
                    while b'message_start' not in received:
                        part = connection.recv(4096)
                        if not part:
                            raise RuntimeError('Claude SSE ended before first event')
                        received.extend(part)
                    assert b'message_stop' not in received
                    (output / 'early-sse.bin').write_bytes(received)
            concurro.wait(timeout=30)
            sponsor.wait(timeout=30)
            assert 'NATIVE_CANCEL cli_disconnect' in (output / 'concurro.log').read_text()
            assert concurro.returncode != 0 and sponsor.returncode != 0
            for role in (concurro, sponsor):
                try:
                    os.killpg(role.pid, 0)
                except ProcessLookupError:
                    pass
                else:
                    raise RuntimeError(f'{role.args[0]} left native helpers running')
            (output / 'comparison.json').write_text(json.dumps({
                'sponsor': args.sponsor, 'concurro': args.concurro,
                'client': args.client, 'concurro_returncode': concurro.returncode,
                'sponsor_returncode': sponsor.returncode,
                'early_sse_bytes': len((output / 'early-sse.bin').read_bytes())
                if args.client == 'streaming_cancel' else 0}, indent=2) + '\n')
            print(json.dumps({'outcome': 'passed', 'output': str(output)}))
            return
        if args.client in ('error401', 'error429'):
            host, port = ingress.rsplit(':', 1)
            body = json.dumps({'model': 'claude-sonnet-5-5', 'max_tokens': 8,
                               'stream': True, 'messages': [{'role': 'user',
                               'content': 'Reply OK.'}]}).encode()
            connection = http.client.HTTPConnection(host, int(port), timeout=90)
            try:
                connection.request('POST', '/v1/messages', body=body,
                                   headers={'Authorization': 'Bearer local-relay-placeholder',
                                            'Content-Type': 'application/json',
                                            'anthropic-version': '2023-06-01'})
                response = connection.getresponse()
                error_body = response.read()
            finally:
                connection.close()
            status = int(args.client[-3:])
            assert response.status == status
            error_type = ('authentication_error' if status == 401 else 'rate_limit_error')
            assert json.loads(error_body)['error']['type'] == error_type
            concurro.wait(timeout=30)
            sponsor.wait(timeout=30)
            provider.wait(timeout=30)
            assert concurro.returncode != 0 and sponsor.returncode != 0
            evidence = json.loads(next((output / 'concurro').glob('**/provider-error.json')).read_text())
            assert evidence == {'status': status, 'content_type': 'application/json',
                                'error_type': error_type,
                                'response_sha256': hashlib.sha256(error_body).hexdigest()}
            (output / 'comparison.json').write_text(json.dumps({
                'sponsor': args.sponsor, 'concurro': args.concurro,
                'client': args.client, 'status': response.status,
                'error_type': error_type, 'body_bytes': len(error_body),
                'evidence': evidence, 'concurro_returncode': concurro.returncode,
                'sponsor_returncode': sponsor.returncode}, indent=2) + '\n')
            print(json.dumps({'outcome': 'passed', 'output': str(output)}))
            return
        for index in (1, 2):
            if args.client == 'large':
                host, port = ingress.rsplit(':', 1)
                body = json.dumps({'model': 'claude-sonnet-5-5', 'max_tokens': 8,
                                   'stream': True, 'messages': [{'role': 'user',
                                   'content': 'X' * 70_000 if index == 1 else 'Reply OK.'}]}).encode()
                connection = http.client.HTTPConnection(host, int(port), timeout=90)
                try:
                    connection.request('POST', '/v1/messages', body=body,
                                       headers={'Authorization': 'Bearer local-relay-placeholder',
                                                'Content-Type': 'application/json',
                                                'anthropic-version': '2023-06-01'})
                    response = connection.getresponse()
                    data = response.read()
                    assert response.status == 200 and b'event: message_stop' in data
                finally:
                    connection.close()
                (output / f'client-{index}.log').write_text(json.dumps({
                    'status': response.status, 'body_bytes': len(body),
                    'message_stop': True}) + '\n')
                continue
            script = (DOCS / 'tls13-concurrent-v16/run_synthetic_claude.py'
                      if args.client == 'synthetic' else
                      DOCS / 'tls13-packaged-first-slice/run_claude_cli.py')
            command = [str(BUNDLE / 'sponsor/native-runtime/python'), str(script), str(index),
                       '--output', str(client_dir), '--ingress', ingress]
            if args.client == 'claude':
                command += ['--claude-binary', str(Path.home() / '.local/bin/claude')]
            completed = subprocess.run(command, capture_output=True, text=True, timeout=300)
            (output / f'client-{index}.log').write_text(completed.stdout + completed.stderr)
            if completed.returncode:
                raise RuntimeError(f'Claude client {index} failed: {completed.returncode}')
        for role, process in roles.items():
            process.wait(timeout=180)
            if process.returncode:
                raise RuntimeError(f'{role} failed: {process.returncode}')
        provider.wait(timeout=30)
        wait_text(output / 'provider.log', 'requests', [], timeout=5)
        result = {'sponsor': args.sponsor, 'concurro': args.concurro,
                  'client': args.client,
                  'provider': json.loads((output / 'provider.log').read_text().splitlines()[-1]),
                  'sponsor_result': json.loads(next((output / 'sponsor').glob('**/sponsor-result.json')).read_text()),
                  'concurro_result': json.loads(next((output / 'concurro').glob('**/concurro-result.json')).read_text())}
        assert result['sponsor_result']['session_id'] == result['concurro_result']['session_id']
        assert result['sponsor_result']['h2'] == result['concurro_result']['h2']
        assert result['sponsor_result']['h3'] == result['concurro_result']['h3']
        assert len(result['provider']['requests']) == len(result['concurro_result']['responses']) == 2
        assert result['sponsor_result']['protected_bootstrap_count'] == 1
        assert result['sponsor_result']['indexed_headers_accepted'] == 1
        assert result['sponsor_result']['provider_connection_count'] == 1
        assert len(result['sponsor_result']['prompts']) == len(result['sponsor_result']['usage']) == 2
        assert [request['stream'] for request in result['provider']['requests']] == [1, 3]
        assert [response['stream'] for response in result['concurro_result']['responses']] == [1, 3]
        assert [entry['value'] for entry in result['sponsor_result']['usage']] == [
            response['usage'] for response in result['concurro_result']['responses']]
        assert all(response['status'] == 200 for response in result['concurro_result']['responses'])
        (output / 'comparison.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'outcome': 'passed', 'output': str(output)}))
    finally:
        for process in (concurro, sponsor, provider):
            stop(process)
        for listener in listeners.values():
            listener.close()
        for log in logs:
            log.close()
        shutil.rmtree(socket_dir)


if __name__ == '__main__':
    main()
