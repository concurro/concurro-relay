"""Run local Codex tool turns against mixed Python/Rust native roles."""

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time


HERE = Path(__file__).resolve().parent
DOCS = Path('/Users/cylwit/Code/github.com/concurro/concurro/.worktrees/sponsor-relay-design/docs/proposals/sponsor-relay')
BUNDLE = Path('/Users/cylwit/Code/github.com/concurro/.artifacts/concurro-relay-native-v16')


def free_port():
    """Reserve one loopback port for the local CLI listener."""
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def wait_text(path, marker, processes, timeout=180):
    """Wait for one readiness event while retaining early failures."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists() and marker in path.read_text(errors='replace'):
            return
        for process in processes:
            if process.poll() is not None:
                raise RuntimeError(f'early exit {process.args[0]}: {process.returncode}')
        time.sleep(.1)
    raise TimeoutError(marker)


def pump(source, target):
    """Forward one authenticated bridge direction with half-close."""
    try:
        while data := source.recv(65536):
            target.sendall(data)
        target.shutdown(socket.SHUT_WR)
    except OSError:
        source.close()
        target.close()


def stop(process):
    """Stop one fixture process group and its native helper children."""
    if process is None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except (ProcessLookupError, PermissionError, subprocess.TimeoutExpired):
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)


def role_command(kind, role, sockets, output, provider_port, ca, ingress, worker):
    """Choose an explicitly selected Python or Rust role with the same CLI."""
    package = BUNDLE / role / 'native-runtime'
    command = ([str(worker)] if kind == 'rust' else
               [str(package / 'python'), str(package / 'worker/role.py')])
    command += ['--role', role, '--route', 'codex', '--control', str(sockets[role][0]),
                '--aux', str(sockets[role][1]), '--runtime', str(package / 'runtime'),
                '--output', str(output / role), '--provider-host', '127.0.0.1',
                '--provider-port', str(provider_port), '--provider-ca', str(ca)]
    if role == 'concurro':
        command += ['--listen', ingress]
    return command


def main():
    """Preserve each fresh case's role, provider, CLI and proof evidence."""
    parser = argparse.ArgumentParser()
    parser.add_argument('--sponsor', choices=['python', 'rust'], required=True)
    parser.add_argument('--concurro', choices=['python', 'rust'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--client', choices=['synthetic', 'codex', 'fragmented', 'pending_cancel', 'bootstrap_disconnect'], default='synthetic')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    for role in ('sponsor', 'concurro'):
        (output / role).mkdir()
    certs = output / 'certs'
    subprocess.run(['sh', str(DOCS / 'tls13-runnable-mvp/source/generate_synthetic_certs.sh'),
                    str(certs)], check=True, capture_output=True)
    socket_dir = Path(tempfile.mkdtemp(prefix='phase4-', dir='/private/tmp'))
    listeners = {}
    sockets = {}
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
        provider = subprocess.Popen([
            str(BUNDLE / 'sponsor/native-runtime/python'), str(HERE / 'fixture_server.py'),
            '--route', 'codex', '--source', str(DOCS / 'codex-live-ws-v1/source'),
            '--certs', str(certs), '--tool-loop', '--calls',
            '2' if args.client == 'pending_cancel' else '3',
            *(['--delay-inference', '2'] if args.client == 'pending_cancel' else [])],
            stdout=subprocess.PIPE, stderr=provider_error, text=True, start_new_session=True)
        port_line = provider.stdout.readline()
        (output / 'provider-port.json').write_text(port_line)
        provider_port = json.loads(port_line)['port']
        def provider_output():
            """Retain the synthetic provider's final connection projection."""
            for line in provider.stdout:
                provider_log.write(line)
                provider_log.flush()
        threading.Thread(target=provider_output, daemon=True).start()
        ingress = f'127.0.0.1:{free_port()}'
        credential = {'token': 'SYNTHETIC_CODEX_' + 'X' * 69, 'account': 'synthetic-account-101'}
        roles = {}
        for role, kind in [('sponsor', args.sponsor), ('concurro', args.concurro)]:
            log = (output / f'{role}.log').open('w')
            logs.append(log)
            environment = dict(os.environ, PATH='/opt/homebrew/bin:/usr/bin:/bin',
                               CONCURRO_NATIVE_TEST_TURNS_CODEX='2',
                               HANDOFF_BENCHMARK_TIMEOUT='900')
            command = role_command(kind, role, sockets, output, provider_port,
                                   certs / 'chain-ca.pem', ingress, args.worker)
            roles[role] = subprocess.Popen(command, stdin=subprocess.PIPE if role == 'sponsor' else subprocess.DEVNULL,
                                           stdout=log, stderr=subprocess.STDOUT, env=environment,
                                           start_new_session=True)
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
        if args.client == 'synthetic':
            command = [str(BUNDLE / 'sponsor/native-runtime/python'),
                       str(DOCS / 'tls13-concurrent-v16/run_synthetic_codex_reconnect.py'), '1',
                       '--output', str(client_dir), '--ingress', ingress]
        elif args.client == 'codex':
            command = [str(BUNDLE / 'sponsor/native-runtime/python'),
                       str(DOCS / 'tls13-packaged-first-slice/run_codex_cli.py'),
                       '--output', str(client_dir), '--ingress', ingress,
                       '--codex-binary', '/opt/homebrew/bin/codex']
        else:
            command = [str(BUNDLE / 'sponsor/native-runtime/python'),
                       str(HERE / 'phase4_codex_client.py'), args.client,
                       '--output', str(client_dir), '--ingress', ingress]
        client = subprocess.run(command, capture_output=True, text=True, timeout=300)
        (output / 'client.log').write_text(client.stdout + client.stderr)
        if client.returncode:
            raise RuntimeError(f'local client failed: {client.returncode}')
        if args.client == 'bootstrap_disconnect':
            concurro.wait(timeout=30)
            sponsor.wait(timeout=30)
            assert 'NATIVE_CANCEL cli_disconnect' in (output / 'concurro.log').read_text()
            assert concurro.returncode != 0
            assert sponsor.returncode != 0
            for role in (concurro, sponsor):
                try:
                    os.killpg(role.pid, 0)
                except ProcessLookupError:
                    pass
                else:
                    raise RuntimeError(f'{role.args[0]} left native helpers running')
            (output / 'comparison.json').write_text(json.dumps({
                'sponsor': args.sponsor, 'concurro': args.concurro,
                'client': args.client, 'cli': json.loads((client_dir / 'summary.json').read_text()),
                'concurro_returncode': concurro.returncode,
                'sponsor_returncode': sponsor.returncode}, indent=2) + '\n')
            print(json.dumps({'outcome': 'passed', 'output': str(output)}))
            return
        if args.client == 'pending_cancel':
            concurro.wait(timeout=30)
            if 'NATIVE_CANCEL codex_cancel' not in (output / 'concurro.log').read_text():
                raise RuntimeError('queued active turn did not cancel native session')
            (output / 'comparison.json').write_text(json.dumps({
                'sponsor': args.sponsor, 'concurro': args.concurro,
                'client': args.client, 'cli': json.loads((client_dir / 'summary.json').read_text()),
                'concurro_returncode': concurro.returncode}, indent=2) + '\n')
            print(json.dumps({'outcome': 'passed', 'output': str(output)}))
            return
        for role, process in roles.items():
            process.wait(timeout=180)
            if process.returncode:
                raise RuntimeError(f'{role} failed: {process.returncode}')
        provider.wait(timeout=30)
        wait_text(output / 'provider.log', 'provider_connections', [], timeout=5)
        result = {'sponsor':args.sponsor, 'concurro':args.concurro,
                  'client':args.client, 'cli':json.loads((client_dir / 'summary.json').read_text()),
                  'provider':json.loads((output / 'provider.log').read_text().splitlines()[-1]),
                  'sponsor_result':json.loads(next((output / 'sponsor').glob('**/sponsor-result.json')).read_text()),
                  'concurro_result':json.loads(next((output / 'concurro').glob('**/concurro-result.json')).read_text())}
        sponsor_result = result['sponsor_result']
        concurro_result = result['concurro_result']
        provider_result = result['provider']
        assert sponsor_result['session_id'] == concurro_result['session_id']
        assert sponsor_result['h2'] == concurro_result['h2']
        assert sponsor_result['h3'] == concurro_result['h3']
        assert sponsor_result['request_proof_records'] == (7 if args.client == 'codex' else 4)
        assert sponsor_result['protected_bootstrap_count'] == 1
        assert provider_result['provider_connections'] == 1
        assert len(sponsor_result['prompts']) == len(sponsor_result['usage']) == 3
        assert len(concurro_result['responses']) == len(provider_result['bindings']) == 3
        assert [item['id'] for item in concurro_result['responses']] == [
            item['response_id'] for item in provider_result['bindings']]
        assert [item['usage'] for item in concurro_result['responses']] == [
            item['value'] for item in sponsor_result['usage']]
        audits = [json.loads(line.removeprefix('NATIVE_AUDIT '))
                  for line in (output / 'sponsor.log').read_text().splitlines()
                  if line.startswith('NATIVE_AUDIT ')]
        assert [item['sha256'] for item in audits] == [
            item['sha256'] for item in sponsor_result['prompts']]
        assert 'TOOL_LOOP_DONE' in json.dumps(result['cli'].get('answer'))
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
