"""Project matched local WAN fixture runs without adding overlapping helper times."""

import argparse
import json
from pathlib import Path
import statistics


def helper_metrics(directory, role):
    """Read accepted helper-reported elapsed times for one role session."""
    root = next((directory / role).glob('concurro-native-*'))
    phases = {}
    for phase in ('handshake', 'prefix'):
        text = (root / f'{role}-{phase}-mpc.log').read_text()
        metric = next(line.split(' ', 1)[1] for line in text.splitlines()
                      if line.startswith('HANDOFF_METRICS '))
        phases[phase] = json.loads(metric)['elapsed_ms']
    proofs = []
    for path in root.glob(f'{role}-request-*-proof.log'):
        text = path.read_text()
        line = next(line.split(' ', 1)[1] for line in text.splitlines()
                    if line.startswith('REQUEST_OK '))
        proofs.append(json.loads(line)['elapsed_ms'])
    phases['proof_count'] = len(proofs)
    phases['proof_elapsed_ms_sum'] = sum(proofs)
    return phases


def resource_peak(directory):
    """Sample aggregate parent, worker, and helper CPU/RSS by process ancestry."""
    samples = json.loads((directory / 'resource-samples.json').read_text())
    rss_mib = cpu_pct = 0
    for sample in samples:
        rows = {item['pid']: item for item in sample['processes']}
        owned = {pid for pid, item in rows.items()
                 if '/bin/concurro-relay ' in item.get('command', '')
                 or '/bin/dev-verifier ' in item.get('command', '')}
        changed = True
        while changed:
            previous = len(owned)
            owned.update(pid for pid, item in rows.items() if item['ppid'] in owned)
            changed = len(owned) != previous
        rss_mib = max(rss_mib, sum(rows[pid]['rss_kib'] for pid in owned) / 1024)
        cpu_pct = max(cpu_pct, sum(rows[pid]['cpu_pct'] for pid in owned))
    return {'peak_rss_mib': round(rss_mib, 1), 'peak_cpu_pct': round(cpu_pct, 1)}


def project(directory):
    """Verify one two-turn run and retain its bounded comparison metrics."""
    summary = json.loads((directory / 'summary.json').read_text())
    client = summary['cli'][0]['summary']
    sponsor = json.loads(next((directory / 'sponsor').glob('*/sponsor-result.json')).read_text())
    concurro = json.loads(next((directory / 'concurro').glob('*/concurro-result.json')).read_text())
    provider = summary['provider_claude']
    assert client['returncode'] == 0 and len(client['turns']) == 2
    assert [item['phase'] for item in client['turns']] == ['cold', 'warm']
    assert sponsor['session_id'] == concurro['session_id']
    assert sponsor['protected_bootstrap_count'] == 1
    assert sponsor['provider_connection_count'] == provider['connections'] == 1
    assert sponsor['indexed_headers_accepted'] == 1
    assert len(sponsor['prompts']) == len(sponsor['usage']) == len(concurro['responses']) == 2
    assert [item['stream'] for item in provider['requests']] == [1, 3]
    assert len({item['body_sha256'] for item in provider['requests']}) == 1
    sponsor_helpers = helper_metrics(directory, 'sponsor')
    concurro_helpers = helper_metrics(directory, 'concurro')
    assert sponsor_helpers['proof_count'] == concurro_helpers['proof_count'] == sponsor['request_proof_records']
    shaper = json.loads((directory / 'shaper-stats.json').read_text())
    name = directory.name
    worker = 'python' if '-python-' in name else 'rust' if '-rust-' in name else None
    assert worker and summary['profile'] in ('fast', 'home', 'constrained')
    return {'output': str(directory), 'profile': summary['profile'], 'worker': worker,
            'turns': client['turns'], 'bootstrap_count': 1,
            'proof_records': sponsor['request_proof_records'],
            'directional_bytes': shaper, 'sponsor_helpers': sponsor_helpers,
            'concurro_helpers': concurro_helpers, 'resources': resource_peak(directory),
            'request_sha256': provider['requests'][0]['body_sha256'],
            'provider_response_ms': [round(item['final_event_ms'] - item['first_event_ms'], 1)
                                     for item in provider['requests']]}


def main():
    """Write per-run checks and min/median/max repeat spread by profile and worker."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('runs', nargs='+', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    runs = [project(path) for path in args.runs]
    groups = {}
    for run in runs:
        groups.setdefault((run['profile'], run['worker']), []).append(run)
    spread = {}
    for (profile, worker), rows in groups.items():
        metrics = {}
        for phase_index, phase in enumerate(('cold', 'warm')):
            for field in ('first_body_ms', 'complete_ms'):
                values = [row['turns'][phase_index][field] for row in rows]
                metrics[f'{phase}_{field}'] = {'min': min(values),
                    'median': statistics.median(values), 'max': max(values)}
        spread[f'{profile}_{worker}'] = {'n': len(rows), 'metrics': metrics}
    output = {'runs': runs, 'spread': spread}
    args.output.write_text(json.dumps(output, indent=2) + '\n')
    print(json.dumps({'runs': len(runs), 'groups': sorted(spread)}))


if __name__ == '__main__':
    main()
