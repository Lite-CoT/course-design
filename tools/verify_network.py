"""Acceptance with a server process, six voter processes and an offline trustee process."""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from time import perf_counter
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from common import read_json, write_json


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--work', required=True, help='New isolated test directory, never commit its secrets')
    parser.add_argument('--evidence', required=True)
    parser.add_argument('--exe', help='Test a frozen executable instead of Python source')
    args = parser.parse_args()
    work = Path(args.work).resolve(); work.mkdir(parents=True, exist_ok=False)
    evidence = Path(args.evidence); evidence.mkdir(parents=True, exist_ok=True)
    command = [str(Path(args.exe).resolve())] if args.exe else [sys.executable, str(ROOT/'src/main.py')]
    env = dict(os.environ, PYTHONIOENCODING='utf-8')
    password = 'Synthetic-Acceptance-2026!'
    def stop_server(process):
        if process.poll() is None:
            # A PyInstaller one-file process has a child on Windows. Stopping
            # only its bootstrap parent would leave our test listener running.
            if os.name == 'nt':
                subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],
                               capture_output=True, timeout=20)
            else:
                process.terminate()
            process.wait(timeout=20)
        if process.stdout: process.stdout.close()
    def run(arguments, stdin=None, expected=0):
        started = perf_counter()
        completed = subprocess.run(command+arguments, input=stdin, text=True, encoding='utf-8',
                                   capture_output=True, timeout=90, env=env)
        if completed.returncode != expected:
            raise AssertionError(f'{arguments[0]} exit={completed.returncode}: {completed.stderr}')
        return json.loads(completed.stdout) if expected == 0 else completed.stderr, (perf_counter()-started)*1000
    initialized, init_ms = run(['init','--out',str(work/'round'),'--title','局域网多端验收',
                               '--options','同意,反对,弃权','--voters','8','--password-stdin'], password+'\n')
    server = subprocess.Popen(command+['serve','--data',str(work/'round/server'),'--host','127.0.0.1','--port','0'],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', env=env)
    try:
        line = server.stdout.readline()
        match = re.search(r'https://127.0.0.1:(\d+)', line)
        if not match: raise AssertionError('Server failed to start: '+line)
        port = match.group(1)
        def connection(identity):
            ticket = work/'round/organizer'/('admin.ticket.json' if identity=='admin' else f'voters/{identity}.ticket.json')
            return ['--host','127.0.0.1','--port',port,'--ticket',str(ticket)]
        choices = [0,1,0,2,0,1]
        def cast(item):
            index, choice = item
            value, elapsed = run(['cast',*connection(f'V{index+1:04d}'),'--choice',str(choice+1)])
            return {'voter_id': f'V{index+1:04d}', 'receipt': value['receipt'],
                    'client_metrics': value['client_metrics'], 'client_wall_ms': elapsed}
        started = perf_counter()
        with ThreadPoolExecutor(max_workers=6) as pool:
            votes = list(pool.map(cast, enumerate(choices)))
        concurrent_ms = (perf_counter()-started)*1000
        duplicate, _ = run(['cast',*connection('V0001'),'--choice','1'], expected=1)
        assert '重复' in duplicate
        run(['close',*connection('admin')])
        late, _ = run(['cast',*connection('V0007'),'--choice','1'], expected=1)
        assert '关闭' in late
        run(['export',*connection('admin'),'--out',str(work/'bundle.json')])
        result, trustee_wall_ms = run(['decrypt','--data',str(work/'round/trustee'),'--bundle',str(work/'bundle.json'),
                                      '--out',str(work/'result.json'),'--password-stdin'], password+'\n')
        assert result['payload']['counts'] == [3,2,1]
        run(['publish',*connection('admin'),'--result',str(work/'result.json')])
        published, _ = run(['status',*connection('V0008')])
        assert published['status']['result'] == result
        before_restart = published['status']
        stop_server(server)
        server = subprocess.Popen(command+['serve','--data',str(work/'round/server'),'--host','127.0.0.1','--port',port],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', env=env)
        assert f':{port}' in server.stdout.readline()
        after_restart, _ = run(['status',*connection('V0008')])
        assert after_restart['status'] == before_restart
        bundle = read_json(work/'bundle.json')
        files = [p.name for p in (work/'round/server').iterdir() if p.is_file()]
        assert not any(name.endswith('.vault') for name in files)
        record = {'created_at':datetime.now(timezone.utc).isoformat(),
            'transport':'HTTPS/TLS over 127.0.0.1, separate OS processes; not a claim of separate physical machines',
            'mode':'packaged' if args.exe else 'source','key_bits':2048,
            'client_processes':6,'synthetic_choices':choices,'expected_counts':[3,2,1],
            'actual_counts':result['payload']['counts'],'accepted':result['payload']['accepted'],
            'initialization_ms':init_ms,'concurrent_clients_wall_ms':concurrent_ms,
            'server_aggregation_ms':bundle['aggregation_ms'],'trustee_decrypt_ms':result['payload']['decrypt_ms'],
            'trustee_process_wall_ms':trustee_wall_ms,'duplicate_rejected':True,'closed_rejected':True,
            'result_verified_by_other_client':True,'restart_preserved_result':True,
            'server_files':files,'server_has_no_vault':True,
            'source_files_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT/'src').glob('*.py'))},
            'receipts':votes,'passed':True}
        if args.exe: record['executable_sha256']=hashlib.sha256(Path(args.exe).read_bytes()).hexdigest()
        write_json(evidence/'network-processes.json', record)
        write_json(evidence/'public-bundle.json', bundle)
        write_json(evidence/'signed-result.json', result)
        print(json.dumps({key:record[key] for key in ('mode','actual_counts','client_processes','passed')},ensure_ascii=False))
    finally:
        stop_server(server)


if __name__ == '__main__': main()
