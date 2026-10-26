"""Executable task-sheet challenges. Uses only new, temporary synthetic elections."""
import copy
import csv
import hashlib
import platform
import random
import secrets
import statistics
import sys
import tempfile
import threading
from collections import Counter
from contextlib import contextmanager
from importlib.metadata import version
from pathlib import Path
from time import perf_counter

from phe import paillier
from audit_service import require_fields, sign_manifest
from common import VoteError, digest, now, read_json, write_json
from crypto_service import encrypt_ballot, generate_keys, public_key
from network_client import NetworkClient
from network_protocol import aggregate_records
from network_server import make_server
from network_setup import initialize_network
from network_trustee import decrypt_bundle

PASSWORD = 'Synthetic-Challenge-Only-2026!'


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def validate_case(case):
    require_fields(case, ('name', 'options', 'voters', 'choices'), '现场测试案例')
    if (not isinstance(case['name'], str) or not 1 <= len(case['name']) <= 80
            or type(case['voters']) is not int or not 1 <= case['voters'] <= 10000
            or not isinstance(case['options'], list) or not 2 <= len(case['options']) <= 8
            or any(not isinstance(x, str) or not 1 <= len(x.strip()) <= 24 for x in case['options'])
            or len({x.strip() for x in case['options']}) != len(case['options'])
            or not isinstance(case['choices'], list) or len(case['choices']) > case['voters']
            or any(type(x) is not int or not 0 <= x < len(case['options']) for x in case['choices'])):
        raise VoteError('现场案例的名称、选项、人数或选择索引不合法')
    return case


@contextmanager
def round_server(path, options, voters):
    initialize_network(path, '课程随机验证', options, voters, PASSWORD)
    server = make_server(path / 'server', '127.0.0.1', 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        def client(identity):
            ticket = 'admin.ticket.json' if identity == 'admin' else f'voters/{identity}.ticket.json'
            return NetworkClient('127.0.0.1', server.server_port, read_json(path / 'organizer' / ticket))
        yield server, client
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def network_round(path, case):
    """Real TLS, full verification and persistence; independent clients in one process."""
    validate_case(case)
    counts = Counter(case['choices'])  # independent plaintext oracle, never sent to server
    expected = [counts[i] for i in range(len(case['options']))]
    with round_server(path, case['options'], case['voters']) as (_, make_client):
        admin = make_client('admin')
        admin.connect()
        timings = []
        started = perf_counter()
        for i, choice in enumerate(case['choices'], 1):
            client = make_client(f'V{i:04d}')
            client.connect()
            client.vote(choice)
            timings.append(client.last_vote_metrics)
        cast_wall_ms = (perf_counter() - started) * 1000
        admin.close()
        started = perf_counter()
        bundle = admin.export()
        export_ms = (perf_counter() - started) * 1000
        started = perf_counter()
        result = decrypt_bundle(path / 'trustee', bundle, PASSWORD)
        trustee_ms = (perf_counter() - started) * 1000
        require(result['payload']['counts'] == expected, '解密总票与独立纸面预期不一致')
        admin.publish(result)
        require(admin.status()['result'] == result, '发布后的结果不一致')
        receipt = make_client('V0001')
        require((receipt.connect()['me']['receipt'] is not None) == bool(case['choices']), '回执存在性不一致')
        require(not list((path / 'server').glob('*.vault')), '服务器出现私钥保管库')
        return {'name': case['name'], 'eligible': case['voters'], 'accepted': len(case['choices']),
                'options': case['options'], 'input_sha256': digest(case), 'expected': expected,
                'actual': result['payload']['counts'], 'encrypt_ms': sum(t['encrypt_ms'] for t in timings),
                'submit_roundtrip_ms': sum(t['submit_roundtrip_ms'] for t in timings),
                'cast_wall_ms': cast_wall_ms, 'export_wall_ms': export_ms,
                'aggregate_ms': bundle['aggregation_ms'], 'decrypt_ms': result['payload']['decrypt_ms'],
                'trustee_wall_ms': trustee_ms, 'client_timings': timings}


def run_challenges(output, seed=None, random_rounds=7, max_voters=30,
                   primitive_sizes=(10, 100, 1000), network_sizes=(10, 100), repeats=3, fixture=None):
    if (type(random_rounds) is not int or not 0 <= random_rounds <= 100
            or type(max_voters) is not int or not 1 <= max_voters <= 10000
            or type(repeats) is not int or not 1 <= repeats <= 10
            or any(type(n) is not int or not 1 <= n <= 10000 for n in (*primitive_sizes, *network_sizes))):
        raise VoteError('复测轮数、人数或性能规模不合法')
    if seed is not None and (type(seed) is not int or not 0 <= seed < 2**64):
        raise VoteError('种子必须是0至2^64-1之间的整数')
    supplied = []
    if fixture is not None:
        value = read_json(fixture)
        require_fields(value, ('cases',), '私有测试数据')
        if not isinstance(value['cases'], list) or not 1 <= len(value['cases']) <= 100:
            raise VoteError('私有测试数据需要1至100个案例')
        supplied = [validate_case(case) for case in value['cases']]
    output = Path(output)
    if output.exists() and any(output.iterdir()):
        raise VoteError('测试输出目录必须为空，避免覆盖已有证据')
    output.mkdir(parents=True, exist_ok=True)
    seed = secrets.randbits(64) if seed is None else seed
    rng = random.Random(seed)  # fixture choices only; never seed encryption randomness
    report = {'created_at': now(), 'seed': seed, 'key_bits': 2048,
              'environment': {'python': platform.python_version(), 'os': platform.platform(),
                              'dependencies': {name: version(name) for name in ('phe', 'gmpy2', 'cryptography')}},
              'mode': 'packaged' if getattr(sys, 'frozen', False) else 'source',
              'scope': 'Synthetic data; real loopback TLS; clients in one process; not physical-LAN or oral-exam certification',
              'configuration': {'random_rounds': random_rounds, 'max_voters': max_voters,
                                'primitive_sizes': list(primitive_sizes), 'network_sizes': list(network_sizes),
                                'repeats': repeats, 'private_fixture_sha256': digest(supplied) if supplied else None},
              'checks': [], 'primitive_performance': [], 'network_performance': []}
    if getattr(sys, 'frozen', False):
        report['executable_sha256'] = hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
    else:
        report['source_files_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                        for p in sorted(Path(__file__).parent.glob('*.py'))}

    def checkpoint():
        report['completed_checks'] = len(report['checks'])
        report['failed_checks'] = sum(not c['passed'] for c in report['checks'])
        write_json(output / 'challenges.json', report)

    def check(name, category, fn, limitation=False):
        started = perf_counter()
        try:
            detail = fn()
            entry = {'name': name, 'category': category, 'passed': True, 'detail': detail}
        except Exception as exc:
            entry = {'name': name, 'category': category, 'passed': False,
                     'error_type': type(exc).__name__, 'error': str(exc)}
        entry.update(kind='limitation_demonstration' if limitation else 'requirement',
                     wall_ms=(perf_counter() - started) * 1000)
        report['checks'].append(entry)
        checkpoint()
        print(f'{"PASS" if entry["passed"] else "FAIL"} {name}', flush=True)

    with tempfile.TemporaryDirectory(prefix='mipiao-challenges-') as temp:
        root = Path(temp)
        pub, _, secret = generate_keys(2048)
        priv = paillier.PaillierPrivateKey(pub, int(secret['p']), int(secret['q']))

        def homomorphic():
            examples = []
            for _ in range(32):
                a, b, k = rng.randrange(101), rng.randrange(101), rng.randrange(11)
                ca, cb = pub.raw_encrypt(a), pub.raw_encrypt(b)
                total = priv.raw_decrypt(ca * cb % pub.nsquare)
                scaled = priv.raw_decrypt(pow(ca, k, pub.nsquare))
                rerandomized = ca * pub.raw_encrypt(0) % pub.nsquare
                require(total == a + b and scaled == a * k, '同态运算不符合预期')
                require(rerandomized != ca and priv.raw_decrypt(rerandomized) == a, '重新随机化失败')
                examples.append({'a': a, 'b': b, 'k': k, 'sum': total, 'scaled': scaled})
            require(priv.raw_decrypt(pub.raw_encrypt(pub.n - 1) * pub.raw_encrypt(1) % pub.nsquare) == 0,
                    '模n回绕边界不符合预期')
            ciphertexts = [pub.raw_encrypt(1) for _ in range(32)]
            require(len(set(ciphertexts)) == 32 and all(priv.raw_decrypt(c) == 1 for c in ciphertexts),
                    '相同明文的随机化加密失败')
            return {'examples': examples, 'repeated_plaintext_unique_ciphertexts': 32,
                    'wraparound': '(n-1)+1 mod n = 0', 'note': 'nonce is metadata; r is fresh cryptographic randomness'}
        check('随机同态加法/数乘/重新随机化/模n回绕', 'homomorphism', homomorphic)

        cases = [
            {'name': '空票箱', 'options': ['甲', '乙'], 'voters': 4, 'choices': []},
            {'name': '单人隐私边界', 'options': ['同意', '反对', '弃权'], 'voters': 1, 'choices': [2]},
            {'name': '八选项平票', 'options': [f'方案{i}' for i in range(1, 9)], 'voters': 16, 'choices': list(range(8)) * 2},
            {'name': '全票同一选项', 'options': ['甲', '乙'], 'voters': 12, 'choices': [1] * 12},
        ]
        for i in range(random_rounds):
            option_count = 2 + i % 7
            voters = rng.randint(1, max_voters)
            accepted = rng.randint(0, voters)
            cases.append({'name': f'随机轮次{i + 1}', 'options': [f'随机{rng.randrange(1000)}方案{j}' for j in range(option_count)],
                          'voters': voters, 'choices': [rng.randrange(option_count) for _ in range(accepted)]})
        cases.extend(supplied)
        for i, case in enumerate(cases):
            check(case['name'], 'random_and_boundary', lambda i=i, case=case: network_round(root / f'case-{i}', case))

        def max_roster():
            path = root / 'roster-max'
            with round_server(path, ['甲', '乙'], 10000) as (_, make_client):
                voter = make_client('V10000'); voter.connect(); voter.vote(1)
                admin = make_client('admin'); admin.connect(); admin.close()
                result = decrypt_bundle(path / 'trustee', admin.export(), PASSWORD)
                require(result['payload']['counts'] == [0, 1], '最大名单ID投票失败')
                return {'eligible': 10000, 'actual_cast': 1, 'last_id': 'V10000', 'counts': [0, 1],
                        'note': '10,000 credentials, not a 10,000-vote throughput measurement'}
        check('10000人名单末尾ID', 'boundary', max_roster)

        def malicious_limit():
            path = root / 'non-one-hot'
            with round_server(path, ['甲', '乙'], 2) as (_, make_client):
                for i, vector in enumerate(([2, 0], [0, 0]), 1):
                    client = make_client(f'V{i:04d}'); client.connect()
                    ballot = encrypt_ballot(client.election['config'], f'V{i:04d}', 0)
                    pk = public_key(client.election['config'])
                    ballot['ciphertexts'] = [str(pk.raw_encrypt(x)) for x in vector]
                    client.request('POST', '/api/ballots', {'ballot': ballot})
                admin = make_client('admin'); admin.connect(); admin.close()
                result = decrypt_bundle(path / 'trustee', admin.export(), PASSWORD)
                require(result['payload']['counts'] == [2, 0], '局限复现实验出现不同结果')
                return {'vectors': [[2, 0], [0, 0]], 'counts': [2, 0],
                        'limitation': '总和校验不能证明每张选票独热；需要独热零知识证明，当前未实现'}
        check('恶意非独热选票可互相抵消', 'security_limit', malicious_limit, True)

        def resign_limit():
            path = root / 'resigned-subset'
            with round_server(path, ['甲', '乙'], 2) as (server, make_client):
                for i in (1, 2):
                    client = make_client(f'V{i:04d}'); client.connect(); client.vote(i - 1)
                admin = make_client('admin'); admin.connect(); admin.close()
                forged = copy.deepcopy(admin.export())
                forged['ballots'].pop(); forged['manifest']['payload']['entries'].pop()
                forged['manifest'] = sign_manifest(forged['manifest']['payload'], server.store.signer)
                forged['aggregate'], forged['aggregation_ms'] = aggregate_records(
                    forged['election'], forged['manifest'], forged['ballots'])
                result = decrypt_bundle(path / 'trustee', forged, PASSWORD)
                require(result['payload']['counts'] == [1, 0], '恶意服务器首次重签集合实验出现不同结果')
                return {'actual_cast': 2, 'signed_subset_accepted': 1,
                        'limitation': '持登记签名密钥的恶意服务器可首次重签删票集合；需要独立回执见证或外部日志'}
        check('恶意服务器首次重签删票集合', 'security_limit', resign_limit, True)

        for size in primitive_sizes:
            for repeat in range(repeats):
                def primitives(size=size, repeat=repeat):
                    choices = [rng.randrange(3) for _ in range(size)]
                    start = perf_counter()
                    ballots = [[pub.raw_encrypt(int(j == choice)) for j in range(3)] for choice in choices]
                    enc_ms = (perf_counter() - start) * 1000
                    start = perf_counter(); aggregate = [1, 1, 1]
                    for ballot in ballots:
                        aggregate = [a * b % pub.nsquare for a, b in zip(aggregate, ballot)]
                    agg_ms = (perf_counter() - start) * 1000
                    start = perf_counter(); counts = [priv.raw_decrypt(c) for c in aggregate]
                    dec_ms = (perf_counter() - start) * 1000
                    require(counts == [choices.count(j) for j in range(3)], '性能实验结果不正确')
                    row = {'voters': size, 'options': 3, 'repeat': repeat + 1, 'counts': counts,
                           'encrypt_ms': enc_ms, 'aggregate_ms': agg_ms, 'decrypt_ms': dec_ms}
                    report['primitive_performance'].append(row)
                    return row
                check(f'纯算法{size}票第{repeat + 1}次', 'performance', primitives)
        for size in network_sizes:
            for repeat in range(repeats):
                def network(size=size, repeat=repeat):
                    case = {'name': f'联网性能{size}-{repeat + 1}', 'options': ['同意', '反对', '弃权'],
                            'voters': size, 'choices': [rng.randrange(3) for _ in range(size)]}
                    row = network_round(root / f'perf-{size}-{repeat}', case)
                    row.update(voters=size, repeat=repeat + 1)
                    report['network_performance'].append(row)
                    return {k: v for k, v in row.items() if k != 'client_timings'}
                check(f'真实TLS{size}票第{repeat + 1}次', 'performance', network)
    report['finished_at'] = now()
    report['passed'] = report['failed_checks'] == 0
    checkpoint()
    with (output / 'performance.csv').open('w', encoding='utf-8-sig', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['scope', 'voters', 'repeats', 'encrypt_mean_ms', 'aggregate_mean_ms', 'decrypt_mean_ms',
                         'cast_wall_mean_ms', 'cast_wall_min_ms', 'cast_wall_max_ms'])
        for scope, key in [('primitive', 'primitive_performance'), ('TLS_sequential', 'network_performance')]:
            rows = report[key]
            for size in sorted({r['voters'] for r in rows}):
                same = [r for r in rows if r['voters'] == size]
                writer.writerow([scope, size, len(same), *(statistics.mean(r[k] for r in same)
                    for k in ('encrypt_ms', 'aggregate_ms', 'decrypt_ms')),
                    *([statistics.mean(r['cast_wall_ms'] for r in same), min(r['cast_wall_ms'] for r in same),
                       max(r['cast_wall_ms'] for r in same)] if scope == 'TLS_sequential' else ['', '', ''])])
    return report
