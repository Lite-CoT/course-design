"""Repeatable synthetic experiments; outputs are actual measured results."""
import copy
import csv
import json
import platform
import random
import shutil
import statistics
import tempfile
import hashlib
from importlib.metadata import version, PackageNotFoundError
from pathlib import Path
from time import perf_counter
from common import VoteError, now, read_json, write_json, digest
from crypto_service import encrypt_ballot, public_key, open_secret
from election_service import create_election, Election
from audit_service import audit
from tally_service import aggregate, decrypt_tally

PASSWORD = 'LabOnly-2026!'


def run_experiments(output, full=True):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    cases = []
    def check(name, owner, fn, expected_error=False):
        start = perf_counter()
        try:
            value = fn()
            if expected_error:
                raise AssertionError('预期拒绝但操作成功')
            cases.append({'name': name, 'owner': owner, 'passed': True, 'detail': str(value or '符合预期'), 'ms': (perf_counter()-start)*1000})
        except Exception as exc:
            # A programming error such as KeyError must never count as a safe rejection.
            passed = expected_error and isinstance(exc, VoteError)
            cases.append({'name': name, 'owner': owner, 'passed': passed, 'detail': str(exc), 'ms': (perf_counter()-start)*1000})

    with tempfile.TemporaryDirectory(prefix='paillier-lab-') as temp:
        root = Path(temp) / 'baseline'
        e = create_election(root, '基准实验', ['同意', '反对', '弃权'], 12, PASSWORD)
        pub = public_key(e.config)
        secret = open_secret(read_json(root/'private/trustee.vault'), PASSWORD, e.config['election_id'])
        from phe import paillier
        priv = paillier.PaillierPrivateKey(pub, int(secret['p']), int(secret['q']))
        def homomorphic():
            assert priv.raw_decrypt(pub.raw_encrypt(2)*pub.raw_encrypt(3) % pub.nsquare) == 5
            return 'E(2) × E(3) mod n² 解密为5'
        check('加法同态性质', 'A/B', homomorphic)
        def randomized():
            c1, c2 = pub.raw_encrypt(1), pub.raw_encrypt(1)
            assert c1 != c2 and priv.raw_decrypt(c1) == priv.raw_decrypt(c2) == 1
            return '相同明文两次加密得到不同密文'
        check('随机化加密', 'A', randomized)
        check('越界选项拒绝', 'A', lambda: encrypt_ballot(e.config, 'V0001', 3), True)
        check('名单外ID拒绝', 'C', lambda: e.cast('UNKNOWN', 0), True)
        choices = [0, 1, 0, 2, 0, 1]
        for i, c in enumerate(choices, 1):
            e.cast(f'V{i:04d}', c)
        check('重复投票拒绝', 'C', lambda: e.cast('V0001', 1), True)
        check('未关闭禁止汇总', 'B', lambda: aggregate(root), True)
        check('错误口令拒绝', 'A', lambda: open_secret(read_json(root/'private/trustee.vault'), 'bad-password', e.config['election_id']), True)
        def modified_ballot(field, value):
            b = encrypt_ballot(e.config, 'V0007', 0)
            b[field] = value
            return e.accept(b)
        check('跨轮次选票拒绝', 'C', lambda: modified_ballot('election_id','other'), True)
        check('错误维度拒绝', 'A/C', lambda: modified_ballot('ciphertexts',['1']), True)
        check('非法密文空间拒绝', 'A/C', lambda: modified_ballot('ciphertexts',['0','1','1']), True)
        e.close()
        check('关闭后禁止新票', 'C', lambda: e.cast('V0007',0), True)
        req = aggregate(root)
        result = decrypt_tally(root, PASSWORD, req)
        def known_result():
            assert result['counts'] == [3,2,1]
            return '6张票得到 [3, 2, 1]'
        check('已知票数准确性', 'B', known_result)
        def no_oracle():
            changed = copy.deepcopy(req)
            changed['ciphertexts'] = read_json(next((root/'public/ballots').glob('*.json')))['ciphertexts']
            return decrypt_tally(root, PASSWORD, changed)
        check('拒绝单票解密请求', 'B', no_oracle, True)
        def reload():
            loaded = Election(root)
            assert loaded.signer is None
            assert len(loaded.refresh()) == 6
            return '重启后只读载入成功'
        check('重启加载', 'C', reload)
        def no_plaintext():
            for p in (root/'public/ballots').glob('*.json'):
                b = read_json(p)
                assert not {'choice','plaintext','p','q','private_key'} & b.keys()
            return '公开选票不含明文选择或私钥字段'
        check('公开选票字段检查', 'A/C', no_plaintext)
        def public_export():
            import zipfile
            p = Path(temp)/'public.zip'
            e.export_public(p)
            with zipfile.ZipFile(p) as z:
                assert all(x.startswith('public/') for x in z.namelist())
                assert not any('vault' in x or 'private' in x for x in z.namelist())
                z.extractall(Path(temp)/'collector')
            assert aggregate(Path(temp)/'collector')['ciphertexts'] == req['ciphertexts']
            return '公开包无私钥；独立计票目录可完成同态汇总'
        check('无私钥计票端', 'B/C', public_export)

        def corrupt(kind):
            target = Path(temp)/kind
            shutil.copytree(root, target)
            ballotpath = next((target/'public/ballots').glob('*.json'))
            if kind == 'delete':
                ballotpath.unlink()
            elif kind == 'change':
                ballot = read_json(ballotpath)
                ballot['ciphertexts'][0] = str((int(ballot['ciphertexts'][0])*pub.g) % pub.nsquare)
                write_json(ballotpath, ballot)
            elif kind == 'extra':
                shutil.copyfile(ballotpath, ballotpath.parent/'extra.json')
            elif kind == 'manifest':
                m = read_json(target/'public/manifest.json')
                m['payload']['entries'].pop()
                write_json(target/'public/manifest.json',m)
            elif kind == 'config':
                conf = read_json(target/'public/config.json')
                conf['options'][0] = '替换选项'
                write_json(target/'public/config.json',conf)
            return audit(target)
        for kind, label in [('delete','删除选票检测'),('change','篡改选票检测'),('extra','额外选票检测'),('manifest','清单篡改检测'),('config','配置篡改检测')]:
            check(label, 'C', lambda kind=kind: corrupt(kind), True)
        empty = create_election(Path(temp)/'empty', '零票', ['甲','乙'], 1, PASSWORD)
        empty.close()
        def empty_tally():
            r = decrypt_tally(empty.root, PASSWORD, aggregate(empty.root))
            assert r['counts'] == [0,0]
            return '零票正常输出 [0,0]'
        check('零票边界', 'B', empty_tally)
        dynamic = create_election(Path(temp)/'dynamic', '四选项', ['甲','乙','丙','丁'], 4, PASSWORD)
        for i in range(4):
            dynamic.cast(f'V{i+1:04d}',i)
        dynamic.close()
        def dynamic_tally():
            r = decrypt_tally(dynamic.root, PASSWORD, aggregate(dynamic.root))
            assert r['counts'] == [1,1,1,1]
            return '动态4选项得到 [1,1,1,1]'
        check('动态选项数量', 'A/B', dynamic_tally)

        for option_count in (2, 8):
            def option_boundary(option_count=option_count):
                t = create_election(Path(temp)/f'options-{option_count}', '选项边界',
                                    [f'选项{i+1}' for i in range(option_count)], option_count, PASSWORD)
                for i in range(option_count):
                    t.cast(f'V{i+1:04d}', i)
                t.close()
                counts = decrypt_tally(t.root, PASSWORD, aggregate(t.root))['counts']
                assert counts == [1] * option_count
                return f'{option_count}个选项各一票，结果 {counts}'
            check(f'{option_count}选项边界', 'A/B', option_boundary)

        def single_voter_limit():
            t = create_election(Path(temp)/'single', '单人隐私边界', ['甲','乙'], 1, PASSWORD)
            t.cast('V0001', 1)
            t.close()
            counts = decrypt_tally(t.root, PASSWORD, aggregate(t.root))['counts']
            assert counts == [0, 1]
            return '局限确认：一人投票的总票 [0,1] 暴露该人的选择'
        check('单人投票隐私局限', 'B', single_voter_limit)

        def balanced_invalid_limit():
            t = create_election(Path(temp)/'balanced', '非独热组合边界', ['甲','乙'], 2, PASSWORD)
            pk = public_key(t.config)
            for i, vector in enumerate(([2, 0], [0, 0]), 1):
                ballot = encrypt_ballot(t.config, f'V{i:04d}', 0)
                ballot['ciphertexts'] = [str(pk.raw_encrypt(x)) for x in vector]
                t.accept(ballot)
            t.close()
            counts = decrypt_tally(t.root, PASSWORD, aggregate(t.root))['counts']
            assert counts == [2, 0]
            return '局限确认：非独热选票 [2,0] 与 [0,0] 的总和仍满足两票约束'
        check('非法选票组合局限', 'A/B', balanced_invalid_limit)

        # Explicit limitation experiment: a structurally valid but non-one-hot vote.
        invalid = create_election(Path(temp)/'invalid', '恶意客户端边界', ['甲','乙'], 1, PASSWORD)
        b = encrypt_ballot(invalid.config, 'V0001', 0)
        ip = public_key(invalid.config)
        b['ciphertexts'] = [str(ip.raw_encrypt(2)), str(ip.raw_encrypt(0))]
        invalid.accept(b)
        invalid.close()
        check('非法选票总和约束', 'B', lambda: decrypt_tally(invalid.root,PASSWORD,aggregate(invalid.root)),True)

        def rollback_limit():
            t = create_election(Path(temp)/'rollback', '回滚局限', ['甲','乙'],2,PASSWORD)
            old = read_json(t.root/'public/manifest.json')
            t.cast('V0001',0)
            for p in (t.root/'public/ballots').glob('*.json'):
                p.unlink()
            write_json(t.root/'public/manifest.json',old)
            _, restored, _ = audit(t.root)
            assert len(restored['entries']) == 0
            return '局限确认：整套数据回滚到旧有效签名状态无法被本地审计识别'
        check('完整回滚局限验证', 'C', rollback_limit)
        write_json(output/'baseline_result.json',result)

        # Performance isolates primitives; end-to-end filesystem/UI cost is not included.
        performance = []
        for size in ([10,100,1000] if full else [10]):
            runs = []
            for repeat in range(3):
                rng = random.Random(20261026 + repeat)
                selected = [rng.randrange(3) for _ in range(size)]
                start = perf_counter()
                vectors = [[pub.raw_encrypt(int(j == c)) for j in range(3)] for c in selected]
                enc_ms = (perf_counter()-start)*1000
                start = perf_counter()
                acc = [1,1,1]
                for vector in vectors:
                    acc = [a*c % pub.nsquare for a,c in zip(acc, vector)]
                agg_ms = (perf_counter()-start)*1000
                start = perf_counter()
                counts = [priv.raw_decrypt(c) for c in acc]
                dec_ms = (perf_counter()-start)*1000
                assert counts == [selected.count(i) for i in range(3)]
                runs.append({'repeat':repeat+1,'encrypt_ms':enc_ms,'aggregate_ms':agg_ms,'decrypt_ms':dec_ms,'counts':counts})
            performance.append({'voters':size,'options':3,'runs':runs,
                **{k:statistics.mean(r[k] for r in runs) for k in ('encrypt_ms','aggregate_ms','decrypt_ms')}})
    dependencies = {}
    for name in ('phe', 'gmpy2', 'cryptography', 'PySide6-Essentials'):
        try:
            dependencies[name] = version(name)
        except PackageNotFoundError:
            dependencies[name] = 'not installed'
    source_hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in sorted(Path(__file__).parent.glob('*.py'))}
    report = {'created_at':now(),'run_mode':'full' if full else 'quick',
              'source_files_sha256':source_hashes,
              'environment':{'os':platform.platform(),'python':platform.python_version(),
              'processor':platform.processor(),'key_bits':2048,'dependencies':dependencies},
              'fixture':'synthetic / fixed seed 20261026+repeat; encryption randomness is not seeded',
              'cases':cases,'passed':sum(c['passed'] for c in cases),'total':len(cases),'performance':performance,
              'performance_scope':'Paillier primitives only; excludes IO, signing, KDF and GUI',
              'limitations':['No zero-knowledge proof of one-hot ballots','Full signed-state rollback not detected',
                             'Roster ID is not identity authentication','Single-machine roles are not a trust boundary',
                             'Single-writer classroom storage; no distributed transaction recovery']}
    write_json(output/'experiment_results.json',report)
    with (output/'performance.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.writer(f); w.writerow(['人数','选项','加密均值ms','汇总均值ms','解密均值ms'])
        for row in performance:
            w.writerow([row['voters'],3,row['encrypt_ms'],row['aggregate_ms'],row['decrypt_ms']])
    with (output/'test_cases.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.writer(f); w.writerow(['用例','责任模块','通过','实际结果','耗时ms'])
        for c in cases:
            w.writerow([c['name'],c['owner'],c['passed'],c['detail'],c['ms']])
    return report
