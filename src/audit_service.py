"""Member C: manifest signatures, ID validation, close state and audit.

Signatures detect changes relative to the trusted public configuration.
They do not prove encrypted one-hot validity or prevent complete rollback.
"""
import math
from pathlib import Path
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from common import VoteError, canonical, b64, unb64, digest, read_json


def sign_manifest(payload, signer):
    return {'payload': payload, 'signature': b64(signer.sign(canonical(payload)))}


def verify_manifest(config, manifest):
    try:
        Ed25519PublicKey.from_public_bytes(unb64(config['audit_public_key'])).verify(
            unb64(manifest['signature']), canonical(manifest['payload']))
    except (InvalidSignature, ValueError, KeyError, TypeError) as exc:
        raise VoteError('清单签名无效，配置或清单可能被修改') from exc
    payload = manifest['payload']
    if payload['config_sha256'] != digest(config) or payload['election_id'] != config['election_id']:
        raise VoteError('配置摘要或投票轮次不匹配')
    if payload['status'] not in ('open', 'closed'):
        raise VoteError('非法投票状态')
    return payload


def validate_ballot(config, ballot):
    expected = {'version', 'election_id', 'voter_id', 'ballot_type', 'timestamp', 'nonce', 'ciphertexts'}
    if set(ballot) != expected or ballot['version'] != 1:
        raise VoteError('选票字段或版本不正确')
    if ballot['election_id'] != config['election_id']:
        raise VoteError('选票属于其他投票轮次')
    if ballot['voter_id'] not in config['roster']:
        raise VoteError('投票者ID不在授权名单内')
    if ballot['ballot_type'] != 'single_choice':
        raise VoteError('不支持的票型')
    if not isinstance(ballot['nonce'], str) or len(ballot['nonce']) != 32:
        raise VoteError('选票随机标识格式错误')
    try:
        int(ballot['nonce'], 16)
        stamp = datetime.fromisoformat(ballot['timestamp'])
        if stamp.tzinfo is None:
            raise ValueError()
    except (ValueError, TypeError):
        raise VoteError('随机标识或时间戳格式错误')
    values = ballot['ciphertexts']
    if not isinstance(values, list) or len(values) != len(config['options']):
        raise VoteError('密文向量维度与选项数不一致')
    n = int(config['n'])
    for c in values:
        if not isinstance(c, str) or not c.isascii() or not c.isdecimal() or len(c) > len(str(n*n)):
            raise VoteError('密文编码错误')
        value = int(c)
        if not 0 < value < n*n or math.gcd(value, n) != 1:
            raise VoteError('密文不属于合法密文空间')


def audit(root):
    root = Path(root)
    config = read_json(root / 'public' / 'config.json')
    if not 2 <= len(config['options']) <= 8 or not 1 <= len(config['roster']) <= 10000:
        raise VoteError('配置规模超出支持范围')
    payload = verify_manifest(config, read_json(root / 'public' / 'manifest.json'))
    entries = payload['entries']
    if not isinstance(entries, list) or len(entries) > len(config['roster']):
        raise VoteError('清单记录数量异常')
    expected, seen, nonces, ballots = set(), set(), set(), []
    for entry in entries:
        voter = entry['voter_id']
        if voter not in config['roster'] or voter in seen:
            raise VoteError('清单出现非法ID或重复投票')
        filename = digest({'voter_id': voter}) + '.json'
        if entry['file'] != filename:
            raise VoteError('清单路径异常')
        path = root / 'public' / 'ballots' / filename
        if not path.is_file():
            raise VoteError('发现选票被删除：' + voter)
        ballot = read_json(path, 100000)
        if digest(ballot) != entry['sha256']:
            raise VoteError('发现选票被篡改：' + voter)
        validate_ballot(config, ballot)
        if ballot['voter_id'] != voter or ballot['nonce'] in nonces:
            raise VoteError('选票身份不一致或随机标识重复')
        seen.add(voter)
        nonces.add(ballot['nonce'])
        expected.add(filename)
        ballots.append(ballot)
    actual = {p.name for p in (root / 'public' / 'ballots').iterdir() if p.is_file()}
    if actual != expected:
        raise VoteError('发现未登记选票或额外文件')
    return config, payload, ballots
