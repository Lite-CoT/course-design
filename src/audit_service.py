"""Member C: manifest signatures, ID validation, close state and audit.

Signatures detect changes relative to the trusted public configuration.
They do not prove encrypted one-hot validity or prevent complete rollback.
"""
import math
import re
from pathlib import Path
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from common import VoteError, canonical, b64, unb64, digest, read_json


def require_fields(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise VoteError(label + '字段不正确')


def validate_config(config):
    require_fields(config, ('version', 'election_id', 'title', 'options', 'roster',
                           'n', 'key_bits', 'created_at', 'audit_public_key'), '配置')
    if type(config['version']) is not int or config['version'] != 1:
        raise VoteError('配置版本不正确')
    if not isinstance(config['election_id'], str) or not re.fullmatch(r'[0-9a-f]{32}', config['election_id']):
        raise VoteError('配置投票轮次格式错误')
    if not isinstance(config['title'], str) or not 1 <= len(config['title'].strip()) <= 80:
        raise VoteError('配置标题格式错误')
    options, roster = config['options'], config['roster']
    if (not isinstance(options, list) or not 2 <= len(options) <= 8
            or any(not isinstance(x, str) or not 1 <= len(x.strip()) <= 24 for x in options)
            or len(set(options)) != len(options)):
        raise VoteError('配置选项格式错误')
    if (not isinstance(roster, list) or not 1 <= len(roster) <= 10000
            or any(not isinstance(x, str) or not 1 <= len(x) <= 80 for x in roster)
            or len(set(roster)) != len(roster)):
        raise VoteError('配置授权名单格式错误')
    n, bits = config['n'], config['key_bits']
    if (type(bits) is not int or bits not in (1024, 2048, 3072)
            or not isinstance(n, str) or not re.fullmatch(r'[1-9][0-9]{1,924}', n)):
        raise VoteError('配置公钥参数错误')
    if int(n).bit_length() != bits or int(n) % 2 == 0:
        raise VoteError('配置公钥长度或模数错误')


def sign_manifest(payload, signer):
    return {'payload': payload, 'signature': b64(signer.sign(canonical(payload)))}


def verify_manifest(config, manifest):
    require_fields(manifest, ('payload', 'signature'), '清单')
    require_fields(manifest['payload'], ('election_id', 'config_sha256', 'status',
                                         'entries', 'updated_at'), '清单载荷')
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
    require_fields(ballot, expected, '选票')
    if type(ballot['version']) is not int or ballot['version'] != 1:
        raise VoteError('选票字段或版本不正确')
    if ballot['election_id'] != config['election_id']:
        raise VoteError('选票属于其他投票轮次')
    if ballot['voter_id'] not in config['roster']:
        raise VoteError('投票者ID不在授权名单内')
    if ballot['ballot_type'] != 'single_choice':
        raise VoteError('不支持的票型')
    if not isinstance(ballot['nonce'], str) or not re.fullmatch(r'[0-9a-fA-F]{32}', ballot['nonce']):
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
    validate_config(config)
    payload = verify_manifest(config, read_json(root / 'public' / 'manifest.json'))
    entries = payload['entries']
    if not isinstance(entries, list) or len(entries) > len(config['roster']):
        raise VoteError('清单记录数量异常')
    expected, seen, nonces, ballots = set(), set(), set(), []
    for entry in entries:
        require_fields(entry, ('voter_id', 'file', 'sha256'), '清单选票记录')
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
    ballot_dir = root / 'public' / 'ballots'
    if not ballot_dir.is_dir():
        raise VoteError('选票目录不存在')
    actual = {p.name for p in ballot_dir.iterdir()}
    if actual != expected:
        raise VoteError('发现未登记选票或额外文件')
    return config, payload, ballots
