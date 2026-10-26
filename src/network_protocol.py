"""Public protocol verification shared by clients, server and offline trustee."""
import json
from time import perf_counter
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from common import VoteError, canonical, digest, b64, unb64
from audit_service import require_fields, validate_config, validate_ballot, verify_manifest


def parse_json(data):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise VoteError('JSON包含重复字段')
            out[key] = value
        return out
    def constant(_):
        raise VoteError('JSON不允许非有限数值')
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise VoteError('JSON数据格式不正确') from exc


def sign_object(payload, signer):
    return {'payload': payload, 'signature': b64(signer.sign(canonical(payload)))}


def verify_object(envelope, public_key):
    require_fields(envelope, ('payload', 'signature'), '签名对象')
    try:
        Ed25519PublicKey.from_public_bytes(unb64(public_key)).verify(
            unb64(envelope['signature']), canonical(envelope['payload']))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise VoteError('签名验证失败') from exc
    return envelope['payload']


def validate_election(election):
    require_fields(election, ('protocol', 'config', 'result_public_key'), '联网配置')
    if type(election['protocol']) is not int or election['protocol'] != 1:
        raise VoteError('联网协议版本不正确')
    validate_config(election['config'])
    try:
        Ed25519PublicKey.from_public_bytes(unb64(election['result_public_key']))
        Ed25519PublicKey.from_public_bytes(unb64(election['config']['audit_public_key']))
    except (ValueError, TypeError) as exc:
        raise VoteError('配置签名公钥不正确') from exc


def audit_records(election, manifest, ballots):
    validate_election(election)
    config = election['config']
    payload = verify_manifest(config, manifest)
    entries = payload['entries']
    if (not isinstance(entries, list) or not isinstance(ballots, list)
            or len(entries) != len(ballots) or len(entries) > len(config['roster'])):
        raise VoteError('选票集合与清单不一致')
    seen, nonces = set(), set()
    for entry, ballot in zip(entries, ballots):
        require_fields(entry, ('voter_id', 'file', 'sha256'), '清单记录')
        validate_ballot(config, ballot)
        voter = ballot['voter_id']
        if not isinstance(voter, str) or voter in seen or ballot['nonce'].lower() in nonces:
            raise VoteError('发现重复ID或随机标识')
        if (entry['voter_id'] != voter or entry['file'] != digest({'voter_id': voter}) + '.json'
                or entry['sha256'] != digest(ballot)):
            raise VoteError('选票被修改或清单记录不一致')
        seen.add(voter)
        nonces.add(ballot['nonce'].lower())
    return payload


def aggregate_records(election, manifest, ballots):
    payload = audit_records(election, manifest, ballots)
    if payload['status'] != 'closed':
        raise VoteError('必须先关闭投票才能汇总')
    started = perf_counter()
    n = int(election['config']['n'])
    totals = [1] * len(election['config']['options'])
    for ballot in ballots:
        totals = [(value * int(c)) % (n*n) for value, c in zip(totals, ballot['ciphertexts'])]
    aggregate = {'election_id': election['config']['election_id'],
                 'manifest_sha256': digest(payload), 'accepted': len(ballots),
                 'ciphertexts': [str(value) for value in totals]}
    return aggregate, (perf_counter() - started) * 1000


def verify_bundle(election, bundle):
    require_fields(bundle, ('election', 'manifest', 'ballots', 'aggregate', 'aggregation_ms'), '汇总包')
    if bundle['election'] != election:
        raise VoteError('汇总包与独立保管的可信配置不一致')
    expected, _ = aggregate_records(election, bundle['manifest'], bundle['ballots'])
    if bundle['aggregate'] != expected:
        raise VoteError('汇总请求不等于完整选票集合的密文乘积')
    return expected


def bundle_id(bundle):
    # Measurement noise must not turn the same closed election into a new request.
    return digest({key: bundle[key] for key in ('election', 'manifest', 'aggregate')})


def verify_result(election, envelope, bundle=None):
    payload = verify_object(envelope, election['result_public_key'])
    require_fields(payload, ('version', 'election_sha256', 'election_id', 'manifest_sha256',
                            'bundle_sha256', 'counts', 'accepted', 'created_at', 'decrypt_ms'), '结果')
    if (type(payload['version']) is not int or payload['version'] != 1
            or payload['election_sha256'] != digest(election)
            or payload['election_id'] != election['config']['election_id']):
        raise VoteError('结果属于其他投票配置')
    counts, accepted = payload['counts'], payload['accepted']
    if (type(accepted) is not int or not 0 <= accepted <= len(election['config']['roster'])
            or not isinstance(counts, list) or len(counts) != len(election['config']['options'])
            or any(type(x) is not int or not 0 <= x <= accepted for x in counts)
            or sum(counts) != accepted):
        raise VoteError('结果票数约束不成立')
    if bundle is not None and (payload['bundle_sha256'] != bundle_id(bundle)
            or payload['manifest_sha256'] != bundle['aggregate']['manifest_sha256']
            or accepted != bundle['aggregate']['accepted']):
        raise VoteError('结果与服务器当前完整汇总不一致')
    return payload
