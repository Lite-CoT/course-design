"""Public protocol verification shared by clients, server and offline trustee."""
import re
from datetime import datetime
from time import perf_counter
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from common import VoteError, canonical, digest, b64, unb64, decode_json
from audit_service import require_fields, validate_config, validate_ballot, verify_manifest


def parse_json(data):
    return decode_json(data)


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


def verify_receipt(election, envelope, voter, ballot_sha256=None):
    payload = verify_object(envelope, election['config']['audit_public_key'])
    require_fields(payload, ('election_id', 'voter_id', 'ballot_sha256', 'accepted_at'), '回执')
    if (payload['election_id'] != election['config']['election_id'] or payload['voter_id'] != voter
            or not isinstance(payload['ballot_sha256'], str)
            or not re.fullmatch('[0-9a-f]{64}', payload['ballot_sha256'])
            or (ballot_sha256 is not None and payload['ballot_sha256'] != ballot_sha256)):
        raise VoteError('回执身份、轮次或选票摘要不一致')
    try:
        if datetime.fromisoformat(payload['accepted_at']).tzinfo is None:
            raise ValueError()
    except (TypeError, ValueError) as exc:
        raise VoteError('回执接收时间格式错误') from exc
    return payload


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
    aggregate = bundle['aggregate']
    require_fields(aggregate, ('election_id', 'manifest_sha256', 'accepted', 'ciphertexts'), '密文汇总')
    if type(aggregate['accepted']) is not int:
        raise VoteError('汇总票数必须为整数')
    if type(bundle['aggregation_ms']) not in (int, float) or not 0 <= bundle['aggregation_ms'] < 1e12:
        raise VoteError('汇总计时格式错误')
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
