"""Member B: public homomorphic aggregation and closed-election trustee.

Only this module's trustee function reconstructs the Paillier private key.
The GUI calls it in a separate process and receives aggregate counts only.
"""
from pathlib import Path
from time import perf_counter
from phe import paillier
from common import VoteError, digest, read_json, now
from crypto_service import public_key, open_secret
from audit_service import audit


def aggregate(root):
    started = perf_counter()
    config, manifest, ballots = audit(root)
    audit_ms = (perf_counter()-started)*1000
    if manifest['status'] != 'closed':
        raise VoteError('请先关闭投票，避免通过重复查询推断单票')
    pub = public_key(config)
    started = perf_counter()
    totals = [1] * len(config['options'])
    for ballot in ballots:
        for i, c in enumerate(ballot['ciphertexts']):
            totals[i] = totals[i] * int(c) % pub.nsquare
    return {'election_id': config['election_id'], 'manifest_sha256': digest(manifest),
            'ciphertexts': [str(c) for c in totals], 'accepted': len(ballots),
            'audit_ms': audit_ms, 'aggregate_ms': (perf_counter()-started)*1000}


def decrypt_tally(root, password, request):
    # Independently recompute, rather than accepting an arbitrary ciphertext oracle.
    config, manifest, _ = audit(root)
    expected = aggregate(root)
    for key in ('election_id', 'manifest_sha256', 'ciphertexts', 'accepted'):
        if request.get(key) != expected[key]:
            raise VoteError('拒绝解密：请求不是当前完整投票的汇总')
    secret = open_secret(read_json(Path(root) / 'private' / 'trustee.vault'), password, config['election_id'])
    pub = public_key(config)
    priv = paillier.PaillierPrivateKey(pub, int(secret['p']), int(secret['q']))
    started = perf_counter()
    counts = [priv.raw_decrypt(int(c)) for c in request['ciphertexts']]
    decrypt_ms = (perf_counter()-started)*1000
    if any(x < 0 or x > request['accepted'] for x in counts) or sum(counts) != request['accepted']:
        raise VoteError('总票数约束不成立，可能存在非法加密选票')
    return {'election_id': config['election_id'], 'title': config['title'], 'options': config['options'],
            'counts': counts, 'accepted': request['accepted'], 'eligible': len(config['roster']),
            'manifest_sha256': request['manifest_sha256'], 'aggregate_ms': request['aggregate_ms'],
            'audit_ms': request['audit_ms'], 'decrypt_ms': decrypt_ms, 'created_at': now()}
