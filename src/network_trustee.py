"""Offline custodian. No network listener and no single-ballot decrypt API."""
import os
from pathlib import Path
from time import perf_counter
from phe import paillier
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from common import VoteError, read_json, write_json, unb64, digest, now
from crypto_service import open_secret, public_key
from network_protocol import verify_bundle, bundle_id, sign_object, verify_result


def decrypt_bundle(root, bundle, password):
    root = Path(root)
    election = read_json(root/'election.json')
    aggregate = verify_bundle(election, bundle)
    lock_path = root/'approval.lock'
    try:
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise VoteError('保管端正在批准结果；若进程异常退出，请核对批准记录后移除遗留锁') from exc
    try:
        secret = open_secret(read_json(root/'trustee.vault'), password, election['config']['election_id'])
        previous = root/'approved-result.json'
        if previous.exists():
            envelope = read_json(previous)
            verify_result(election, envelope)
            if envelope['payload']['bundle_sha256'] != bundle_id(bundle):
                raise VoteError('本轮已批准其他完整汇总，拒绝再次解密不同集合')
            return envelope
        pub = public_key(election['config'])
        priv = paillier.PaillierPrivateKey(pub, int(secret['p']), int(secret['q']))
        started = perf_counter()
        counts = [priv.raw_decrypt(int(c)) for c in aggregate['ciphertexts']]
        elapsed = (perf_counter() - started)*1000
        if any(not 0 <= x <= aggregate['accepted'] for x in counts) or sum(counts) != aggregate['accepted']:
            raise VoteError('总票数约束不成立，拒绝发布')
        signer = Ed25519PrivateKey.from_private_bytes(unb64(secret['result_signer']))
        envelope = sign_object({'version': 1, 'election_sha256': digest(election),
            'election_id': election['config']['election_id'], 'manifest_sha256': aggregate['manifest_sha256'],
            'bundle_sha256': bundle_id(bundle), 'counts': counts, 'accepted': aggregate['accepted'],
            'created_at': now(), 'decrypt_ms': elapsed}, signer)
        verify_result(election, envelope, bundle)
        write_json(previous, envelope)
        return envelope
    finally:
        os.close(lock_fd)
        lock_path.unlink()
