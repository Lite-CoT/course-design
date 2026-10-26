"""Member A: Paillier key generation, one-hot ballots and encrypted vault.

The private key is never required by ballot encryption or public aggregation.
The LAN client reuses ballot encryption; the offline custodian holds the key.
The original local experiment interface remains available as a teaching aid.
"""
import secrets
import uuid
from phe import paillier
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag
from common import VoteError, b64, unb64, canonical, now


def generate_keys(bits=2048):
    if bits not in (1024, 2048, 3072):
        raise VoteError('不支持的密钥长度')
    pub, priv = paillier.generate_paillier_keypair(n_length=bits)
    signer = Ed25519PrivateKey.generate()
    secret = {'p': str(priv.p), 'q': str(priv.q),
              'signer': b64(signer.private_bytes(serialization.Encoding.Raw,
                          serialization.PrivateFormat.Raw, serialization.NoEncryption()))}
    return pub, signer, secret


def public_key(config):
    return paillier.PaillierPublicKey(int(config['n']))


def seal_secret(secret, password, election_id):
    if len(password) < 8:
        raise VoteError('保管口令至少需要8个字符')
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode('utf-8'))
    ct = AESGCM(key).encrypt(nonce, canonical(secret), election_id.encode())
    return {'version': 1, 'kdf': 'scrypt-N32768-r8-p1', 'salt': b64(salt),
            'nonce': b64(nonce), 'ciphertext': b64(ct), 'election_id': election_id}


def open_secret(vault, password, election_id):
    import json
    if vault['version'] != 1 or vault['kdf'] != 'scrypt-N32768-r8-p1' or vault['election_id'] != election_id:
        raise VoteError('密钥文件与投票不匹配')
    try:
        salt, nonce = unb64(vault['salt']), unb64(vault['nonce'])
        if len(salt) != 16 or len(nonce) != 12:
            raise VoteError('密钥文件参数错误')
        key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode('utf-8'))
        return json.loads(AESGCM(key).decrypt(nonce, unb64(vault['ciphertext']), election_id.encode()))
    except InvalidTag as exc:
        raise VoteError('口令错误或密钥文件已损坏') from exc


def encrypt_ballot(config, voter_id, choice):
    if type(choice) is not int or not 0 <= choice < len(config['options']):
        raise VoteError('必须且只能选择一个有效选项')
    if voter_id not in config['roster']:
        raise VoteError('投票者ID不在授权名单内')
    pub = public_key(config)
    # raw_encrypt chooses independent, cryptographically random r in Z*_n.
    encrypted = [str(pub.raw_encrypt(int(i == choice))) for i in range(len(config['options']))]
    return {'version': 1, 'election_id': config['election_id'], 'voter_id': voter_id,
            'ballot_type': 'single_choice', 'timestamp': now(), 'nonce': uuid.uuid4().hex,
            'ciphertexts': encrypted}
