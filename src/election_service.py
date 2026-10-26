"""Member C: single-writer election lifecycle and public-only export."""
import copy
import uuid
import zipfile
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from common import VoteError, now, b64, unb64, digest, read_json, write_json
from crypto_service import generate_keys, seal_secret, open_secret, encrypt_ballot
from audit_service import audit, validate_ballot, sign_manifest


def create_election(root, title, options, count, password, bits=2048):
    root = Path(root)
    options = [x.strip() for x in options if x.strip()]
    if not title.strip() or len(title) > 80:
        raise VoteError('标题不能为空且不得超过80字')
    if not 2 <= len(options) <= 8 or len(set(options)) != len(options) or any(len(x) > 24 for x in options):
        raise VoteError('请输入2至8个不重复的选项，每项不超过24字')
    if type(count) is not int or not 1 <= count <= 10000:
        raise VoteError('投票人数范围为1至10000')
    if len(password) < 8:
        raise VoteError('保管口令至少需要8个字符')
    if root.exists() and any(root.iterdir()):
        raise VoteError('请选择空目录，防止覆盖已有投票')
    pub, signer, secret = generate_keys(bits)
    eid = uuid.uuid4().hex
    config = {'version': 1, 'election_id': eid, 'title': title.strip(), 'options': options,
              'roster': [f'V{i:04d}' for i in range(1, count+1)], 'n': str(pub.n), 'key_bits': bits,
              'created_at': now(), 'audit_public_key': b64(signer.public_key().public_bytes(
                  serialization.Encoding.Raw, serialization.PublicFormat.Raw))}
    vault = seal_secret(secret, password, eid)
    (root / 'public' / 'ballots').mkdir(parents=True, exist_ok=True)
    write_json(root / 'private' / 'trustee.vault', vault)
    write_json(root / 'public' / 'config.json', config)
    payload = {'election_id': eid, 'config_sha256': digest(config), 'status': 'open', 'entries': [], 'updated_at': now()}
    write_json(root / 'public' / 'manifest.json', sign_manifest(payload, signer))
    return Election(root, signer)


class Election:
    """Holds only the registrar signing key, never a Paillier private key."""
    def __init__(self, root, signer=None):
        self.root = Path(root)
        self.signer = signer
        self.config, self.payload, _ = audit(root)

    def unlock_registrar(self, password):
        secret = open_secret(read_json(self.root / 'private' / 'trustee.vault'), password, self.config['election_id'])
        signer = Ed25519PrivateKey.from_private_bytes(unb64(secret['signer']))
        pub = b64(signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        if pub != self.config['audit_public_key']:
            raise VoteError('登记密钥与配置不匹配')
        self.signer = signer

    def refresh(self):
        self.config, self.payload, ballots = audit(self.root)
        return ballots

    def accept(self, ballot):
        if self.signer is None:
            raise VoteError('请先解锁登记端')
        self.refresh()
        if self.payload['status'] != 'open':
            raise VoteError('投票已关闭，不能提交新票')
        validate_ballot(self.config, ballot)
        if any(x['voter_id'] == ballot['voter_id'] for x in self.payload['entries']):
            raise VoteError('该ID已投票，拒绝重复提交')
        if any(b['nonce'] == ballot['nonce'] for b in self.refresh()):
            raise VoteError('选票随机标识重复')
        filename = digest({'voter_id': ballot['voter_id']}) + '.json'
        entry = {'voter_id': ballot['voter_id'], 'file': filename, 'sha256': digest(ballot)}
        payload = copy.deepcopy(self.payload)
        payload['entries'].append(entry)
        payload['updated_at'] = now()
        # Crash between writes is fail-closed: audit detects an unregistered file.
        write_json(self.root / 'public' / 'ballots' / filename, ballot)
        write_json(self.root / 'public' / 'manifest.json', sign_manifest(payload, self.signer))
        self.payload = payload
        return entry['sha256']

    def cast(self, voter_id, choice):
        return self.accept(encrypt_ballot(self.config, voter_id, choice))

    def close(self):
        if self.signer is None:
            raise VoteError('请先解锁登记端')
        self.refresh()
        payload = copy.deepcopy(self.payload)
        payload['status'] = 'closed'
        payload['updated_at'] = now()
        write_json(self.root / 'public' / 'manifest.json', sign_manifest(payload, self.signer))
        self.payload = payload

    def export_public(self, output):
        self.refresh()
        output = Path(output).resolve()
        if self.root.resolve() in output.parents:
            raise VoteError('请将公开包导出到投票目录之外')
        with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as z:
            # Export the audited election only, never arbitrary neighboring JSON.
            paths = [self.root / 'public' / name for name in ('config.json', 'manifest.json')]
            paths.extend(self.root / 'public' / 'ballots' / entry['file']
                         for entry in self.payload['entries'])
            for p in paths:
                z.write(p, p.relative_to(self.root))
        return str(output)
