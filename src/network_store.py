"""Transactional ciphertext storage. This module never imports a decryptor."""
import copy
import hashlib
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from common import VoteError, canonical, digest, now, read_json, b64
from audit_service import sign_manifest, validate_ballot
from network_protocol import (validate_election, parse_json, audit_records, aggregate_records,
                              sign_object, verify_result)


class APIError(VoteError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


class NetworkStore:
    def __init__(self, root):
        self.root = Path(root).resolve()
        if any(self.root.rglob('*.vault')):
            raise VoteError('服务器目录中发现私钥保管库，请仅部署初始化生成的server目录')
        self.election = read_json(self.root/'election.json')
        validate_election(self.election)
        self.signer = Ed25519PrivateKey.from_private_bytes((self.root/'registrar.key').read_bytes())
        public = self.signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if b64(public) != self.election['config']['audit_public_key']:
            raise VoteError('服务器登记密钥与配置不匹配')
        if not (self.root/'votes.sqlite3').is_file():
            raise VoteError('服务器数据库不存在')
        self.status()  # Verify persisted signatures and ballot integrity before listening.

    @contextmanager
    def transaction(self, write=False):
        db = sqlite3.connect(self.root/'votes.sqlite3', timeout=15, isolation_level=None)
        try:
            db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def authorize(self, token):
        if not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', token):
            raise APIError('投票凭证无效', 401)
        with self.transaction() as db:
            row = db.execute('SELECT voter_id,role FROM credentials WHERE token_hash=?',
                             (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
        if row is None:
            raise APIError('投票凭证无效', 401)
        return {'voter_id': row[0], 'role': row[1]}

    def _read(self, db):
        row = db.execute('SELECT manifest,result FROM state WHERE id=1').fetchone()
        if row is None:
            raise VoteError('投票状态丢失')
        manifest = parse_json(row[0].encode())
        ballots = [parse_json(item[0].encode()) for item in db.execute('SELECT content FROM ballots ORDER BY rowid')]
        payload = audit_records(self.election, manifest, ballots)
        result = parse_json(row[1].encode()) if row[1] is not None else None
        return manifest, ballots, payload, result

    def _bundle(self, manifest, ballots):
        aggregate, elapsed = aggregate_records(self.election, manifest, ballots)
        return {'election': self.election, 'manifest': manifest, 'ballots': ballots,
                'aggregate': aggregate, 'aggregation_ms': elapsed}

    def status(self):
        with self.transaction() as db:
            manifest, ballots, payload, result = self._read(db)
            if result is not None:
                verify_result(self.election, result, self._bundle(manifest, ballots))
            return {'election_id': self.election['config']['election_id'], 'status': payload['status'],
                    'accepted': len(ballots), 'eligible': len(self.election['config']['roster']), 'result': result}

    def receipt(self, voter):
        with self.transaction() as db:
            self._read(db)
            row = db.execute('SELECT receipt FROM ballots WHERE voter_id=?', (voter,)).fetchone()
            return parse_json(row[0].encode()) if row else None

    def accept(self, voter, ballot):
        validate_ballot(self.election['config'], ballot)
        if ballot['voter_id'] != voter:
            raise APIError('凭证只能为绑定的ID投票', 403)
        with self.transaction(write=True) as db:
            _, ballots, payload, _ = self._read(db)
            if payload['status'] != 'open':
                raise APIError('投票已关闭', 409)
            if db.execute('SELECT 1 FROM ballots WHERE voter_id=?', (voter,)).fetchone():
                raise APIError('该ID已投票，拒绝重复提交', 409)
            if any(b['nonce'].lower() == ballot['nonce'].lower() for b in ballots):
                raise APIError('选票随机标识已使用', 409)
            receipt = sign_object({'election_id': self.election['config']['election_id'],
                                  'voter_id': voter, 'ballot_sha256': digest(ballot), 'accepted_at': now()}, self.signer)
            payload = copy.deepcopy(payload)
            payload['entries'].append({'voter_id': voter, 'file': digest({'voter_id': voter})+'.json',
                                       'sha256': digest(ballot)})
            payload['updated_at'] = now()
            # Unique ID/nonce and state update commit together, including competing requests.
            db.execute('INSERT INTO ballots VALUES(?,?,?,?)', (voter, ballot['nonce'].lower(),
                       canonical(ballot).decode(), canonical(receipt).decode()))
            db.execute('UPDATE state SET manifest=? WHERE id=1',
                       (canonical(sign_manifest(payload, self.signer)).decode(),))
            return receipt

    def close(self):
        with self.transaction(write=True) as db:
            _, _, payload, _ = self._read(db)
            if payload['status'] != 'closed':
                payload['status'] = 'closed'
                payload['updated_at'] = now()
                db.execute('UPDATE state SET manifest=? WHERE id=1',
                           (canonical(sign_manifest(payload, self.signer)).decode(),))
        return self.status()

    def export(self):
        with self.transaction() as db:
            manifest, ballots, _, _ = self._read(db)
            return self._bundle(manifest, ballots)

    def publish(self, envelope):
        with self.transaction(write=True) as db:
            manifest, ballots, _, previous = self._read(db)
            verify_result(self.election, envelope, self._bundle(manifest, ballots))
            if previous is not None and previous != envelope:
                raise APIError('该轮次已有确定的签名结果', 409)
            db.execute('UPDATE state SET result=? WHERE id=1', (canonical(envelope).decode(),))
        return self.status()
