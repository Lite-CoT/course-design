"""Task-sheet challenges on isolated synthetic elections and real loopback TLS."""
import copy
import json
import random
import socket
import sqlite3
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from common import VoteError, canonical, read_json
from crypto_service import encrypt_ballot, public_key
from network_setup import initialize_network
from network_server import make_server
from network_store import NetworkStore
from network_client import NetworkClient, NetworkError
from network_trustee import decrypt_bundle
from network_protocol import verify_bundle, sign_object

PASSWORD = 'Challenge-Synthetic-2026!'


class ChallengeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        initialize_network(self.root, '现场随机验证', ['同意', '反对', '弃权'], 8, PASSWORD, bits=1024)
        self.server = make_server(self.root / 'server', '127.0.0.1', 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)
        self.admin = self.client('admin')

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def client(self, identity):
        path = 'admin.ticket.json' if identity == 'admin' else f'voters/{identity}.ticket.json'
        client = NetworkClient('127.0.0.1', self.server.server_port, read_json(self.root / 'organizer' / path))
        client.connect()
        return client

    def reject(self, fn, status=400):
        with self.assertRaises(NetworkError) as caught:
            fn()
        self.assertEqual(caught.exception.status, status)

    def alter_db(self, sql, params=()):
        with closing(sqlite3.connect(self.root / 'server/votes.sqlite3')) as db:
            db.execute(sql, params)
            db.commit()

    def test_database_identity_column_tamper_fails_before_next_write(self):
        self.client('V0001').vote(0)
        self.alter_db('UPDATE ballots SET voter_id=?', ('V0008',))
        self.reject(self.admin.status)
        with self.assertRaises(VoteError):
            NetworkStore(self.root / 'server')

    def test_database_nonce_column_tamper_is_detected(self):
        self.client('V0001').vote(0)
        self.alter_db('UPDATE ballots SET nonce=?', ('0' * 32,))
        self.reject(self.admin.status)

    def test_database_receipt_tamper_is_detected_on_audit_and_restart(self):
        self.client('V0001').vote(0)
        self.alter_db('UPDATE ballots SET receipt=?', ('{}',))
        self.reject(self.admin.status)
        with self.assertRaises(VoteError):
            NetworkStore(self.root / 'server')

    def test_valid_signature_on_wrong_receipt_digest_is_rejected(self):
        receipt = self.client('V0001').vote(0)
        receipt['payload']['ballot_sha256'] = '0' * 64
        wrong = sign_object(receipt['payload'], self.server.store.signer)
        self.alter_db('UPDATE ballots SET receipt=?', (canonical(wrong).decode(),))
        self.reject(self.admin.status)

    def test_stalled_tls_handshake_does_not_block_other_clients(self):
        entered = threading.Event()
        original = self.server.tls.wrap_socket
        def wrap(*args, **kwargs):
            entered.set()
            return original(*args, **kwargs)
        with patch.object(self.server.tls, 'wrap_socket', wrap):
            slow = socket.create_connection(('127.0.0.1', self.server.server_port), timeout=3)
            with ThreadPoolExecutor(max_workers=1) as pool:
                try:
                    self.assertTrue(entered.wait(3), 'test connection never reached TLS')
                    status = pool.submit(self.admin.status)
                    self.assertEqual(status.result(timeout=2)['accepted'], 0)
                finally:
                    slow.close()

    def test_boolean_aggregate_count_is_not_integer_one(self):
        self.client('V0001').vote(0)
        self.admin.close()
        bundle = self.admin.export()
        bundle['aggregate']['accepted'] = True
        with self.assertRaises(VoteError):
            verify_bundle(self.admin.election, bundle)

    def test_invalid_json_depth_and_integer_length_are_domain_errors(self):
        path = self.root / 'malformed.json'
        for data in (b'[' * 2000 + b'0' + b']' * 2000, b'9' * 5000):
            path.write_bytes(data)
            with self.subTest(length=len(data)), self.assertRaises(VoteError):
                read_json(path)

    def test_delete_ballot_or_change_ciphertext_inside_valid_group(self):
        self.client('V0001').vote(0)
        with closing(sqlite3.connect(self.root / 'server/votes.sqlite3')) as db:
            original = db.execute('SELECT content FROM ballots').fetchone()[0]
        changed = json.loads(original)
        pub = public_key(self.admin.election['config'])
        changed['ciphertexts'][0] = str(int(changed['ciphertexts'][0]) * pub.g % pub.nsquare)
        self.alter_db('UPDATE ballots SET content=?', (canonical(changed).decode(),))
        self.reject(self.admin.export)
        self.alter_db('UPDATE ballots SET content=?', (original,))
        self.assertEqual(self.admin.status()['accepted'], 1)  # repair, not a permanent false alarm
        self.alter_db('DELETE FROM ballots')
        self.reject(self.admin.status)

    def test_export_tamper_matrix_never_creates_approval(self):
        self.client('V0001').vote(0)
        self.client('V0002').vote(1)
        self.admin.close()
        bundle = self.admin.export()
        variants = []
        for name in ('ciphertext', 'delete', 'duplicate', 'manifest', 'config', 'aggregate'):
            changed = copy.deepcopy(bundle)
            if name == 'ciphertext': changed['ballots'][0]['ciphertexts'][0] = '1'
            elif name == 'delete': changed['ballots'].pop()
            elif name == 'duplicate': changed['ballots'][1] = copy.deepcopy(changed['ballots'][0])
            elif name == 'manifest': changed['manifest']['payload']['status'] = 'open'
            elif name == 'config': changed['election']['config']['options'].reverse()
            else: changed['aggregate']['ciphertexts'] = changed['ballots'][0]['ciphertexts']
            variants.append((name, changed))
        for name, changed in variants:
            with self.subTest(name=name), self.assertRaises(VoteError):
                decrypt_bundle(self.root / 'trustee', changed, PASSWORD)
            self.assertFalse((self.root / 'trustee/approved-result.json').exists())
        self.assertEqual(decrypt_bundle(self.root / 'trustee', bundle, PASSWORD)['payload']['counts'], [1, 1, 0])

    def test_reused_nonce_is_rejected_even_with_different_case(self):
        first, second = self.client('V0001'), self.client('V0002')
        a = encrypt_ballot(first.election['config'], 'V0001', 0)
        a['nonce'] = 'abcdef1234567890abcdef1234567890'
        first.request('POST', '/api/ballots', {'ballot': a})
        b = encrypt_ballot(second.election['config'], 'V0002', 1)
        b['nonce'] = a['nonce'].upper()
        self.reject(lambda: second.request('POST', '/api/ballots', {'ballot': b}), 409)
        self.assertEqual(self.admin.status()['accepted'], 1)

    def test_malformed_ballot_matrix_preserves_empty_state(self):
        client = self.client('V0001')
        original = encrypt_ballot(client.election['config'], 'V0001', 0)
        n = int(client.election['config']['n'])
        patches = [('version', True), ('voter_id', []), ('voter_id', 'UNKNOWN'),
                   ('ballot_type', 'multiple_choice'), ('timestamp', None), ('nonce', '+' + 'a' * 31),
                   ('election_id', 'f' * 32), ('ciphertexts', ['1'] * 2)]
        for value in ('0', str(n), str(n * n), '-1', '1e3', '１', True, None, '9' * 1900):
            patches.append(('ciphertexts', [value, '1', '1']))
        for field, value in patches:
            with self.subTest(field=field, value=str(value)[:30]):
                self.reject(lambda: client.request('POST', '/api/ballots', {'ballot': dict(original, **{field: value})}))
        self.assertEqual(self.admin.status()['accepted'], 0)
        for choice in (-1, 3, True, 0.5, None):
            with self.assertRaises(VoteError): client.vote(choice)
        client.vote(2)
        self.assertEqual(self.admin.status()['accepted'], 1)

    def test_concurrent_close_and_votes_produces_exact_committed_set(self):
        clients = [self.client(f'V{i:04d}') for i in range(1, 9)]
        gate = threading.Barrier(9)
        def cast(pair):
            i, client = pair
            gate.wait(timeout=5)
            try:
                client.vote(i % 3)
                return i % 3
            except NetworkError as exc:
                self.assertEqual(exc.status, 409)
                return None
        def close():
            gate.wait(timeout=5)
            self.admin.close()
        with ThreadPoolExecutor(max_workers=9) as pool:
            futures = [pool.submit(cast, pair) for pair in enumerate(clients)]
            closing_vote = pool.submit(close)
            choices = [f.result() for f in futures]
            closing_vote.result()
        bundle = self.admin.export()
        result = decrypt_bundle(self.root / 'trustee', bundle, PASSWORD)
        self.assertEqual(result['payload']['counts'], [choices.count(i) for i in range(3)])
        self.assertEqual(result['payload']['accepted'], sum(x is not None for x in choices))
        self.assertEqual(NetworkStore(self.root / 'server').status()['status'], 'closed')


if __name__ == '__main__':
    unittest.main()
