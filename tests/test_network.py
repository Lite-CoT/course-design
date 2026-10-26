"""Real TLS sockets, independent credentials and transactional election behavior."""
import copy
import json
import sqlite3
import sys
import tempfile
import threading
import unittest
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
from common import VoteError, read_json, canonical, digest
from crypto_service import encrypt_ballot, open_secret
from audit_service import sign_manifest
from network_setup import initialize_network
from network_server import make_server
from network_client import NetworkClient, NetworkError
from network_trustee import decrypt_bundle
from network_protocol import parse_json, aggregate_records, verify_result
from network_store import NetworkStore

PASSWORD = 'Network-Test-2026!'


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        # Dedicated full acceptance uses 2048; boundary tests use 1024 to stay fast.
        initialize_network(self.root, '网络测试', ['甲', '乙', '弃权'], 6, PASSWORD, bits=1024)
        self.server = make_server(self.root/'server', '127.0.0.1', 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)
        self.admin = self.client('admin')

    def stop(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=5)

    def ticket(self, identity):
        name = 'organizer/admin.ticket.json' if identity=='admin' else f'organizer/voters/{identity}.ticket.json'
        return read_json(self.root/name)

    def client(self, identity):
        client = NetworkClient('127.0.0.1', self.server.server_port, self.ticket(identity))
        client.connect()
        return client

    def assert_rejected(self, status, fn):
        with self.assertRaises(NetworkError) as caught:
            fn()
        self.assertEqual(caught.exception.status, status)

    def test_full_tls_vote_aggregate_offline_decrypt_publish(self):
        for voter, choice in [('V0001',0), ('V0002',1), ('V0003',0)]:
            self.client(voter).vote(choice)
        self.admin.close()
        bundle = self.admin.export()
        self.assertEqual(bundle['aggregate']['accepted'], 3)
        result = decrypt_bundle(self.root/'trustee', bundle, PASSWORD)
        self.assertEqual(result['payload']['counts'], [2,1,0])
        self.admin.publish(result)
        self.assertEqual(self.client('V0004').status()['result'], result)
        self.assertEqual(decrypt_bundle(self.root/'trustee', self.admin.export(), PASSWORD), result)

    def test_server_has_no_paillier_private_material(self):
        election = read_json(self.root/'trustee/election.json')
        secret = open_secret(read_json(self.root/'trustee/trustee.vault'), PASSWORD, election['config']['election_id'])
        for path in (self.root/'server').iterdir():
            self.assertNotEqual(path.suffix, '.vault')
            for value in (secret['p'], secret['q'], secret['result_signer']):
                self.assertNotIn(value.encode(), path.read_bytes())
        voter = self.client('V0001')
        transmitted = []
        original = voter.request
        def capture(method, path, data=None, authenticated=True):
            if path == '/api/ballots': transmitted.append(data)
            return original(method, path, data, authenticated)
        voter.request = capture
        voter.vote(2)
        self.assertEqual(set(transmitted[0]), {'ballot'})
        self.assertEqual(set(transmitted[0]['ballot']),
                         {'version','election_id','voter_id','ballot_type','timestamp','nonce','ciphertexts'})
        with closing(sqlite3.connect(self.root/'server/votes.sqlite3')) as db:
            stored = json.loads(db.execute('SELECT content FROM ballots').fetchone()[0])
        self.assertEqual(stored, transmitted[0]['ballot'])

    def test_concurrent_same_id_only_one_accepted(self):
        clients = [self.client('V0001') for _ in range(8)]
        def cast(client):
            try: client.vote(0); return 200
            except NetworkError as exc: return exc.status
        with ThreadPoolExecutor(max_workers=8) as pool:
            responses = list(pool.map(cast, clients))
        self.assertEqual(responses.count(200), 1)
        self.assertEqual(responses.count(409), 7)
        self.assertEqual(self.admin.status()['accepted'], 1)

    def test_multiple_clients_can_vote_concurrently(self):
        clients = [self.client(f'V{i:04d}') for i in range(1,7)]
        with ThreadPoolExecutor(max_workers=6) as pool:
            list(pool.map(lambda pair: pair[1].vote(pair[0] % 3), enumerate(clients)))
        self.admin.close()
        result = decrypt_bundle(self.root/'trustee', self.admin.export(), PASSWORD)
        self.assertEqual(result['payload']['counts'], [2,2,2])

    def test_credential_cannot_impersonate_another_voter(self):
        voter = self.client('V0001')
        ballot = encrypt_ballot(voter.election['config'], 'V0002', 0)
        self.assert_rejected(403, lambda: voter.request('POST', '/api/ballots', {'ballot': ballot}))
        self.assertEqual(self.admin.status()['accepted'], 0)

    def test_invalid_token_is_rejected(self):
        ticket = self.ticket('V0001'); ticket['token'] = 'x'*43
        client = NetworkClient('127.0.0.1', self.server.server_port, ticket)
        self.assert_rejected(401, client.connect)

    def test_wrong_certificate_pin_rejected_before_credential_auth(self):
        ticket = self.ticket('V0001'); ticket['tls_sha256'] = '0'*64
        called = []
        original = self.server.store.authorize
        self.server.store.authorize = lambda token: (called.append(True), original(token))[1]
        client = NetworkClient('127.0.0.1', self.server.server_port, ticket)
        with self.assertRaisesRegex(VoteError, '证书指纹'):
            client.connect()
        self.assertEqual(called, [])

    def test_wrong_config_digest_rejected(self):
        ticket = self.ticket('V0001'); ticket['election_sha256'] = '0'*64
        client = NetworkClient('127.0.0.1', self.server.server_port, ticket)
        with self.assertRaisesRegex(VoteError, '配置'):
            client.connect()

    def test_role_permissions(self):
        voter = self.client('V0001')
        self.assert_rejected(403, voter.close)
        self.assert_rejected(403, voter.export)
        ballot = encrypt_ballot(voter.election['config'], 'V0001', 0)
        self.assert_rejected(403, lambda: self.admin.request('POST', '/api/ballots', {'ballot': ballot}))

    def test_no_early_tally_and_no_late_ballot(self):
        self.assert_rejected(400, self.admin.export)
        self.admin.close()
        self.assert_rejected(409, lambda: self.client('V0001').vote(0))

    def test_network_schema_rejects_plaintext_and_invalid_ciphertext(self):
        voter = self.client('V0001')
        ballot = encrypt_ballot(voter.election['config'], 'V0001', 0)
        variants = [{'choice': 0}, {'ballot': dict(ballot, choice=0)},
                    {'ballot': dict(ballot, ciphertexts=['0','1','1'])}, {'ballot': {}}]
        for body in variants:
            self.assert_rejected(400, lambda: voter.request('POST','/api/ballots',body))
        self.assertEqual(self.admin.status()['accepted'], 0)

    def test_receipt_recovers_confirmation_after_reconnect(self):
        receipt = self.client('V0001').vote(1)
        self.assertEqual(self.client('V0001').me()['receipt'], receipt)
        self.assert_rejected(409, lambda: self.client('V0001').vote(1))

    def test_database_tamper_detected(self):
        self.client('V0001').vote(1)
        with closing(sqlite3.connect(self.root/'server/votes.sqlite3')) as db:
            ballot = json.loads(db.execute('SELECT content FROM ballots').fetchone()[0])
            ballot['ciphertexts'][0] = '1'
            db.execute('UPDATE ballots SET content=?', (canonical(ballot).decode(),))
            db.commit()
        self.assert_rejected(400, self.admin.status)
        with self.assertRaises(VoteError): NetworkStore(self.root/'server')

    def test_trustee_rejects_wrong_password_and_partial_aggregate(self):
        self.client('V0001').vote(0); self.client('V0002').vote(1); self.admin.close()
        bundle = self.admin.export()
        with self.assertRaisesRegex(VoteError, '口令'):
            decrypt_bundle(self.root/'trustee', bundle, 'wrong-password')
        changed = copy.deepcopy(bundle)
        changed['aggregate']['ciphertexts'] = changed['ballots'][0]['ciphertexts']
        with self.assertRaisesRegex(VoteError, '完整选票'):
            decrypt_bundle(self.root/'trustee', changed, PASSWORD)
        self.assertFalse((self.root/'trustee/approved-result.json').exists())

    def test_trustee_refuses_second_different_even_valid_signed_set(self):
        self.client('V0001').vote(0); self.client('V0002').vote(1); self.admin.close()
        bundle = self.admin.export()
        decrypt_bundle(self.root/'trustee', bundle, PASSWORD)
        forged = copy.deepcopy(bundle)
        forged['ballots'].pop()
        forged['manifest']['payload']['entries'].pop()
        forged['manifest'] = sign_manifest(forged['manifest']['payload'], self.server.store.signer)
        forged['aggregate'], forged['aggregation_ms'] = aggregate_records(forged['election'], forged['manifest'], forged['ballots'])
        with self.assertRaisesRegex(VoteError, '已批准'):
            decrypt_bundle(self.root/'trustee', forged, PASSWORD)

    def test_result_signature_cannot_be_forged(self):
        self.client('V0001').vote(0); self.admin.close()
        result = decrypt_bundle(self.root/'trustee', self.admin.export(), PASSWORD)
        forged = copy.deepcopy(result); forged['payload']['counts'] = [0,1,0]
        self.assert_rejected(400, lambda: self.admin.request('POST','/api/results',forged))
        self.assertIsNone(self.admin.status()['result'])

    def test_closed_empty_election_publishes_zero_counts(self):
        self.admin.close()
        result = decrypt_bundle(self.root/'trustee', self.admin.export(), PASSWORD)
        self.assertEqual(result['payload']['counts'], [0,0,0])
        self.admin.publish(result)

    def test_strict_network_json_parser(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'\xff', b'{'):
            with self.assertRaises(VoteError): parse_json(raw)


if __name__ == '__main__': unittest.main()
