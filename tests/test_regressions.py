"""Behavior regressions for problems found during the task-sheet review."""
import copy
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from common import VoteError, read_json, write_json
from crypto_service import encrypt_ballot
from election_service import create_election
from audit_service import audit, validate_ballot
from tally_service import aggregate, decrypt_tally

PASSWORD = 'Regression-2026!'


class ElectionRegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        # Small keys keep these boundary tests fast; acceptance experiments use 2048.
        self.election = create_election(self.directory / 'vote', '回归测试',
                                        ['甲', '乙'], 2, PASSWORD, bits=1024)

    def test_export_contains_only_audited_files(self):
        e = self.election
        e.cast('V0001', 0)
        e.close()
        write_json(e.root / 'public' / 'accidental-secret.json', {'private_note': 'exclude'})
        write_json(e.root / 'public' / 'backup' / 'extra.json', {'other': 'exclude'})
        output = self.directory / 'public.zip'
        e.export_public(output)
        with zipfile.ZipFile(output) as archive:
            expected = {'public/config.json', 'public/manifest.json',
                        'public/ballots/' + e.payload['entries'][0]['file']}
            self.assertEqual(set(archive.namelist()), expected)
            archive.extractall(self.directory / 'collector')
        self.assertFalse((self.directory / 'collector/private').exists())
        self.assertEqual(aggregate(e.root)['ciphertexts'],
                         aggregate(self.directory / 'collector')['ciphertexts'])

    def test_export_rejects_destination_inside_election(self):
        with self.assertRaisesRegex(VoteError, '目录之外'):
            self.election.export_public(self.election.root / 'export.zip')

    def test_malformed_ballots_raise_domain_errors(self):
        original = encrypt_ballot(self.election.config, 'V0001', 0)
        malformed = [None, [], {}, dict(original, version=True),
                     dict(original, nonce='+' + 'a' * 31),
                     dict(original, timestamp='2026-10-27'),
                     dict(original, ciphertexts=['0', '1'])]
        for ballot in malformed:
            with self.subTest(ballot=ballot), self.assertRaises(VoteError):
                validate_ballot(self.election.config, ballot)

    def test_damaged_public_config_raises_domain_error(self):
        path = self.election.root / 'public/config.json'
        for data in [None, [], {}, dict(self.election.config, options=[[], []]),
                     dict(self.election.config, n='9' * 10000),
                     dict(self.election.config, version=True)]:
            with self.subTest(data_type=type(data).__name__):
                write_json(path, data)
                with self.assertRaises(VoteError):
                    audit(self.election.root)

    def test_malformed_manifest_is_rejected(self):
        path = self.election.root / 'public/manifest.json'
        for value in [None, [], {}, {'payload': [], 'signature': 'bad'}]:
            write_json(path, value)
            with self.assertRaises(VoteError):
                audit(self.election.root)

    def test_strict_json_read(self):
        path = self.directory / 'invalid.json'
        for data in [b'{', b'\xff', b'{"x":1,"x":2}', b'{"x":NaN}', b'Infinity']:
            path.write_bytes(data)
            with self.subTest(data=data), self.assertRaises(VoteError):
                read_json(path)
        path.write_bytes(b'123456')
        with self.assertRaisesRegex(VoteError, '大小'):
            read_json(path, limit=5)
        with self.assertRaises(VoteError):
            read_json(self.directory / 'missing.json')

    def test_nested_unregistered_ballot_is_not_silently_ignored(self):
        write_json(self.election.root / 'public/ballots/subdir/hidden.json', {})
        with self.assertRaisesRegex(VoteError, '额外文件'):
            audit(self.election.root)

    def test_trustee_uses_its_own_timing_measurements(self):
        e = self.election
        e.cast('V0001', 0)
        e.close()
        request = aggregate(e.root)
        request.update(aggregate_ms=-999, audit_ms=-999)
        result = decrypt_tally(e.root, PASSWORD, request)
        self.assertEqual(result['counts'], [1, 0])
        self.assertGreaterEqual(result['aggregate_ms'], 0)
        self.assertGreaterEqual(result['audit_ms'], 0)

    def test_trustee_rejects_bad_request_shape_and_partial_tally(self):
        e = self.election
        e.cast('V0001', 0)
        e.cast('V0002', 1)
        e.close()
        request = aggregate(e.root)
        single = copy.deepcopy(request)
        single['ciphertexts'] = read_json(e.root / 'public/ballots' /
                                         e.payload['entries'][0]['file'])['ciphertexts']
        for bad in [None, [], {}, dict(request, accepted=True), single]:
            with self.subTest(request_type=type(bad).__name__), self.assertRaises(VoteError):
                decrypt_tally(e.root, PASSWORD, bad)


if __name__ == '__main__':
    unittest.main()
