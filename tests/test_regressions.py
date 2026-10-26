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


if __name__ == '__main__':
    unittest.main()
