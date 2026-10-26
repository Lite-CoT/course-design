"""Run on the organizer/trustee machine; distribute only server/ to the host."""
import hashlib
import secrets
import sqlite3
import uuid
from pathlib import Path
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from common import VoteError, b64, canonical, digest, now, write_json
from crypto_service import generate_keys, seal_secret
from audit_service import sign_manifest
from network_protocol import validate_election


def private_bytes(key):
    return key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())


def public_bytes(key):
    return b64(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def initialize_network(root, title, options, count, password, bits=2048):
    root = Path(root)
    if root.exists() and any(root.iterdir()):
        raise VoteError('初始化目录必须为空，不能覆盖已有轮次')
    if (not isinstance(title, str) or not 1 <= len(title.strip()) <= 80
            or type(count) is not int or not 1 <= count <= 10000
            or not isinstance(options, list) or not 2 <= len(options) <= 8
            or any(not isinstance(x, str) or not 1 <= len(x.strip()) <= 24 for x in options)
            or len({x.strip() for x in options}) != len(options)):
        raise VoteError('标题、人数或选项不合法')
    if len(password) < 8:
        raise VoteError('保管口令至少8个字符')
    pub, registrar, private = generate_keys(bits)
    private.pop('signer')  # The server's registrar key is not a decryption key.
    result_signer = Ed25519PrivateKey.generate()
    private['result_signer'] = b64(private_bytes(result_signer))
    config = {'version': 1, 'election_id': uuid.uuid4().hex, 'title': title.strip(),
              'options': [x.strip() for x in options], 'roster': [f'V{i:04d}' for i in range(1, count+1)],
              'n': str(pub.n), 'key_bits': bits, 'created_at': now(), 'audit_public_key': public_bytes(registrar)}
    election = {'protocol': 1, 'config': config, 'result_public_key': public_bytes(result_signer)}
    validate_election(election)
    server, trustee, organizer = (root/name for name in ('server', 'trustee', 'organizer'))
    for directory in (server, trustee, organizer/'voters'):
        directory.mkdir(parents=True, exist_ok=True)
    write_json(server/'election.json', election)
    write_json(trustee/'election.json', election)
    write_json(trustee/'trustee.vault', seal_secret(private, password, config['election_id']))
    (server/'registrar.key').write_bytes(private_bytes(registrar))

    tls_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'MiPiaoLab LAN')])
    stamp = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(tls_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(stamp-timedelta(minutes=5)).not_valid_after(stamp+timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(tls_key, hashes.SHA256()))
    (server/'tls.crt').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (server/'tls.key').write_bytes(tls_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    manifest = sign_manifest({'election_id': config['election_id'], 'config_sha256': digest(config),
                              'status': 'open', 'entries': [], 'updated_at': now()}, registrar)
    with sqlite3.connect(server/'votes.sqlite3') as db:
        db.executescript('''
            PRAGMA journal_mode=WAL;
            CREATE TABLE state (id INTEGER PRIMARY KEY CHECK(id=1), manifest TEXT NOT NULL, result TEXT);
            CREATE TABLE credentials (token_hash TEXT PRIMARY KEY, voter_id TEXT UNIQUE, role TEXT NOT NULL);
            CREATE TABLE ballots (voter_id TEXT PRIMARY KEY, nonce TEXT UNIQUE NOT NULL,
                                  content TEXT NOT NULL, receipt TEXT NOT NULL);
        ''')
        db.execute('INSERT INTO state(id,manifest) VALUES(1,?)', (canonical(manifest).decode(),))
        for voter, role in [(None, 'admin')]+[(v, 'voter') for v in config['roster']]:
            token = secrets.token_urlsafe(32)
            db.execute('INSERT INTO credentials VALUES(?,?,?)',
                       (hashlib.sha256(token.encode()).hexdigest(), voter, role))
            ticket = {'version': 1, 'role': role, 'voter_id': voter, 'token': token,
                      'tls_sha256': fingerprint, 'election_sha256': digest(election),
                      'election_id': config['election_id']}
            path = organizer/'admin.ticket.json' if role == 'admin' else organizer/'voters'/f'{voter}.ticket.json'
            write_json(path, ticket)
    return {'election_id': config['election_id'], 'server': str(server), 'trustee': str(trustee),
            'organizer': str(organizer), 'tls_sha256': fingerprint, 'voters': count}
