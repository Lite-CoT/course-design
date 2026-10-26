"""Pinned TLS client. Choice encoding and Paillier encryption happen here."""
import hashlib
import hmac
import http.client
import re
import ssl
from common import VoteError, canonical, digest
from crypto_service import encrypt_ballot
from network_protocol import parse_json, validate_election, verify_object, verify_result, verify_bundle
from audit_service import require_fields

MAX_RESPONSE = 256_000_000


class NetworkError(VoteError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def validate_ticket(ticket):
    require_fields(ticket, ('version', 'role', 'voter_id', 'token', 'tls_sha256',
                            'election_sha256', 'election_id'), '凭证')
    if (type(ticket['version']) is not int or ticket['version'] != 1
            or ticket['role'] not in ('admin', 'voter')
            or not isinstance(ticket['token'], str)
            or not re.fullmatch(r'[A-Za-z0-9_-]{43}', ticket['token'])):
        raise VoteError('凭证版本、角色或票码不正确')
    for field in ('tls_sha256', 'election_sha256'):
        if not isinstance(ticket[field], str) or not re.fullmatch('[0-9a-f]{64}', ticket[field]):
            raise VoteError('凭证指纹格式不正确')
    if ticket['role'] == 'voter' and not isinstance(ticket['voter_id'], str):
        raise VoteError('投票凭证缺少绑定ID')


class NetworkClient:
    def __init__(self, host, port, ticket):
        validate_ticket(ticket)
        if not isinstance(host, str) or not host.strip() or any(c in host for c in '/\\ \t\r\n'):
            raise VoteError('请输入IP或主机名，不含协议和路径')
        if type(port) is not int or not 1 <= port <= 65535:
            raise VoteError('端口必须在1至65535之间')
        self.host, self.port, self.ticket = host.strip(), port, dict(ticket)
        self.election = None

    def request(self, method, path, data=None, authenticated=True):
        # Trust is the exact certificate fingerprint delivered with the ticket,
        # not the ambient CA store or an unverified first connection.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        connection = http.client.HTTPSConnection(self.host, self.port, context=context, timeout=30)
        try:
            connection.connect()
            actual = hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()
            if not hmac.compare_digest(actual, self.ticket['tls_sha256']):
                raise NetworkError('服务器证书指纹与凭证不符，未发送凭证或选票')
            headers = {'Accept': 'application/json'}
            if authenticated:
                headers['Authorization'] = 'Bearer ' + self.ticket['token']
            body = None if data is None else canonical(data)
            if body is not None:
                headers['Content-Type'] = 'application/json'
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                raise NetworkError('服务器响应超过允许大小')
            value = parse_json(raw)
            if response.status != 200:
                message = value.get('error', '请求失败') if isinstance(value, dict) else '请求失败'
                raise NetworkError(str(message), response.status)
            return value
        except (OSError, http.client.HTTPException) as exc:
            raise NetworkError('连接失败或响应中断，请核对IP、端口和服务器状态；提交中断后请先刷新回执') from exc
        finally:
            connection.close()

    def connect(self):
        election = self.request('GET', '/api/election', authenticated=False)
        validate_election(election)
        if (digest(election) != self.ticket['election_sha256']
                or election['config']['election_id'] != self.ticket['election_id']):
            raise VoteError('服务器投票配置与凭证中可信摘要不符')
        self.election = election
        me = self.me()
        if me['role'] != self.ticket['role'] or me['voter_id'] != self.ticket['voter_id']:
            raise VoteError('服务器返回的凭证身份不一致')
        return {'election': election, 'me': me, 'status': self.status()}

    def status(self):
        value = self.request('GET', '/api/status', authenticated=False)
        if self.election is None or value['election_id'] != self.election['config']['election_id']:
            raise VoteError('投票状态不属于当前轮次')
        if value['result'] is not None:
            verify_result(self.election, value['result'])
        return value

    def me(self):
        value = self.request('GET', '/api/me')
        if value['receipt'] is not None:
            payload = verify_object(value['receipt'], self.election['config']['audit_public_key'])
            if payload['voter_id'] != self.ticket['voter_id'] or payload['election_id'] != self.ticket['election_id']:
                raise VoteError('回执身份或轮次不一致')
        return value

    def vote(self, choice):
        if self.election is None:
            raise VoteError('请先连接服务器')
        if self.ticket['role'] != 'voter':
            raise VoteError('请使用投票凭证')
        ballot = encrypt_ballot(self.election['config'], self.ticket['voter_id'], choice)
        response = self.request('POST', '/api/ballots', {'ballot': ballot})
        receipt = response['receipt']
        payload = verify_object(receipt, self.election['config']['audit_public_key'])
        if (payload['voter_id'] != self.ticket['voter_id'] or payload['election_id'] != self.ticket['election_id']
                or payload['ballot_sha256'] != digest(ballot)):
            raise VoteError('服务器回执与本端提交选票不一致')
        return receipt

    def close(self):
        return self.request('POST', '/api/close', {})

    def export(self):
        bundle = self.request('GET', '/api/export')
        verify_bundle(self.election, bundle)
        return bundle

    def publish(self, result):
        verify_result(self.election, result)
        return self.request('POST', '/api/results', result)
