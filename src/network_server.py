"""LAN HTTPS server: authorized ciphertext intake and homomorphic aggregation."""
import ssl
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from common import VoteError, canonical
from audit_service import require_fields
from network_protocol import parse_json
from network_store import NetworkStore, APIError

MAX_REQUEST = 128_000


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'
    server_version = 'MiPiaoLab/1'

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, *_):
        # Do not log credentials, ciphertext payloads or user input.
        pass

    def reply(self, status, value):
        data = canonical(value)
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        lengths = self.headers.get_all('Content-Length', [])
        if self.headers.get('Transfer-Encoding') or len(lengths) != 1:
            raise APIError('必须提供唯一Content-Length', 400)
        try:
            size = int(lengths[0])
        except ValueError as exc:
            raise APIError('Content-Length不合法') from exc
        if not 0 < size <= MAX_REQUEST:
            raise APIError('请求超过允许大小', 413)
        if self.headers.get_content_type() != 'application/json':
            raise APIError('请求必须为application/json', 415)
        raw = self.rfile.read(size)
        if len(raw) != size:
            raise APIError('请求内容不完整')
        return parse_json(raw)

    def route(self):
        store = self.server.store
        if self.command == 'GET' and self.path == '/api/election':
            return store.election
        if self.command == 'GET' and self.path == '/api/status':
            return store.status()
        authorization = self.headers.get('Authorization', '')
        user = store.authorize(authorization[7:] if authorization.startswith('Bearer ') else '')
        if self.command == 'GET' and self.path == '/api/me':
            return dict(user, receipt=store.receipt(user['voter_id']) if user['role']=='voter' else None)
        if self.command == 'POST' and self.path == '/api/ballots':
            if user['role'] != 'voter':
                raise APIError('管理员凭证不能代替投票凭证', 403)
            body = self.body()
            require_fields(body, ('ballot',), '投票请求')
            return {'receipt': store.accept(user['voter_id'], body['ballot'])}
        if self.path in ('/api/close', '/api/export', '/api/results'):
            if user['role'] != 'admin':
                raise APIError('该操作需要管理员凭证', 403)
            if self.command == 'GET' and self.path == '/api/export':
                return store.export()
            if self.command == 'POST' and self.path == '/api/close':
                require_fields(self.body(), (), '关闭请求')
                return store.close()
            if self.command == 'POST' and self.path == '/api/results':
                return store.publish(self.body())
        raise APIError('接口不存在', 404)

    def dispatch(self):
        try:
            self.reply(200, self.route())
        except APIError as exc:
            self.reply(exc.status, {'error': str(exc)})
        except VoteError as exc:
            self.reply(400, {'error': str(exc)})
        except sqlite3.OperationalError:
            self.reply(503, {'error': '存储暂不可用，请重试或联系管理员'})
        except (ConnectionError, TimeoutError):
            self.close_connection = True
        except Exception:
            self.reply(500, {'error': '服务器内部错误，操作未确认成功'})

    do_GET = dispatch
    do_POST = dispatch


class VotingServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def process_request_thread(self, request, client_address):
        # Handshake in the worker, not get_request(): a connected peer that
        # never sends ClientHello must not block the listener's accept loop.
        request.settimeout(10)
        try:
            secured = self.tls.wrap_socket(request, server_side=True)
        except OSError:
            request.close()
            return
        super().process_request_thread(secured, client_address)


def make_server(root, host='0.0.0.0', port=8443):
    store = NetworkStore(root)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(store.root/'tls.crt', store.root/'tls.key')
    server = VotingServer((host, port), Handler)
    server.store, server.tls = store, tls
    return server


def serve(root, host='0.0.0.0', port=8443):
    with make_server(root, host, port) as server:
        print(f'密文投票服务器已启动 https://{host}:{server.server_port}', flush=True)
        print('服务器只保存公钥、密文、凭证摘要及登记签名密钥。Ctrl+C停止。', flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
