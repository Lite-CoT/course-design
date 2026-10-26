"""Explicit network roles; passwords are read interactively, never sent to server."""
import argparse
import getpass
import json
import sys
from common import VoteError, read_json, write_json

COMMANDS = {'init', 'serve', 'cast', 'status', 'close', 'export', 'decrypt', 'publish'}


def run(argv):
    parser = argparse.ArgumentParser(description='密票实验室：局域网密文投票')
    commands = parser.add_subparsers(dest='command', required=True)
    init = commands.add_parser('init', help='在保管端初始化并生成三个分离目录')
    init.add_argument('--out', required=True)
    init.add_argument('--title', required=True)
    init.add_argument('--options', required=True, help='逗号分隔')
    init.add_argument('--voters', type=int, required=True)
    init.add_argument('--password-stdin', action='store_true', help='自动复测时从标准输入读一行口令')
    server = commands.add_parser('serve', help='启动只持公钥的服务器')
    server.add_argument('--data', required=True)
    server.add_argument('--host', default='0.0.0.0')
    server.add_argument('--port', default=8443, type=int)
    trustee = commands.add_parser('decrypt', help='保管端离线解密完整汇总')
    trustee.add_argument('--data', required=True)
    trustee.add_argument('--bundle', required=True)
    trustee.add_argument('--out', required=True)
    trustee.add_argument('--password-stdin', action='store_true', help='自动复测时从标准输入读一行口令')
    for command in ('cast', 'status', 'close', 'export', 'publish'):
        sub = commands.add_parser(command)
        sub.add_argument('--host', default='127.0.0.1')
        sub.add_argument('--port', type=int, default=8443)
        sub.add_argument('--ticket', required=True)
        if command == 'cast':
            sub.add_argument('--choice', type=int, required=True, help='从1开始的选项序号，仅在客户端转换加密')
        if command == 'export':
            sub.add_argument('--out', required=True)
        if command == 'publish':
            sub.add_argument('--result', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'init':
            from network_setup import initialize_network
            password = sys.stdin.readline().rstrip('\r\n') if args.password_stdin else getpass.getpass('保管口令（至少8字符）：')
            if not args.password_stdin and password != getpass.getpass('再次输入保管口令：'):
                raise VoteError('两次口令不一致')
            result = initialize_network(args.out, args.title, args.options.replace('，', ',').split(','), args.voters, password)
        elif args.command == 'serve':
            from network_server import serve
            serve(args.data, args.host, args.port)
            return 0
        elif args.command == 'decrypt':
            from network_trustee import decrypt_bundle
            password = sys.stdin.readline().rstrip('\r\n') if args.password_stdin else getpass.getpass('保管口令：')
            result = decrypt_bundle(args.data, read_json(args.bundle, 256_000_000), password)
            write_json(args.out, result)
        else:
            from network_client import NetworkClient
            client = NetworkClient(args.host, args.port, read_json(args.ticket, 16000))
            client.connect()
            if args.command == 'cast':
                receipt = client.vote(args.choice-1)
                result = {'receipt': receipt, 'client_metrics': client.last_vote_metrics}
            elif args.command == 'status': result = {'status': client.status(), 'me': client.me()}
            elif args.command == 'close': result = client.close()
            elif args.command == 'publish': result = client.publish(read_json(args.result, 128000))
            else:
                result = client.export()
                write_json(args.out, result)
                result = {'saved': args.out, 'accepted': result['aggregate']['accepted']}
        print(json.dumps(result, ensure_ascii=True), flush=True)
        return 0
    except (VoteError, OSError, ValueError) as exc:
        print('操作失败：'+str(exc), file=sys.stderr)
        return 1
