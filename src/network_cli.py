"""Explicit network roles; passwords are read interactively, never sent to server."""
import argparse
import getpass
import json
import sys
from common import VoteError, read_json, write_json

COMMANDS = {'init', 'serve', 'cast', 'status', 'close', 'export', 'decrypt', 'publish', 'challenge'}


def run(argv):
    parser = argparse.ArgumentParser(description='密票实验室：局域网密文投票')
    commands = parser.add_subparsers(dest='command', required=True)
    challenge = commands.add_parser('challenge', help='隔离的随机票型、同态性质、边界与性能验证')
    challenge.add_argument('--out', required=True, help='新的空证据目录')
    challenge.add_argument('--seed', type=int, help='只控制测试输入；不固定密码学随机数')
    challenge.add_argument('--rounds', type=int, default=7)
    challenge.add_argument('--max-voters', type=int, default=30)
    challenge.add_argument('--sizes', default='10,100,1000', help='纯算法性能人数，逗号分隔；空串可跳过')
    challenge.add_argument('--network-sizes', default='10,100', help='真实TLS顺序投票人数；空串可跳过')
    challenge.add_argument('--repeats', type=int, default=3)
    challenge.add_argument('--fixture', help='教师现场指定的JSON测试数据，仅在临时轮次使用')
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
        if args.command == 'challenge':
            from challenge_checks import run_challenges
            sizes = lambda text: tuple(int(x) for x in text.split(',') if x.strip())
            report = run_challenges(args.out, seed=args.seed, random_rounds=args.rounds,
                max_voters=args.max_voters, primitive_sizes=sizes(args.sizes),
                network_sizes=sizes(args.network_sizes), repeats=args.repeats, fixture=args.fixture)
            print(json.dumps({key: report[key] for key in ('seed', 'completed_checks', 'failed_checks', 'passed')}, ensure_ascii=True))
            return 0 if report['passed'] else 1
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
