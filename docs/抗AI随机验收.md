# 题目一随机验证与代码口试

此文配合任务书的五项检查：随机票型、现场篡改、同态性质、性能数据和边界案例。验证程序实际执行本端加密、TLS提交、服务器密文汇总、保管端解密及结果发布。自动测试可以核对程序行为；教师现场参数、跨电脑连通和每位同学的解释能力仍需本人现场验证。

## 临时参数和私有数据

在仓库根目录运行。使用源码时，将以下 ` .\dist\MiPiaoLab.exe ` 替换为 ` .\.venv\Scripts\python.exe src/main.py `。

```powershell
# 不指定种子，每次生成新种子；7轮依次覆盖2至8个选项
.\dist\MiPiaoLab.exe challenge --out outputs/现场随机01 --rounds 7 --max-voters 47 --sizes 10 --network-sizes 10 --repeats 1
# 用记录下来的种子复现测试输入；输出必须使用新目录
.\dist\MiPiaoLab.exe challenge --out outputs/复现01 --seed 2026102707 --rounds 21 --max-voters 47 --sizes 10,100,1000 --network-sizes 10,100,300 --repeats 3
# 教师可现场编辑或另行提供JSON，文件格式见下文
.\dist\MiPiaoLab.exe challenge --out outputs/私有数据01 --fixture tests/fixtures/challenge-input.json --rounds 0 --sizes 10 --network-sizes 10 --repeats 1
```

`seed`只控制测试人数和选择分布；密钥、Paillier加密随机数、凭证与nonce仍使用密码学随机源，密文不会随种子重复。工具仅在新建临时目录运行，不修改正在使用的投票轮次，不导出私钥或票码。输出包含逐项结果、输入摘要、种子、源码或EXE哈希、原始计时JSON和汇总CSV。失败时进程返回非零退出码，已经完成的检查保留在JSON中。

私有输入格式如下，`choices`使用从0开始的索引，顺序对应临时ID V0001、V0002等；实际投票客户端CLI的`--choice`仍从1开始。`voters`为名单总人数，`choices`可以少于名单人数或为空。当前票型为单选，多选项指候选项数量可变。

```json
{
  "cases": [
    {
      "name": "教师指定五选项",
      "options": ["甲", "乙", "丙", "丁", "弃权"],
      "voters": 8,
      "choices": [4, 0, 2, 4, 1, 4]
    }
  ]
}
```

纸面预期应为`[1,1,1,0,3]`，有效票6，未投2。改变选项数量或选项顺序后必须建立新轮次；旧凭证和旧选票不能跨轮次复用。例子是公开合成数据，不是教师尚未提供的私有测试。

## 现场篡改

运行 `python -m unittest discover -s tests -v` 可重放测试，相关回归在 `tests/test_challenges.py`。所有破坏性操作都在每个用例创建的临时数据库中执行。

| 注入的变化 | 必须观察的结果 | 对应检查 |
| --- | --- | --- |
| 将有效密文乘以g后取模n²，仍留在合法密文空间 | 摘要不匹配，拒绝；不能只靠密文范围判断 | `test_delete_ballot_or_change_ciphertext_inside_valid_group` |
| 删除一张已登记选票 | 清单数量不一致，拒绝审计 | 同上 |
| 只修改SQL的voter_id或nonce列 | 索引与签名选票不一致，拒绝状态查询及后续写入 | `test_database_identity_column_tamper_fails_before_next_write`、`test_database_nonce_column_tamper_is_detected` |
| 修改回执，或给错误选票摘要签名 | 签名/摘要绑定校验失败；重启时也拒绝加载损坏状态 | `test_database_receipt_tamper_is_detected_on_audit_and_restart`、`test_valid_signature_on_wrong_receipt_digest_is_rejected` |
| 删除/替换导出包选票，修改清单、配置、列乘积 | 保管端拒绝，不生成批准记录；原始包仍能通过 | `test_export_tamper_matrix_never_creates_approval` |
| 同一ID并发投8次，或不同ID复用同一nonce | 同ID只成功一次，重复nonce拒绝且不增加票数 | 既有并发测试、`test_reused_nonce_is_rejected_even_with_different_case` |
| 关闭与8个客户端提交同时发生 | 结果等于事务真正接收的集合，其他请求返回409 | `test_concurrent_close_and_votes_produces_exact_committed_set` |

完整性错误也可能来自误编辑、磁盘损坏或不完整复制。恢复原始内容后应重新通过审计；告警说明数据与可信记录不一致，不能单凭告警推断操作者或动机。恶意服务器掌握登记签名密钥时的重签攻击需要单独说明，见下节。

## 同态性质和本人解释

| 现场追问 | 应能写出并对照代码解释的内容 |
| --- | --- |
| 公钥、私钥是什么，在哪生成和保存？ | 生成不同大素数p、q，n=pq，g=n+1；服务器持n和登记签名密钥，保管端持口令保护的p、q及结果签名密钥。TLS私钥不能解密Paillier选票。对照`network_setup.py`。 |
| 为什么可以先汇总后解密？ | `E(m;r)=g^m r^n mod n²`，所以`E(a;r1)×E(b;r2) mod n² = E((a+b) mod n; r1r2 mod n)`。服务器按选项列相乘，对照`aggregate_records`。 |
| 为什么不是直接把密文相加？ | 本实现操作的是原始整数密文，支持明文相加的操作是密文乘法。`phe`高层`EncryptedNumber`的加号重载不是原始整数加号。本程序用`raw_encrypt/raw_decrypt`，不存在浮点编码。 |
| 如何解密？ | 课本表达为λ=lcm(p−1,q−1)，L(x)=(x−1)/n，μ=L(g^λ mod n²)的模n逆元，m=L(c^λ mod n²)μ mod n。所用`phe`库实现等价的CRT加速路径，不能说项目自己实现了整套大整数密码算法。 |
| 相同选择为何密文不同？nonce是否是r？ | 每一维都重新随机加密。公开nonce用于重放检测，不能当加密随机数r；r不会写入选票。现场重复加密1，解释两份密文不同但解密相同。 |
| 平票、弃权与未投票有什么区别？ | 一个选项一列，选择一项编码为独热向量。弃权是被选中的独立列，计入有效票；未提交者不进入密文乘积。空集合每列乘积初值1，解密为0。 |
| 模运算会不会溢出？ | 原始明文在模n环中，(n−1)+1会回绕为0；正常票数上限10000远小于2048位n。不能把任意大整数总和都说成普通整数加法。 |
| 一次批准能解决什么？ | 同一保管目录拒绝第二个不同集合，减少反复查询不同子集总和的机会；无法独自证明首次集合未被恶意服务器删减。 |

`challenge`实际做32组随机a、b、k，验证加法、公开整数数乘、乘上E(0)后的重新随机化，以及模n回绕；另重复加密1共32次检查随机化。代码口试应由成员自己选择例子、追踪执行路径并解释结果，不能把程序输出当作本人已经掌握的证明。

算法API依据：[python-paillier文档](https://python-paillier.readthedocs.io/en/latest/phe.html)。线程调度依据：[Python socketserver文档](https://docs.python.org/3.12/library/socketserver.html)；TLS握手现在在工作线程执行，未完成握手的单个连接不再阻塞监听线程。

## 性能数据怎样读

默认对10、100、1000票执行3次纯算法测试，对10、100票执行3次真实TLS顺序投票。可用`--network-sizes 10,100,300`增加联网规模。每一轮都核对明文预期与解密总票后才记录成功。

- 纯算法`encrypt_ms`是全部N×3个密文的加密总时间，`aggregate_ms`是三个列乘积，`decrypt_ms`是三列总票解密；不含密钥生成、网络、签名、文件和scrypt。
- 联网`encrypt_ms`是各客户端实际加密计时之和；`submit_roundtrip_ms`是提交请求耗时之和。`cast_wall_ms`还包含各端连接、配置、状态和回执核验。
- 联网`aggregate_ms`仍只测服务器密文乘法。`export_wall_ms`包含审计、导出、网络及客户端复核；`trustee_wall_ms`包含复核、scrypt、解密、签名和落盘，不能与纯解密混为一谈。
- 每次原始值保存在JSON；CSV给均值，联网另有最小/最大总投票耗时。不同轮次使用新的密钥和加密随机数，单机回环结果不能推断物理局域网或生产吞吐量。

当前每次读取都会核验已接收集合与回执，因此连续N票的总审计工作约为O(N²)。性能数据保留这一开销，未为了好看的计时跳过验证。10000人名单边界只测试初始化和末尾ID投1票，不代表10000票吞吐已验证。

## 必须如实说明的局限

1. 单人轮次的总票直接揭示该人的选择。加密不能消除公开总和本身的信息。
2. 没有独热零知识证明。合法客户端只产生0/1独热向量，但恶意客户端可以提交加密的`[2,0]`与`[0,0]`；合计`[2,0]`仍满足两票约束。单张`[2,0]`的总票约束失败会被拒绝，两张相互抵消则不能检测。自动记录中将后者标为`limitation_demonstration`，表示局限被复现，不是安全机制通过。
3. 掌握登记签名密钥的服务器可在首次送审前重签删票后的集合。需独立回执见证、外部透明日志等才能加强完整性保证；当前一次批准不能取代这些机制。
4. 完整私钥持有者可绕开本程序解密单票；当前没有门限解密。TLS工作线程修复只解决单连接阻塞，仍不等同于生产级连接限额、限速和抗拒绝服务能力。

这些边界属于系统威胁模型，现场必须解释。修复记录和本轮实测结果见[针对性测试记录](针对性测试记录.md)。
