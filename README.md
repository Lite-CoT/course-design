# 基于同态加密的局域网电子投票系统

客户端输入服务器 **IP＋端口**，在本端将选择随机加密后提交。服务器只有Paillier公钥，以密文乘法统计各选项总票；关闭后，独立保管端复核完整汇总并解密、签署总票。服务器公布签名结果，客户端验证后显示。

支持局域网多台电脑，也可在本机打开多个客户端窗口连接同一个端口。默认启动联网客户端；原单机界面通过 --local-demo 保留为算法实验工具。原单机阶段的整体完成判断已在[架构修正](docs/联网架构.md)中纠正。

## 安装

本轮验证Windows 11 x64、Python 3.12，在仓库根目录PowerShell执行：

~~~powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
~~~

使用本机构建的EXE时，以下命令中的“.\.venv\Scripts\python.exe src/main.py”可整体替换为“.\dist\MiPiaoLab.exe”。

## 1. 初始化并分发目录

在组织者/保管者电脑运行一次，交互输入保管口令；新轮次使用新目录：

~~~powershell
.\.venv\Scripts\python.exe src/main.py init --out network-data/demo --title "班级方案投票" --options "同意,反对,弃权" --voters 8
~~~

| 生成目录 | 交给谁 | 内容 |
| --- | --- | --- |
| network-data/demo/server/ | 服务器电脑 | 公钥配置、密文数据库、TLS及登记签名密钥；无Paillier私钥 |
| network-data/demo/trustee/ | 独立保管者 | 可信配置、口令保护的Paillier私钥和结果签名密钥、批准记录 |
| organizer/admin.ticket.json | 管理员 | 关闭投票、导出汇总和发布签名结果的凭证 |
| organizer/voters/V0001.ticket.json 等 | 分别交对应投票人 | 绑定ID的独立票码、服务器证书指纹和配置摘要 |

后两行相对于初始化输出目录。实际分机部署时，**只复制server目录到服务器**，保管者保留trustee目录。不要把保管口令输入服务器或投票客户端。每人只拿自己的凭证。凭证和运行数据已列入Git忽略规则。

## 2. 启动服务器

~~~powershell
.\.venv\Scripts\python.exe src/main.py serve --data network-data/demo/server --host 0.0.0.0 --port 8443
~~~

保持此终端运行，Ctrl+C停止。0.0.0.0表示监听本机各IPv4接口，不是客户端应填写的地址。

- 本机多端：各窗口填写127.0.0.1和8443。
- 局域网：服务器运行ipconfig查看当前网卡IPv4地址，其他电脑填写该地址和相同端口。Windows防火墙需要允许该程序或所选TCP端口在当前网络接收连接；校园网访客隔离可能阻止设备互访。
- 使用HTTPS。客户端在发送票码和选票前核对凭证中的证书指纹，通过组织者分发的凭证建立信任，无需浏览器或导入系统证书。

## 3. 多端投票

~~~powershell
.\.venv\Scripts\python.exe src/main.py
~~~

各端填写IP、端口，导入本人的Vxxxx.ticket.json，点击“连接服务器”，选择一个选项并点击“在本端加密并提交选票”。回执会验证服务器签名与本端密文摘要。

本机演示时重复启动客户端，分别导入不同凭证。服务器在SQLite事务中检查凭证绑定ID和重复投票；同一ID同时提交只接收一次。连接中断后先刷新状态与回执，避免将已接收但响应丢失的选票误判为未投。

支持2–8个选项中的单选、1–10000个名单ID。改变人数或选项数量时初始化新轮次。

## 4. 关闭、解密总票并发布

管理员也打开客户端，导入admin.ticket.json后会出现管理员按钮：

1. 所有人提交后，点击“关闭投票”，再“导出密文汇总”，保存为密文汇总.json。
2. 将公开汇总文件交给独立保管者，在保管者电脑运行：

~~~powershell
.\.venv\Scripts\python.exe src/main.py decrypt --data network-data/demo/trustee --bundle "密文汇总.json" --out "签名总票.json"
~~~

3. 保管者交互输入口令。程序核验可信配置、签名清单、选票集合与密文乘积，只解密完整汇总，输出签名总票。
4. 管理员拿回签名总票.json，点击“发布签名结果”。各端刷新后显示已验证的总票。

服务器没有接收Paillier私钥、保管口令或单票明文的接口。同一保管目录只批准一个确定的关闭汇总；相同汇总再次处理返回原结果，不再批准其他集合。保管端的approved-result.json应一并备份。

## 复测与证据

~~~powershell
# 18项联网测试＋15项任务书挑战回归＋9项既有工程回归
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
# 服务器＋6个独立客户端进程＋离线保管进程；每次使用新的work目录
.\.venv\Scripts\python.exe tools/verify_network.py --work work/check-1 --evidence outputs/network
# 两个真实Qt窗口通过TLS端口完成6次控件投票
.\.venv\Scripts\python.exe src/main.py --network-ui-smoke outputs/gui-check-1
# 原有密码学性质和边界实验
.\.venv\Scripts\python.exe src/main.py --experiments outputs/crypto --quick
~~~

联网原始证据位于evidence/2026-10-27-network/，包含进程数、实际计时、签名结果、截图与源码哈希。自动验收在同一电脑通过真实TLS连接完成；跨物理电脑的连通性按[现场步骤](docs/现场验收.md)复核。历史单机证据保留于evidence/2026-10-27/，不混作联网验收。

任务书五项针对性验证见[随机验收与口试说明](docs/抗AI随机验收.md)和[测试修复记录](docs/针对性测试记录.md)。可现场生成新参数或导入教师JSON数据：

~~~powershell
.\.venv\Scripts\python.exe src/main.py challenge --out outputs/现场随机01 --rounds 7 --max-voters 47 --sizes 10 --network-sizes 10 --repeats 1
~~~

省略seed时每次生成新测试种子；该种子不控制密钥或加密随机数。当前新增证据保存在evidence/2026-10-27-challenges/，旧报告和旧证据中的计时仍属于其记录的历史版本。

## Windows打包

~~~powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
.\.venv\Scripts\python.exe -m PyInstaller --noconfirm build_app.spec
.\.venv\Scripts\python.exe tools/verify_network.py --exe dist/MiPiaoLab.exe --work work/exe-check-1 --evidence outputs/exe-network
.\dist\MiPiaoLab.exe --network-ui-smoke outputs/exe-gui-check-1
~~~

EXE支持相同的init、serve、decrypt命令和默认客户端界面。保留控制台用于服务器状态和口令输入；票码从凭证文件加载，口令默认交互读取。--password-stdin供自动测试使用，口令不会作为命令行参数或网络字段传递。

## 模块与边界

| 角色 | 主要模块 |
| --- | --- |
| A：本端加密、初始化与密钥分离 | crypto_service.py、network_setup.py、network_client.py |
| B：完整汇总、受控解密和结果签名 | network_protocol.py、network_trustee.py |
| C：网络接口、事务登记与可视化 | network_store.py、network_server.py、network_ui.py、network_cli.py |

保护目标是个人选择不被无私钥的服务器直接解密；ID、时间等元数据仍可见。凭证由组织者分发，丢失或转交可能导致冒用。当前没有独热零知识证明、门限解密、独立透明日志及生产级抗拒绝服务措施。一次批准限制不能单独证明恶意服务器没有重签删票集合，仍需独立回执或见证核对；完整私钥持有者可另行解密单票，小群体总票也可能暴露选择。

三份报告、AI声明和[联网验收记录](docs/联网验收记录.md)与本实现配套。姓名、学号、真实贡献及教师现场结果由本人填写。查看细分提交：git log --reverse --oneline 891daec..HEAD。
