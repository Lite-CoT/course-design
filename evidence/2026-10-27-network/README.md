# 2026年10月27日联网版本实际证据

- regressions.txt：18项联网测试＋9项既有回归，27项全部通过。边界测试使用1024位密钥以缩短耗时；端到端验证使用2048位。
- source/network-processes.json：源码模式下，1个服务器、6个独立投票客户端、独立保管端及管理员/查询进程的真实TLS流程、计时和源码SHA-256。
- packaged/network-processes.json：最终EXE重复上述流程，包括EXE哈希、关闭/重复拒绝、发布后查询与服务重启恢复。
- 两个目录中的public-bundle.json、signed-result.json：对应运行的公开密文集合、服务器签名清单与保管端签名总票。所有ID和选择均为合成输入。
- ui/：源码Qt界面实际截图与network-ui.json；2个窗口、6次控件投票。窗口共享一个GUI进程，独立客户端进程验证由前述工具单独完成。
- packaged/ui/：最终EXE的对应Qt界面证据。
- report-review.json：最终三份DOCX的页数、哈希、版式和数值核对记录。

运行环境为本机Windows 11 x64，网络为127.0.0.1上的真实HTTPS。记录不声称已在两台物理电脑上验收。服务器监听地址、端口可配置，跨机操作步骤见README及现场清单。

JSON时间使用UTC，目录日期按北京时间标注。一次并发测量存在CPU竞争，不用来推断生产吞吐量。逐端encrypt_ms只包含本端选票构造与随机加密；submit_roundtrip_ms包含TLS、服务器登记与响应；server_aggregation_ms和trustee_decrypt_ms分别只计列乘积和总票解密。进程wall_ms另含启动和配置校验。目录中不包含票码凭证、保管库或TLS/签名私钥。

首轮打包进程测试因管道编码失败，后续构建曾因未结束的测试子进程占用而失败；已修复输出编码和测试清理。这里保存的是最终成功运行的记录。此前单机证据保留在相邻2026-10-27目录，不覆盖、不冒充联网数据。
