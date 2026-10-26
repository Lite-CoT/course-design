# 基于同态加密的隐私保护投票系统

专业课程设计第一题。Python/Qt 桌面程序使用 Paillier 加密单选独热向量，公开计票端只做密文乘法，投票关闭后由独立进程核对完整汇总并解密总票数。支持 2–8 个选项、1–10000 个名单 ID，以及重复投票、ID、签名清单和文件删改校验。

## 安装和启动

在 Windows 10/11、Python 3.12 下，从仓库根目录运行 PowerShell：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe src/main.py
```

不必激活环境，不必更改 PowerShell 执行策略。安装依赖需要联网；正常投票和测试不访问网络。私钥保管口令至少 8 个字符，创建页会在所选目录下新建投票子目录。

## 复测

```powershell
# 核心用例及 10 人三次性能实验
.\.venv\Scripts\python.exe src/main.py --experiments outputs/quick --quick
# 10、100、1000 人，各三次；结果和原始重复数据写入指定目录
.\.venv\Scripts\python.exe src/main.py --experiments outputs/full
# 实际 Qt 控件点击、后台线程、解密子进程和审计演示
.\.venv\Scripts\python.exe src/main.py --ui-smoke outputs/ui-run-1
```

界面测试每次使用新的输出目录，以免覆盖示例投票。实验输入是合成选票；固定种子只用于生成预期明文，Paillier 加密仍使用系统随机数。性能数据计量加密、密文汇总和解密原语，不包含文件读写、签名、口令派生和界面耗时。

## 文件和角色

| 位置 | 用途 |
| --- | --- |
| `src/crypto_service.py` | A：独热编码、Paillier、加密密钥保管库 |
| `src/tally_service.py` | B：公开汇总、完整请求复算、受控解密 |
| `src/audit_service.py`、`election_service.py` | C：名单、状态、签名清单和文件审计 |
| `src/app_ui.py`、`ui_smoke.py` | 桌面界面、后台任务和界面集成测试 |
| `reports/` | 三份分别侧重 A/B/C 模块的 Word 报告 |
| `docs/首次审查.md` | 任务书及模板对照、修改前发现的问题 |
| `docs/验收记录.md` | 修订后的完成情况、格式复核、测试与待完成环节 |
| `docs/现场验收.md` | 随机输入、失败案例、现场小改与个人记录步骤 |
| `AI使用声明.txt` | 辅助范围、可追溯记录和个人复核填写区 |

工程问题回归测试：

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

本轮完整结果与正常界面截图在 `evidence/2026-10-27/`；29项核心实验之外的9项回归覆盖公开包泄漏、损坏输入、嵌套额外文件及解密端独立计时。

## Windows 打包

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
.\.venv\Scripts\python.exe -m PyInstaller --noconfirm build_app.spec
.\dist\MiPiaoLab.exe
```

仅在 Windows 上构建 Windows 程序。可执行文件位于 `dist/`，依赖和临时构建目录不提交到 Git。本轮已对生成的程序执行 `--experiments` 和 `--ui-smoke`，证据及EXE哈希在 `evidence/2026-10-27/packaged/`；发布或重新构建后同样复测。本轮验证环境为 Windows 11 x64。

打包配置排除 PATH 中可能不兼容的第三方 ICU，使用 Windows 提供的接口，并收集 GMP 的原生依赖和版本元数据。只有命令行实验通过不足以说明 Qt 界面可启动。

投票目录中的 `public/` 是配置、加密选票与签名清单；`private/trustee.vault` 是口令保护的私钥材料。不要将真实投票目录、口令或保管库提交到 Git。导出公开包后，解压得到包含 `public/` 的根目录，可交给无私钥计票端。

## 使用边界

多选项指多个候选选项中**单选一个**。修改选项数量时新建轮次，旧轮次选票不能混用。界面不提供单票解密，但持有完整私钥的人可以另写程序解密；一人投票时总票也会暴露该人的选择。名单 ID 不是身份认证；公开元数据可见 ID 和时间。当前没有零知识证明、门限解密和外部回滚检查点，仅用于单机、单写入者的课程实验。

## 提交材料

每人应提交自己的报告和源码，并根据真实参与填写姓名、学号和复核记录。组内保留完整 Git 历史、模块分工、AI 声明和测试证据。查看本轮细分修改：

```powershell
git log --reverse --oneline 891daec..HEAD
```

现场随机数据、本人解释与现场小改需要实际验收，仓库内自动测试不能替代这些环节。

## 报告修订复现

`tools/revise_reports.py --role A`（也可选B/C）使用 `python-docx` 和 `Pillow`，从Git基线 `891daec`、本轮证据及角色修订内容重新生成指定报告。该脚本用于复现本次修订，会覆盖相应Word文件；填写个人信息后应在Word中继续编辑，或先把个人修改保存为Git提交。每次再修改报告都应重新用Word导出PDF并检查全部页面。最终三份报告各10页，版式与数据核对结果见 `evidence/2026-10-27/report-review.json`。
