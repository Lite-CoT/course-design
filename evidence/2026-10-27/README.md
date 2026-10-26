# 2026年10月27日复测证据

来源：本地 Windows 实际执行，不是教师私有数据或学生现场验收结果。源码基线为 `1c338a1`；`full/experiment_results.json` 的 `source_files_sha256` 逐文件记录被测源码，可再次核对。

- `full/experiment_results.json`：29 项用例、实际依赖版本、环境、10/100/1000 人各三次原始计时及总票。
- `full/test_cases.csv`：用例期望的实际结果。名称含“局限”的通过，表示复现了缺陷边界，不表示已经防御该风险。
- `full/performance.csv`：三次计时均值，单位毫秒。只统计 Paillier 原语，不含文件、签名、KDF、进程或 GUI。
- `full/baseline_result.json`：六张合成票 `[0,1,0,2,0,1]` 的结果 `[3,2,1]`；此处审计和汇总耗时来自解密端复算。
- `ui/ui_smoke.json` 与四张 PNG：原生 Windows Qt 控件测试、独立解密子进程、篡改和删除演示。截图由 `window.grab()` 生成。

执行命令见仓库 README。运行期间不是独占机器，部分时间进行了文档检查和界面测试，因此均值只表示本机本次结果。时间戳在 JSON 中使用 UTC；目录日期按北京时间标注。加密随机数未固定，重新执行时密文及耗时应不同。

目录不包含示例投票的私钥保管库，不保留真实人员数据。无字体的 Qt offscreen 平台初次渲染不适合作为视觉证据，已改用 Windows 原生平台复跑并仅保留正常截图。
