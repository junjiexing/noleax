# Noleax Windows x64 V1 Release Candidate

> 状态：AI 技术门禁完成，等待人工最终验收
>
> 证据日期：2026-07-30
>
> 已验证源码基线：`e819ece06df534170b53c9c6655baa92f37fa839`
>
> 候选分支：`feat/v1-release-candidate`

本文冻结 Windows x64 V1 release candidate 的范围、二进制身份和验收证据。源码基线之后只允许
文档收口；若产品代码、构建配置、依赖锁或打包逻辑发生变化，必须重新执行对应技术门禁。

当前没有 release tag，也没有已批准或保留的发布归档。人工明确验收前不得合并为正式发布、创建
tag 或对外分发二进制。

## 1. 候选范围

V1 支持 Windows 10/11 x64 controller、原生 x64 目标，注入方式为
`remote-thread`、`thread-hijack`、`entrypoint-code`（run/attach 组合按矩阵），以及
`noleax patch` 静态 PE patch 与 `static-pe-patch` 捕获，包括：

- suspended `run` 与运行中 `attach`；
- `windows-nt-heap`、`windows-virtual-memory` 和九个逻辑 API 的 `windows-native` profile；
- 有界 trace、Module/Stack 字典去重、LZ4/Zstd/无压缩编码和明确的完整性状态；
- events 与 a/b/c outstanding 分析、过滤、console/JSON/CSV 输出和离线符号解析；
- CMake/Ninja/vcpkg 构建以及自包含 Windows x64 ZIP 打包。

以下能力明确不属于本候选：

- Windows x86/ARM64、Linux、macOS 和跨架构注入；
- 自定义符号 hook DSL；
- trace rotation、停止时卸载 agent 和多个 trace 联合分析。

不支持的组合在配置或执行前以稳定退出码拒绝，不会静默回退。

## 2. 二进制身份

下表来自干净源码基线的 `windows-x64-release` 构建。RC 使用 `/MT` 和
`x64-windows-static`；Hoox、LZ4、Zstandard 和 MSVC runtime 均静态链接。

| 文件 | 大小 | SHA-256 |
|---|---:|---|
| `noleax.exe` | 1,670,144 B | `7D8FB035A724B68153AE519F37DF4112C90704342A9D14BDD06E15BA64EA8D32` |
| `noleax-agent.dll` | 899,072 B | `EC92DF63FD601557F7CE63477E040E78D12AAED7DE07662F71E65C22E966274D` |

`noleax.exe` 的动态依赖闭包只包含 Windows 提供的 `dbghelp.dll`、`bcrypt.dll`、
`kernel32.dll` 和 `advapi32.dll`；agent 只依赖 `kernel32.dll`。自动 package smoke 同时拒绝动态
MSVC runtime 和包外第三方 DLL。

测试期间生成的 ZIP 与 `.sha256` companion 已删除。人工 clean-machine 验收时必须从候选源码重新
生成临时归档，并记录归档自身的 SHA-256；不能把本表中的单文件哈希当作 ZIP 哈希。

## 3. 最终自动门禁

以下结果均基于干净的 `e819ece` 源码基线：

| 门禁 | 结果 |
|---|---|
| Debug full suite | 230/230，48.02 s |
| Release full suite | 231/231，58.21 s |
| Hardened full suite | 268/268，60.81 s |
| CFG/CET PE metadata | 37/37 images |
| 五个 hook quiescence 目标 runtime mitigation | 每个 `cfg=1 cet=1` |
| allocate/free/reallocate/heap-lifecycle/NT-VM race | 各 100/100，共 500/500 |
| `windows-native` profile stress | 100/100 |
| Hardened MD/MT 8×20,000×2 ABI 差分 | 3/3 |
| Application Verifier/Full Page Heap workload | 3/3 |
| Application Verifier race 集合 | 3 轮全部通过 |
| Application Verifier 13 项组合集合 | 3 轮全部通过 |
| IFEO 清理与日志导出 | 19/19 key 不存在；19 个 XML 共 0 `LogEntry` |
| Release package smoke | staging 与解压 ZIP 各 1/1，工作流 2/2，版权文本 6/6 |

管理员门禁使用 Application Verifier 10.0.26100 x64。它覆盖真实 hook workload、五组 race、writer、
contract、native profile 和 module generation/tracker，并在 `finally` 后确认本轮创建的 IFEO 设置全部
清理。

## 4. RC 专项证据

### 稳定性

`scripts/Test-NoleaxSoak.ps1` 连续 10 轮执行 run、attach、capture lifecycle、native profile 和完整
CLI analyze 工作流：50/50 通过，用时 110.932 s，无 crash、hang 或守恒失败。

### 不可信 trace

正式 corpus 包含 10 个截断、68 个 header bit flip 和 128 个确定性随机变异：206/206 完成，0 timeout、
0 unexpected exit，最大单例 42 ms。退出分布为 44 个完整、6 个可恢复不完整和 156 个无效输入；没有
0/2/4 之外的退出码。

### 静态 runtime 性能复测

一轮 warm-up 加三轮计时的五个 capture case 共生成 15 个完整 trace，全部零丢失。默认 LZ4、64 帧的
目标 workload 中位时间为 4.619 ms，相对 3.100 ms 未注入基线为 1.490x，中位 trace 为 413,467 B。
V1 保持 LZ4 和 64 帧默认值；详细结果见 [PERFORMANCE.md](PERFORMANCE.md)。

原始 JSON 和管理员 transcript 位于被 Git 忽略的 `_temp/reports`，其中包含机器路径，不进入源码或
发布包。可重复命令与验收语义见 [SOAK_TESTING.md](SOAK_TESTING.md)、
[WINDOWS_HOOK_HARDENING.md](WINDOWS_HOOK_HARDENING.md) 和
[SECURITY_AUDIT.md](SECURITY_AUDIT.md)。

## 5. 发布阻塞项

技术门禁完成不等于允许公开发布。以下事项仍需人工决定：

1. 选择 Noleax 自身许可证并确认公开分发范围。
2. 提供可长期使用的非公开安全报告渠道。
3. 决定 Authenticode 签名、证书保管、哈希发布和撤销策略。
4. 在没有 Visual Studio、vcpkg 和源码构建树的干净 Windows x64 VM 上验证 ZIP。
5. 人工接受当前性能开销、CLI/输出体验、已知风险和 V1 支持边界。

逐项操作和签署位置见 [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)。全部完成并获得明确授权后，才可
决定分支合并、版本号冻结、tag 和发布；这些动作不属于本次 P8.7 技术收口。
