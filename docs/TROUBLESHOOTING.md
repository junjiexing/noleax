# Noleax 故障排查

以下内容针对 Windows x64 V1 release candidate。先运行 `noleax doctor --target <目标>`，并保留
Noleax 的完整 stderr、退出码和 capture summary。

| 现象 | 常见原因 | 处理方法 |
|---|---|---|
| 返回 3，agent 无法初始化 | 权限不同、目标已退出、安全软件拦截或 agent 不匹配 | 让 Noleax 与目标处于相同权限级别；确认 `noleax-agent.dll` 与 exe 同目录；用 `doctor --target` 检查架构 |
| 返回 5 | 使用了不受支持的平台、架构或方法组合 | 核对注入方法与操作的兼容矩阵（`run`/`attach`/`patch`）；trace rotation 与 unload-on-stop 尚未实现 |
| attach 返回 2 | 注入前 allocation 不可见 | 这是预期的不完整性标记；需要完整生命周期时改用 `run` |
| analyze 返回 2 但有输出 | trace 达到上限、记录丢失、栈捕获失败或尾部可恢复 | 检查 completeness reasons；增大 buffer/file limit、缩短 workload 或提高 `--capture-min-size` 后重跑 |
| 返回 4 | 文件头/完整 chunk 损坏或 trace major version 不兼容 | 保留原文件，不要手工修补；使用同版本 Noleax 重试并检查存储介质 |
| trace 很快达到上限 | profile 太宽、workload 太长或小 allocation 过多 | 改用 `windows-nt-heap`、设置 `--capture-min-size`、缩短 duration 或增大 `--max-trace-size` |
| outstanding 结果过多 | 时间窗覆盖初始化、缓存或正常长寿命对象 | 把 a 移到预热之后，缩小 `[a,b)`，在更晚的 c 比较，并按大小/API/stack module 过滤 |
| 没有符号名 | PDB 不可用、路径不对或网络 symbol server 不可达 | 使用 `--symbol-path` 指向本地 PDB；需要网络时再显式添加 `--symbol-server` |
| 目标仅在 hook 后崩溃 | 目标、注入或 hook 回归 | 先用同一输入跑未注入基线；改用最小 `windows-nt-heap` profile；保存 dump、Windows 版本和 Noleax 构建信息 |

## 权限与安全软件

attach 需要打开目标进程并创建远程线程。跨用户、AppContainer 或更高 integrity
目标可能拒绝访问。管理员权限也不能绕过所有 Windows 保护边界。企业 EDR/防病毒可能将注入行为拦截；
仅在获授权环境中添加例外，不要关闭系统级保护来掩盖问题。

Protected Process / PPL 目标不受支持。Noleax 的安全模型要求枚举并暂停目标进程的全部线程、
读取线程上下文，protected process 会拒绝这些访问（`OpenThread`/`SuspendThread` 返回
`ERROR_ACCESS_DENIED`）。表现为 hook 安装失败（返回错误而非崩溃），或卸载无法完成、插装状态
保留到进程退出。这不是权限提升可以解决的问题，请改用其他观测手段。

## 文件大小与完整性

V1 的 `on_full=stop` 保证单个 trace 不超过 `max_file_size`，但达到上限后不再捕获新事件。summary 和
分析 metadata 会将其标记为不完整。`rotate` 与 `max_files > 1` 尚未实现，指定后返回 5。

trace 包含进程路径、模块、地址、线程活动和 allocation 模式，可能泄露敏感信息。分享 trace 前按
[../SECURITY.md](../SECURITY.md) 的建议处理；不可信 trace 只应交给最新构建的离线 analyzer。

## 收集可复现信息

报告问题时至少提供：

- `noleax --version` 与 `noleax doctor` 输出。
- Windows 版本、目标架构、使用的 profile 和完整命令行（移除密钥）。
- 退出码、capture summary、completeness reasons。
- 未注入基线是否复现，以及最小 workload。
- 可公开时提供 dump 或 trace；不要公开包含秘密或私有符号路径的文件。

公开安全问题的联系方式尚未确定，因此正式外部分发仍受
[SECURITY.md](../SECURITY.md) 中的 release gate 约束。

