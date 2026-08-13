# Noleax 故障排查

除标注外，以下内容针对 Windows x64；Linux 故障表见文末 Linux x86-64 章节。先运行
`noleax doctor --target <目标>`，并保留
Noleax 的完整 stderr、退出码和 capture summary。

| 现象 | 常见原因 | 处理方法 |
|---|---|---|
| 返回 3，agent 无法初始化 | 权限不同、目标已退出、安全软件拦截或 agent 不匹配 | 让 Noleax 与目标处于相同权限级别；确认 `noleax-agent.dll` 与 exe 同目录；用 `doctor --target` 检查架构 |
| 返回 5 | 使用了不受支持的平台、架构或方法组合 | 核对注入方法与操作的兼容矩阵（`run`/`attach`/`patch`）；trace rotation 尚未实现；`--unload-on-stop` 仅 attach 支持 |
| attach 返回 2 | 注入前 allocation 不可见 | 这是预期的不完整性标记；需要完整生命周期时改用 `run` |
| analyze 返回 2 但有输出 | trace 达到上限、记录丢失、栈捕获失败或尾部可恢复 | 检查 completeness reasons；增大 buffer/file limit、缩短 workload 或提高 `--capture-min-size` 后重跑 |
| 返回 4 | 文件头/完整 chunk 损坏或 trace major version 不兼容 | 保留原文件，不要手工修补；使用同版本 Noleax 重试并检查存储介质 |
| trace 很快达到上限 | profile 太宽、workload 太长或小 allocation 过多 | 改用 `windows-nt-heap`、设置 `--capture-min-size`、缩短 duration 或增大 `--max-trace-size` |
| outstanding 结果过多 | 时间窗覆盖初始化、缓存或正常长寿命对象 | 把 a 移到预热之后，缩小 `[a,b)`，在更晚的 c 比较，并按大小/API/stack module 过滤 |
| 没有符号名 | PDB 不可用、路径不对或网络 symbol server 不可达 | 使用 `--symbol-path` 指向本地 PDB；需要网络时再显式添加 `--symbol-server` |
| 目标仅在 hook 后崩溃 | 目标、注入或 hook 回归 | 先用同一输入跑未注入基线；改用最小 `windows-nt-heap` profile；保存 dump、Windows 版本和 Noleax 构建信息 |

## Linux x86-64

以下内容针对 Linux x86-64/glibc 目标。先运行 `noleax doctor --target <目标>`——平台、agent
可加载性、目标 ELF 属性（静态链接、setuid）与 ptrace_scope 都会在只读检查中直接报出。

| 现象 | 常见原因 | 处理方法 |
|---|---|---|
| `run` 返回 3，报 `unix socket accept timed out` | 目标是静态链接二进制：没有动态加载器，LD_PRELOAD 不生效，agent 从未加载 | 用 `doctor --target` 确认（静态目标报 `static target: LD_PRELOAD injection is impossible`）；静态目标无法注入，改用动态链接构建 |
| setuid/setgid 目标 `run` 返回 3（与静态目标相同的握手超时） | 提权执行时加载器按 AT_SECURE 规则忽略 LD_PRELOAD，agent 从未加载（属主与调用者相同、不提权时不受影响） | doctor 的 target 检查对 setuid/setgid 位给 warning；以不提权的普通副本运行目标 |
| attach 返回 3（EPERM/EACCES） | ptrace 权限不足：`ptrace_scope=2/3`、跨用户目标或容器 seccomp 拦截 ptrace | 以与目标相同的用户运行；确认 `/proc/sys/kernel/yama/ptrace_scope` 不大于 1，或以 `CAP_SYS_PTRACE` 运行；doctor 的 ptrace-scope 项给出当前状态 |
| attach 报 `wedged inside the agent bootstrap ... must be restarted`（返回 3） | bootstrap 在注入超时 + 一倍 grace 预算后仍未完成：目标被留在 ptrace 停核状态以防内存损坏（injector 没有恢复任何线程的寄存器） | 重启该目标进程；若反复出现，调大 `injection.timeout` 并上报当时的机器负载 |
| 调用栈只显示 module+offset | 目标被 strip：仅剩 `.dynsym` 时非导出函数无法命名（`exports_only`），彻底 strip 则全部如此（`no_symbols`）；或在 Linux 上分析 Windows 录制的 trace | 换用带 `.symtab` 的构建重录；Windows trace 需在 Windows 上分析（Linux 只读 ELF 映像，模块状态为 `image_not_found`/`load_failed`） |
| 安装或收尾卸载 hook 期间目标偶发一次 `EINTR` | 信号停核（park）打断了 `poll`/`select`/`nanosleep` 等慢系统调用；信号以 SA_RESTART 安装，多数调用自动重启，但这几类仍可能向应用返回一次 EINTR | 预期行为，窗口仅停核期间（微秒级）；按 POSIX 规则处理 EINTR 的代码不受影响，不需要处理 |
| Ctrl+C detach 之后捕获不再按 `--capture-duration` 到点停止 | v1 的 duration 定时器由控制器侧驱动，detach 后随之失效，agent 继续捕获到目标退出 | 需要定时停止时保持控制器前台存活；detach 只在你接受"录到目标退出"时使用 |

Linux 的 hook 覆盖边界（libc 内部分配同样被记录、ld.so bootstrap 窗口与直接 syscall 不
覆盖等）见 [LINUX_HOOK_PROFILES.md](LINUX_HOOK_PROFILES.md)；ptrace 注入的已知限制
（RWX stub 页驻留、静态 TLS 盈余等）见
[LINUX_PTRACE_INJECTION.md](LINUX_PTRACE_INJECTION.md) 第 5 节。

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

