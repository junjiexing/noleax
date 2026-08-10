# LD_PRELOAD 启动注入（Linux）

> 注入方式：`ld-preload`，仅 `run`
> 状态：已实现（Linux 移植 M3）

## 1. 目的与适用范围

Linux 下启动注入要回答的问题与 Windows 相同：agent 必须在目标入口点之前就绪。LD_PRELOAD
天然满足——动态链接器在装载阶段就加载 agent 并运行其 constructor，早于目标主镜像的任何
初始化代码。因此 Linux 只提供这一种启动注入；`remote-thread`/`thread-hijack`/
`entrypoint-code`/`static-pe-patch` 在 Linux 上以退出码 5 拒绝，`attach`（M6）另有
ptrace 通道。

适用边界（写入排错文档）：setuid/secure-exec 目标忽略 LD_PRELOAD（glibc 的
`AT_SECURE` 规则）；静态链接目标没有动态装载过程；两者都在 doctor/校验阶段识别并拒绝。

## 2. 通道与参数传递

Windows 用 `WriteProcessMemory` 写入固定 ABI 的 `BootstrapParameters`；Linux 有环境变量
这个天然通道，不需要远程写内存：

| 环境变量 | 内容 |
|---|---|
| `NOLEAX_BOOTSTRAP_SOCKET` | 抽象命名空间 socket 名（不含前导 NUL） |
| `NOLEAX_SESSION_TOKEN` | 16 字节会话 token 的 32 位十六进制 |
| `NOLEAX_CONTROLLER_PID` | 控制器 PID（对端校验） |
| `NOLEAX_CONNECT_TIMEOUT_MS` | bootstrap 连接超时（默认 10000） |
| `NOLEAX_AGENT_CONFIG` | standalone 模式的捕获 TOML 路径 |

agent 的 constructor 读取后**立即 unsetenv 全部五个变量**：LD_PRELOAD 会随 env 传给目标的
子进程，不 scrub 的话孙子进程会重复 bootstrap 并连上已关闭的会话。

token 由控制器用 `getrandom(2)` 生成，同时决定 socket 名（`make_socket_name`，见
[IPC_PROTOCOL.md](IPC_PROTOCOL.md) §4），agent hello 必须回显同一 token——监听端只接受
一次连接，token/ABI/架构/指针宽度任一不符即失败。

## 3. 流程

1. 控制器建 `UnixSocketServer`（抽象名，listen backlog 1）。
2. `fork`；子进程合并环境（覆盖式写入上表变量，`LD_PRELOAD=<agent.so 绝对路径>`）、
   `chdir` 到工作目录、`execve` 目标。exec 失败经 CLOEXEC 管道回传 errno。
3. 装载期：ld.so 加载 agent → constructor 读 env、scrub、拉起会话 worker 线程。
4. worker 连接会话 socket，校验对端 PID，发送 `AgentHello`（ABI 版本、PID、worker TID、
   指针宽度、架构、token）。
5. 控制器校验 hello（token/ABI/架构/指针宽度/对端 PID=目标 PID），下发
   `StartCaptureRequest`（capture 配置全量）。
6. agent 安装 hook、启动 writer，回 `CaptureReady`；此后目标主线程才开始跑入口代码——
   与 Windows"入口点前注入"的时序等价。

`--live` 与默认模式共用这一条会话通道（与 Windows 的双通道不同）：

- 默认模式：控制器在目标退出或 duration 到达前仅等待；目标退出时 agent 自行收尾
  （exit hook 见下）。Ctrl+C → 控制器 detach（关闭会话），**agent 继续捕获直到目标退出**；
  会话断开不停止捕获。
- `--live`：控制器可 QueryStatus 轮询；Ctrl+C → StopCapture → drained → FinalizeHooks →
  finalized 握手。

## 4. 目标退出时的收尾

控制器无法替代进程内收尾（waitpid 只在进程死亡后触发，太晚）。agent 侧保证：

- 目标调用 `exit`（含从 main return）时，agent 钩住的 `exit` 替换函数先执行收尾
  （停止记录 → writer 排水 → flush → 关闭 trace），再转交原函数。
- `_exit`/`_Exit` 走另一条同构 hook；`abort`/信号死亡无法收尾——trace 截断，走
  [TRACE_RECOVERY.md](TRACE_RECOVERY.md) 的既有恢复语义（退出码 2/4）。
- duration 到期：controller 驱动的 stop/finalize 握手结束后目标继续运行，hook 已卸载。

## 5. 与 Windows 四种启动注入的对照

| Windows | Linux 对应 | 说明 |
|---|---|---|
| remote-thread | —（不需要） | LD_PRELOAD 覆盖启动期加载 |
| thread-hijack | —（run 不需要；attach 见 ptrace 文档） | 无线程选择问题 |
| entrypoint-code | LD_PRELOAD constructor | 时序保证相同，无代码改写 |
| static-pe-patch | 本期不做 | standalone 由 `LD_PRELOAD + NOLEAX_AGENT_CONFIG` 直接覆盖 |

## 6. 验证

- `tests/integration/linux_agent_bootstrap_test.cpp`：harness 扮控制器，LD_PRELOAD
  `/bin/sleep`，校验 hello 全字段、StartCapture 错误路径、错误 PID 拒绝。
- M3 端到端：`noleax run --hook-profile linux-glibc-heap` 对工作负载目标产出完整
  trace（见 [LINUX_HOOK_PROFILES.md](LINUX_HOOK_PROFILES.md) 验证节）。
