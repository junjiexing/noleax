# Controller/Agent IPC Protocol

> 传输：仅限本机的 overlapped named pipe

## 1. Frame

每条消息由 32-byte little-endian header 和至多 64 KiB payload 组成。header 固定包含 `NLXP`
magic、major/minor、header size、message type、flags、非零 request ID、payload size 和 reserved。
接收方在分配 payload 前验证全部字段：major 必须等于 1，minor 不得高于当前实现，flags/reserved
必须为零，类型必须已知，payload size 不得超过上限。实际 frame 必须与声明长度完全一致。

协议字符串使用 `uint32 length + UTF-8 bytes`，单个字符串最多 32 KiB，禁止内嵌 NUL。所有 payload
decoder 必须消费完整输入，拒绝截断和尾随数据。

## 2. 消息状态机

| 消息 | 方向 | 用途 |
|---|---|---|
| `AgentHello` | agent → controller | ABI、PID、worker TID、架构和 session token |
| `StartCapture` | controller → agent | profile、栈深、过滤、buffer、trace、压缩配置、内存快照间隔和 custom_hooks |
| `CaptureReady` | agent → controller | hook 与 writer 已 ready |
| `QueryStatus` / `CaptureStatus` | controller ↔ agent | 生命周期和守恒计数 |
| `StopCapture` / `CaptureDrained` | controller ↔ agent | 逻辑停录与 writer final drain |
| `FinalizeHooks` / `CaptureFinalized` | controller ↔ agent | 目标线程暂停后的物理 revert |
| `Error` | 双向 | 稳定错误码、系统错误和消息 |

停止使用两阶段消息，保持安全顺序：agent 先停止新事件并完成 trace，controller 随后暂停除
agent worker 外的目标线程，最后才允许物理卸载 hook。

`StartCapture` 的 `custom_hooks` 以 `uint32 count` 加定长元素块编码在既有字段之后（最多 32
点）：每元素含每角色参数位映射（alloc_size_arg、alloc_count_arg、realloc_ptr_arg、
realloc_size_arg、free_ptr_arg、result_arg、free_size_arg，可选项为 0xFF）、calloc/forced
标志、wait_module_ms、三个角色的定位（none/export/RVA/ELF 符号 + export 名或 RVA；ELF 符号
定位复用 export 名字段承载符号名，仅 Linux）、module 与 label
字符串，以及可选的烘焙映像 identity（timestamp/checksum/image size）。该数组自 ABI 3 起存在；
声明非法（缺 alloc/free、定位冲突、参数位越界、count 超限）在编解码两侧均被拒绝。
安装期失败不再使 `StartCapture` 报错：custom hook 按 hook point 降级安装，失败点写入
trace 的 CustomHookFailure 记录并置 `custom_hook_install_failed`，`CaptureReady` 照常返回；
内置 profile 家族的安装失败仍以 `Error` 上报。

ABI 4 在 `flush_interval_ns` 之后为 `StartCapture` 增加 `memory_counters_interval_ns` 与
`memory_map_interval_ns` 两个 uint64 字段：agent 按各自间隔在 writer 线程采样内存计数器与
虚拟内存 map（0 表示关闭对应采样器）。

ABI 5 把 `custom_hooks` 元素的共享参数位（size_arg/ptr_arg/count_arg）替换为每角色参数位
（alloc_size_arg/alloc_count_arg/realloc_ptr_arg/realloc_size_arg/free_ptr_arg），元素字节序
相应重排；calloc 的一致性约束改为与 alloc_count_arg 配对。定位枚举新增 kElfSymbol（仅
Linux）：符号名经角色的 export 名字段传输，agent 对模块磁盘映像做 symtab/dynsym 流式查找
（必要时经 `.gnu_debuglink` 伴生文件，GNU CRC32 + Build ID 校验）并换算为运行时地址。

ABI 5 在任何发布之前原地扩展 `CaptureStatus`（版本号不升）：在既有字段之后追加五个 uint64
——`queued_events`（队列当前占用）、`queue_capacity`、`queue_high_water_events`（消费侧采
样的占用高水位，队列满丢弃时钉在容量）、`consumed_events`（累计出队数）、
`last_flush_monotonic_ns`（agent writer 上次成功 flush 的 CLOCK_MONOTONIC 纳秒，0 表示从未
flush）。agent 侧尚无队列或 writer 时这些字段为零。编解码仍要求完整消费 payload，两侧同版
本构建因此总是同形。

同为 ABI 5 原地扩展（H1-A）：`CaptureStatus` 再追加一个 uint32 `flags`，携带非致命的
停止/收尾降级——`kCaptureStatusFlagDrainIncomplete`（bit 0：逻辑停止在 drain 预算内没有等到
replacement 静默，仍在飞行的调用与 trace 切断）和 `kCaptureStatusFlagUnpatchIncomplete`
（bit 1：物理拆钩未能在预算内证明完成，patch 保留为 dormant）。`AgentState` 同时追加三个取值
（编解码合法域随之扩到 8）：`kDraining=6`、`kDormant=7`、`kUnpatching=8`。Linux agent 的
显式状态机为：

- `drain()`（StopCapture / standalone duration / 退出钩子）：`kCapturing → kDraining →
  kDrained`；quiescence 超时置 `kDrainIncomplete` 后照常收尾，writer 失败落 `kFailed`。
- `finalize()`（FinalizeHooks）：launch 捕获 `kDrained → kUnpatching → kFinalized`；物理拆钩
  失败（预算耗尽）不崩溃、不无限重试，落 `kDormant` 并置 `kUnpatchIncomplete`。attach 捕获
  从不 live-unpatch（ptrace 停核窗口外没有安全的运行中撤钩），`kDrained → kDormant`，patch
  保持安装但已 dormant（drain 已把 replacement 路由回 original）。
- 进程退出路径只做 drain-only 收尾，状态落 `kDormant`（该路径不做物理拆除，不会到
  `kFinalized`）。

`kDraining`/`kUnpatching` 是瞬态：会话循环顺序处理消息，controller 只能在 drain/finalize
应答里观察到终态；两个瞬态供 QueryStatus 与后续 attach bootstrap（H1-B）的并发观察使用。

`StartCapture` 的 `unload_on_stop` 仅 Windows attach 有意义；Linux agent 以稳定错误码 7
（`kAgentStartErrorUnsupportedOption`）拒绝该请求（CLI 侧在注入前已由
`validate_capture_support` 拒绝，agent 侧防御覆盖手写 controller）。

agent 在 drain 后把 writer 失败映射到会话状态：`CaptureDrained`/`CaptureFinalized` 携带的
`AgentState` 为 `kFailed` 表示 writer 失败（trace 尾部保有细节），controller 据此分类为
writer-error；`StartCapture` 的 `ErrorResponse` 错误码约定为 1=一般 agent 错误、3=内置
profile hook 安装失败、5=不支持的 hook profile、6=trace writer 启动失败（此时
`system_error` 携带 open 阶段的 errno）、7=不支持的捕获选项（如 Linux 上的
`unload_on_stop`）。

## 3. 传输和安全边界

- pipe 名由 128-bit session token 生成，并使用 `PIPE_REJECT_REMOTE_CLIENTS`；
- controller 接受连接后核对 pipe peer PID、`AgentHello.process_id` 和 token；
- connect、accept、header、payload 和 write 都使用同一个调用级 deadline；
- timeout 会执行 `CancelIoEx` 并等待 overlapped I/O 完成，避免栈上 `OVERLAPPED` 生命周期错误；
- broken pipe、部分 header、超长声明、未知版本和保留位均为显式错误，不进入下一状态。

自动测试覆盖 payload/frame round-trip、major/minor、恶意长度、截断、尾随字节、accept timeout、
部分 header timeout、双向传输和 peer PID。

## 4. Linux 传输：抽象命名空间 Unix socket

Linux 侧传输实现为 `noleax::ipc::linux`（`src/ipc/linux/unix_socket.cpp`），帧格式、消息
状态机与安全边界不变：

- 命名：`make_socket_name(token)` 生成抽象命名空间名称（`\0noleax-<hex(token)>`），无文件
  系统痕迹、无需清理；等价于 Windows 的 `\\.\pipe\noleax-<hex>`。
- 对端校验：`SO_PEERCRED` 双向提供对端 PID，替代 `PIPE_REJECT_REMOTE_CLIENTS` + 客户端
  PID 校验；agent 侧拒绝非预期 controller PID 的连接。
- 超时与中断：poll 截止驱动 send/receive/accept 超时；`poll` 不受 `SA_RESTART` 覆盖，
  所有等待显式处理 `EINTR`——park 信号（停核）到达不破坏传输。
- 发送使用 `MSG_NOSIGNAL`（不产生 SIGPIPE）；所有 fd 以 `CLOEXEC` 创建，不泄漏进目标
  exec 后的子进程。
