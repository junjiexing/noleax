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
点）：每元素含参数位映射（size/ptr/result/count/free_size，未设项为 0xFF）、calloc/forced
标志、wait_module_ms、三个角色的定位（none/export/RVA + export 名或 RVA）、module 与 label
字符串，以及可选的烘焙映像 identity（timestamp/checksum/image size）。该数组自 ABI 3 起存在；
声明非法（缺 alloc/free、定位冲突、参数位越界、count 超限）在编解码两侧均被拒绝。
安装期失败不再使 `StartCapture` 报错：custom hook 按 hook point 降级安装，失败点写入
trace 的 CustomHookFailure 记录并置 `custom_hook_install_failed`，`CaptureReady` 照常返回；
内置 profile 家族的安装失败仍以 `Error` 上报。

ABI 4 在 `flush_interval_ns` 之后为 `StartCapture` 增加 `memory_counters_interval_ns` 与
`memory_map_interval_ns` 两个 uint64 字段：agent 按各自间隔在 writer 线程采样内存计数器与
虚拟内存 map（0 表示关闭对应采样器）。

## 3. 传输和安全边界

- pipe 名由 128-bit session token 生成，并使用 `PIPE_REJECT_REMOTE_CLIENTS`；
- controller 接受连接后核对 pipe peer PID、`AgentHello.process_id` 和 token；
- connect、accept、header、payload 和 write 都使用同一个调用级 deadline；
- timeout 会执行 `CancelIoEx` 并等待 overlapped I/O 完成，避免栈上 `OVERLAPPED` 生命周期错误；
- broken pipe、部分 header、超长声明、未知版本和保留位均为显式错误，不进入下一状态。

自动测试覆盖 payload/frame round-trip、major/minor、恶意长度、截断、尾随字节、accept timeout、
部分 header timeout、双向传输和 peer PID。
