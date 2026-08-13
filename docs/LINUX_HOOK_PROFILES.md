# Linux Hook Profiles

> 范围：registry、profile 选择、热路径过滤、统计与停止顺序（Linux 侧）
> 状态：已实现（Linux 移植 M3）

## 1. 单一 registry

产品代码只维护一份 Linux hook registry（`include/noleax/agent/linux/hook_registry.hpp`）。
每项给出稳定 `api_id`、规范名称、模块与物理 export；profile 协调器、writer 和测试均以此表
为边界。Windows 内建占用 api_id 1–9，Linux 内建从 10 起；自定义 hook 沿用共享的
`kCustomHookApiIdBase = 0x1000`。

| api_id | 规范 API | 物理 export | 组 | `capture.min_size` |
|---:|---|---|---|---|
| 10 | malloc | malloc | glibc Heap | 是 |
| 11 | calloc | calloc | glibc Heap | 是 |
| 12 | realloc | realloc | glibc Heap | 否 |
| 13 | free | free | glibc Heap | 否 |
| 14 | posix_memalign | posix_memalign | glibc Heap | 是 |
| 15 | aligned_alloc | aligned_alloc | glibc Heap | 是 |
| 16 | memalign | memalign | glibc Heap | 是 |
| 17 | reallocarray | reallocarray | glibc Heap | 否 |

自动测试双向检查 registry 与实现一一对应，并确认所有物理 export 都能从 `libc.so.6`
解析（`tests/unit/hook_backend_posix_test.cpp` 的 target matrix 用例）。

## 2. Profile

| profile | 逻辑 API |
|---|---|
| `linux-glibc-heap` | 10–17（malloc 族全部） |
| `linux-virtual-memory` | 18–20（mmap/munmap/mremap） |
| `linux-native` | 两组并集 |

虚拟内存组的 mmap 语义（匿名/文件映射的记录类型选择、mremap 的代际展开）见
[LINUX_HOOK_API_MATRIX.md](LINUX_HOOK_API_MATRIX.md) §5。

## 3. 覆盖语义（与 Windows 的关键差异）

Windows 版选择 ntdll Rtl/Nt 作为一切分配路径的隘口；Linux 没有等价单一隘口，本 profile 以
glibc 公开符号为隘口。实测确认（glibc 2.43，`nm -D` 地址比对 + hook 实证）：

- `__libc_malloc` 等隐藏别名与公开符号**同地址**，inline hook 打在共享代码入口上——libc
  内部走 `__libc_*` 的分配（fopen 缓冲区、strdup 等）**同样被记录**。这比 LD_PRELOAD 符号
  覆盖方案的覆盖面大（后者拦不到 hidden alias 调用）。
- 公开符号之间的内部互调（`reallocarray` → `realloc@plt`、`memalign`/`aligned_alloc` →
  共享实现）在双 hook 下由 **guard 递归抑制**保证单事件：内层入口分类为 recursive，只计数
  不记录。reallocarray 调用只产生 reallocarray 事件。
- 明确不覆盖（与 Windows "只覆盖 Rtl/Nt" 同类边界）：ld.so 私有最小分配器（bootstrap 早期
  窗口）、目标直接 `syscall(SYS_*)`、非 glibc 体系分配器（jemalloc/mimalloc，M7 自定义
  hook 场景）、静态链接目标（LD_PRELOAD 不适用）、glibc 分配器自身的 arena 增长
  （brk/mmap 内部路径——不是应用分配，属预期排除）。

## 4. 通用合同

每个 adapter 必须（与 [HOOK_API_MATRIX.md](HOOK_API_MATRIX.md) §2 同构）：

- 使用与 System V AMD64 ABI 匹配的函数类型。
- 使用 Hoox replace_fast 获得 original trampoline（短序言目标自动走 near-redirect 回退）。
- 调用 original 恰好一次。
- 在 original 返回后保存 errno，记录完成后恢复（posix_memalign 不设 errno，返回码原样
  透传）。
- 不在 replacement 中分配 heap、解析符号、写文件或等待阻塞锁。
- 只写入预分配事件队列。
- 提供独立 in-flight counter 与统计计数。
- 支持两阶段停止（逻辑停录 → 物理卸载），替换函数全部位于 `.nlxhk` 段（patch
  rendezvous 覆盖）。

## 4.1 停止顺序与 quiescence 预算（H1-A）

所有 quiescence 等待（`GlibcHeapHooks`/`VirtualMemoryHooks`/`LinuxCustomSymbolHooks` 的
`stop_recording`/`uninstall`/`flush`，以及 `HookBackend` 的 flush/uninstall/shutdown）一律使用
`std::chrono::steady_clock` 绝对 deadline 参数：等待方睡眠在 quiescence epoch 上（Linux 为
`FUTEX_WAIT_BITSET` 绝对超时，Windows 为 `WaitOnAddress`），任一被等待计数归零时由
zero-transition notify 唤醒——**不再有 yield 计数自旋**。每个等待返回 bool；deadline 耗尽
必须走安全回退（保留 patch、上报不完整），绝不无限忙等。预算常量：
`kDefaultQuiescenceBudget`（30 s，单次 teardown 操作）与 `kDrainQuiescenceBudget`
（120 s，capture stop 的 drain——不可重试，必须等完慢的在飞行调用）；测试接缝
`NOLEAX_DRAIN_BUDGET_MS` 可在 bootstrap 缩小 drain 预算。

capture 生命周期在 IPC 显式可见（`AgentState`，见 [IPC_PROTOCOL.md](IPC_PROTOCOL.md)）：

- **逻辑停止（drain）**：`kCapturing → kDraining → kDrained`。全部 profile 先路由
  `record → original`，再在共享 drain deadline 内等 `recording_in_flight` 归零，最后 writer
  final drain、写 Statistics/EndOfTrace。超时：置 `CaptureStatus.flags` 的
  `kDrainIncomplete`，照常收尾；仍在飞行的调用迟到后只能写进已退役的队列（事件不被消费），
  其计数残差由 writer 对账 fail-closed 兜住（error tail + `.partial`，trace 保留到停止点）。
- **物理卸载（finalize，仅 launch）**：`kDrained → kUnpatching → kFinalized`。逐一 revert、
  等待完整 in-flight 归零、释放 lease、backend flush/shutdown。任一步在
  `kDefaultQuiescenceBudget` 内无法证明完成：不崩溃、不无限重试，落 `kDormant` 并置
  `kUnpatchIncomplete`（已 revert 的 target 保持恢复，hook 对象与 trampoline 按进程生命期
  保留）。
- **attach 捕获从不 live-unpatch**：ptrace 停核窗口之外没有安全的运行中撤钩，finalize 直接
  `kDrained → kDormant`——patch 保持安装但已 dormant（drain 已把 replacement 路由回
  original，目标正常续跑）。`unload_on_stop` 因此在 Linux 上被配置校验与 agent 双侧拒绝
  （错误码 7）。
- **standalone duration 与进程退出路径只做 drain-only 收尾**（目标继续运行/正在退出，patch
  dormant），状态落 `kDormant`；`kFinalized` 只出现在 launch 捕获的 controller 驱动
  finalize 之后。

逐 API 语义（calloc 溢出检查时机、realloc(p,0)、free(NULL)、posix_memalign 返回码等）
见 [LINUX_HOOK_API_MATRIX.md](LINUX_HOOK_API_MATRIX.md)。

## 5. 统计守恒

与 Windows 相同的不变式，逐 api_id 成立：

- `observed == successful + failed`
- `observed == written + filtered + dropped`（written 为成功事件入队数）

writer finalize 时对账，不符即失败（trace 不带出）。

## 6. 验证

- hook 合同探针：`tests/integration/linux_glibc_heap_hooks_probe.cpp`（字段、计数对账、
  递归抑制、多线程）。
- 端到端：`noleax run --hook-profile linux-glibc-heap` 对工作负载目标的捕获产物经
  `analyze` 三模式校验（见 tests 的 Linux e2e）。
