# Windows NT Heap Background Trace Writer

> 状态：P5.2 Windows x64 Debug/Release 自动门禁完成
> 范围：NT Heap allocate/reallocate/free 的进程内 trace path、generation 配对和安全停止

## 1. 目标与边界

三个 replacement 只调用 original、保存固定宽度字段、捕获原始 PC 并尝试入队。压缩、容器
分配、文件 I/O、栈去重、allocation_id 配对和 record codec 全部位于后台线程。

当前生成三种规范化事件：

| 原始 API | api_id | 规范化 payload |
|---|---:|---|
| `RtlAllocateHeap` | 1 | `AllocationEvent` |
| `RtlFreeHeap` | 2 | `FreeEvent` |
| `RtlReAllocateHeap` | 3 | `ReallocationEvent` |

`RtlHeapTraceWriter` 是组合模式的公开别名；原有 `RtlAllocateHeapTraceWriter` 单 hook 构造方式仍兼容，
只写 `api_id=1`；alloc/free 构造方式也继续兼容。P5.3 才加入 heap generation，P5.6 前
StackDefinition 仍只保存绝对地址，`module_id` 和 `module_offset` 为零。

## 2. 共享队列与跨 API 顺序

allocate/reallocate/free 使用同一个预分配 `RtlHeapEventQueue`。统一的 600-byte `RtlHeapEvent` 通过
operation 区分三种 API，并包含所需参数、raw result、异常状态和定长栈。成功 reservation 时由队列
分配唯一 sequence，因此不同线程、不同 API 的生命周期顺序不依赖可能倒退或相同的 QPC tick。

三个 hook 分别保存 dropped counter，后台 writer 才能把共享 queue overflow 归因到正确 api_id；底层
queue 的总 dropped counter 只用于队列级诊断。被 queue 拒绝的事件没有 sequence，Loss 因而只保存
数量，不伪造范围。

组合模式的安全调用顺序是：

1. 构造 `HookBackend` 和 `RtlHeapHooks`；后者拥有共享 queue，并让三个 hook 取得各自的固定 TEB
   guard 引用。
2. 在 hook 安装前构造 `RtlHeapTraceWriter`；它校验三个 hook 引用同一个 queue、写 CaptureScope
   metadata，并启动带 `InternalThreadScope` 的 worker。
3. 由 `RtlHeapHooks::install()` 安装 allocate/reallocate/free，再调用 `begin_capture()`。
4. 目标线程产生事件，worker 按共享 sequence 并发 drain。
5. 调用 `RtlHeapHooks::uninstall()`；三个 hook 都完成 revert、replacement quiescence 和 Hoox flush。
6. 调用 writer `finish()`，完成 final drain、Statistics、EndOfTrace 和 worker join。
7. 最后 shutdown `HookBackend` 并关闭输出流。

组合 writer 会拒绝独立 queue、已安装的任一 hook 或未初始化 guard runtime。`begin_capture()` 要求
三个 hook 均已安装；`finish()` 要求三个 hook 均不再 installed/teardown-pending，避免过早写出正常
结束。完整 teardown 原理见 [HOOK_QUIESCENCE.md](HOOK_QUIESCENCE.md)。

## 3. 生命周期配对

worker 维护 `(heap_handle, address) -> allocation_id` 的 live map：

- 成功 allocate 分配单调递增且不复用的 allocation_id，并写入/替换对应 key。
- 失败或异常 allocate 不创建 generation。
- 成功 realloc 命中旧 key 时结束旧 generation；即使地址相同也分配不同的新 allocation_id。
- 成功 realloc 未命中旧 key 时按 CaptureScope 标记 preexisting/unmatched，但仍为返回地址创建新 ID。
- 失败或异常 realloc 使用 `no_change`，已知 old ID 可写入事件，但 live map 不变。
- 成功 free 命中 key 时，把相同 allocation_id 写入 `FreeEvent` 并删除 live entry；跨线程 free 与同线程
  行为完全相同。
- 成功 free 未命中且 address 非零时，若 CaptureScope 声明旧分配未知则写 `preexisting`，否则写
  `unmatched`。
- 成功 free 的 address 为零时写 `unmatched`；不会虚构 allocation_id。
- 返回失败或抛出异常的 free 保持原 live entry，不结束 generation。

事件丢失后 map 可能无法再证明后续 free 的精确归属；Loss 和 aggregate completeness 会把 trace 标为
不完整，因此 analyzer 不得基于该 trace 给出“完整生命周期”的结论。

## 4. 时间、栈与异常

worker 要求原始事件 sequence 连续、thread 非零、operation/status/result/NTSTATUS 组合有效、栈编码
合法且 tick 不早于 FileHeader origin。违反不变量会返回 `kWriterError`。不同线程按 queue reservation
排序时 QPC 可能轻微倒退；writer 保留 sequence 顺序，把倒退 tick 提升到上一事件并累计
`timestamp_adjustments`。

成功或截断的原始栈使用 FNV-1a 定位，再对状态、帧数和每一帧完整比较，hash 碰撞不会误合并。
三个 API 共用一个 stack dictionary，相同栈可以跨 API 复用同一 stack_id。dictionary 容量固定，
满后重置当前索引 segment，但 stack_id 继续单调递增；definition 总在引用它的 Event chunk 之前落盘。

SEH 第一遍 filter 只写固定事件并返回 `EXCEPTION_CONTINUE_SEARCH`。异常派发期间不执行栈展开；请求
深度非零时 stack 标为 failed，同时生成 stack-capture-failed Loss。`RtlAllocateHeap` 的
`HEAP_GENERATE_EXCEPTIONS` 和 Full Page Heap 下 `RtlFreeHeap` 非常规 flags 的异常都保留原 NTSTATUS，
failure event 仍参与统计守恒。

## 5. Loss 与计数守恒

writer 生成三类 Loss：

| 原因 | 位置 | count | sequence/tick range |
|---|---|---:|---|
| stack_capture_failed | agent_queue | 1 | 对应事件的精确范围 |
| queue_full | agent_queue | 三个 hook dropped 的和 | 无；被拒绝事件没有 sequence |
| trace_full | writer | 未落盘事件数 | 首末丢失事件的精确范围 |

Statistics 同时保存 aggregate 与组合模式下的 `api_id=1/2/3`。每个 API 及 aggregate 都必须
满足：

~~~text
successful_operations + failed_operations == observed_calls
written_events + queue_dropped_events + trace_dropped_events == observed_calls
decoded_events == observed_calls - dropped_events
~~~

异常计入 failed_operations；stack-only Loss 不丢失事件。所有累计加法先检查 uint64 overflow，正式
decoder 再次校验 Statistics 与实际 Event 数量。

## 6. 文件硬上限

TraceWriter 强制保留至少 1 KiB 文件尾。普通 metadata/stack/event chunk 只能使用
`max_file_size - reserve`；任何完整 chunk 放不下时不写半块，并把当前及后续已观察事件计为
trace-full。

最终 drain 后释放 reserve。组合模式最坏尾部包含两个 56-byte Loss record、一个含三个 API 的
232-byte Statistics record、一个 48-byte EndOfTrace record 及三个 56-byte chunk header，共 560
bytes。终止 chunk 固定使用 none codec，因此 1 KiB reserve 不依赖 LZ4/Zstd compression bound，且
实际文件不会超过配置上限。

## 7. 自动验证

原 allocate-only 集成测试继续覆盖 empty、normal、queue-limit、file-limit 和 exception 五种模式。
P5.2 组合测试另覆盖：

- writer 拒绝两个独立 queue；
- matched allocate/free 共享 allocation_id；
- allocation 在线程 A、free 在线程 B；
- capture 前 allocation 的成功 free 标为 preexisting；
- null free 标为 unmatched；
- capture 结束仍 live 的 allocation 被 GenerationTracker 保留；
- 原地、跨线程、零大小、失败和 preexisting realloc 的 generation 转换；
- 三组 ApiStatistics、aggregate Statistics、EventStream 数量和 completeness 一致；
- queue/trace dropped 均为零的正常组合路径。

`RtlFreeHeap` 与 `RtlReAllocateHeap` 合同、fail-fast、quiescence、CFG/CET 和 Full Page Heap 证据见
[RTL_FREE_HEAP_HOOK.md](RTL_FREE_HEAP_HOOK.md) 与
[RTL_REALLOCATE_HEAP_HOOK.md](RTL_REALLOCATE_HEAP_HOOK.md) 及
[WINDOWS_HOOK_HARDENING.md](WINDOWS_HOOK_HARDENING.md)。

~~~powershell
. .\scripts\Enter-NoleaxDevShell.ps1
cmake --build --preset windows-x64-debug
cmake --build --preset windows-x64-release
ctest --preset windows-x64-debug -R "rtl-heap-trace-writer|rtl-free-heap|trace-writer" --output-on-failure
ctest --preset windows-x64-release -R "rtl-heap-trace-writer|rtl-free-heap|trace-writer" --output-on-failure
~~~
