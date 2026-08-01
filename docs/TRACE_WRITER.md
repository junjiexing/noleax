# Windows Memory Background Trace Writer

> 范围：进程内 trace、heap/allocation/mapping generation 配对和安全停止

## 1. 目标与边界

所选 replacement 只调用 original、保存固定宽度字段、捕获原始 PC 并尝试入队。压缩、容器
分配、文件 I/O、栈去重、allocation_id 配对和 record codec 全部位于后台线程。

当前生成九种规范化事件：

| 原始 API | api_id | 规范化 payload |
|---|---:|---|
| `RtlAllocateHeap` | 1 | `AllocationEvent` |
| `RtlFreeHeap` | 2 | `FreeEvent` |
| `RtlReAllocateHeap` | 3 | `ReallocationEvent` |
| `RtlCreateHeap` | 4 | `HeapCreateEvent` |
| `RtlDestroyHeap` | 5 | `HeapDestroyEvent` |
| `NtAllocateVirtualMemory` | 6 | `VmAllocateEvent` |
| `NtFreeVirtualMemory` | 7 | `VmFreeEvent` |
| `NtMapViewOfSection` | 8 | `MapEvent` |
| `NtUnmapViewOfSection`/`Ex` | 9 | `UnmapEvent` |

`RtlHeapTraceWriter` 是组合模式的公开别名；原有 `RtlAllocateHeapTraceWriter` 单 hook 构造方式仍兼容，
只写 `api_id=1`；alloc/free 和 alloc/realloc/free 构造方式也继续兼容。`NtVirtualMemoryTraceWriter`
是 VM-only 构造方式的公开别名。writer 现在同时记录初始模块与 loader load/unload 通知；已知模块
帧保存 `module_id`、相对 offset 和绝对地址，未知/JIT 帧保留绝对地址回退。

## 2. 共享队列与跨 API 顺序

独立 heap-only 或 VM-only 模式各使用一个预分配 queue。`windows-native` 产品 profile 让五个
NT Heap hook 与五个 NT memory 物理入口共用同一个 queue。统一的 664-byte `RtlHeapEvent` 通过
operation 区分九种逻辑 API，并包含所需参数、raw result、异常状态和定长栈。成功 reservation 时分配
唯一 sequence，因此完整 native profile 中不同线程、不同 API 的生命周期顺序不依赖可能倒退或相同的
QPC tick。

每个 hook 分别保存 dropped counter，后台 writer 才能把共享 queue overflow 归因到正确 api_id；底层
queue 的总 dropped counter 只用于队列级诊断。被 queue 拒绝的事件没有 sequence，Loss 因而只保存
数量，不伪造范围。

产品 profile 的安全调用顺序是：

1. 构造 `HookBackend` 和 `WindowsMemoryHooks`；后者按 registry 选择 profile，并拥有全部所选 hook
   共用的 queue。
2. 在 hook 安装前用 profile 构造 `RtlHeapTraceWriter`；它校验 queue、写 CaptureScope metadata，并
   启动带 `InternalThreadScope` 的 worker。
3. 调用 `WindowsMemoryHooks::install()`，再调用 writer `begin_capture()`。
4. 目标线程产生事件，worker 按共享 sequence 并发 drain。
5. 调用 `stop_recording()`，一次性把所选 replacement 切到 original 路由，并等待 record 路由的
   in-flight 归零；此后目标线程可继续运行，但不再访问 queue。
6. 调用 writer `finish()`，完成 final drain、Statistics、EndOfTrace 和 worker join。
7. 停止或挂起目标 worker，确认不会再持续进入被 hook API 后，调用 profile `uninstall()` 做物理
   revert 和 Hoox flush。
8. 最后 shutdown `HookBackend` 并关闭输出流。

组合 writer 会拒绝独立 queue、已安装的任一 hook 或未初始化 guard runtime。`begin_capture()` 要求
所选 hook 均已安装；`finish()` 接受“已逻辑停录且 record in-flight 为零”或“已完全卸载”两种状态，
但拒绝仍在记录或 teardown-pending 的 hook。完整 teardown 原理见
[HOOK_QUIESCENCE.md](HOOK_QUIESCENCE.md)。

旧的单 hook、heap-only 和 VM-only 构造方式继续兼容，可在完全 uninstall 后再 finish。NT Heap
outermost guard 仍抑制其嵌套 backing VM 调用，避免 native profile 对同一逻辑 heap allocation 重复
记账。

## 3. 生命周期配对

worker 维护 `heap_handle -> heap_id` 与 `(heap_handle, address) -> allocation_id` 两张 live map：

- 成功 create 分配单调递增且不复用的 heap_id；同一 handle 在 destroy 后复用时取得新 ID。
- 已知 heap 上的 allocate/reallocate/free 均携带当前 heap_id；捕获前已存在的 heap 保留无效 ID。
- 成功 destroy 命中当前 heap_id 时移除 heap map 及 writer 的相关 live allocation；规范化 destroy 让
  GenerationTracker 以 `heap_destroyed` 结束该 heap 下全部 generation。
- 成功 destroy 未命中时按 CaptureScope 标记 preexisting/unmatched；失败或异常 destroy 不改变 map。

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

VM-only worker 另维护按地址排序的 reservation map：reserve 分配 MappingId；commit 命中时复用该 ID，
未命中且 CaptureScope 允许旧状态时补建 preexisting generation；decommit 保留 map；成功 release 才
删除 generation。远程进程事件不进入本进程 map。

事件丢失后 map 可能无法再证明后续 free 的精确归属；Loss 和 aggregate completeness 会把 trace 标为
不完整，因此 analyzer 不得基于该 trace 给出“完整生命周期”的结论。

## 4. 时间、栈与异常

worker 要求原始事件 sequence 连续、thread 非零、operation/status/result/NTSTATUS 组合有效、栈编码
合法且 tick 不早于 FileHeader origin。违反不变量会返回 `kWriterError`。不同线程按 queue reservation
排序时 QPC 可能轻微倒退；writer 保留 sequence 顺序，把倒退 tick 提升到上一事件并累计
`timestamp_adjustments`。

成功或截断的原始栈先按事件时间对应的 module generation 规范化，再使用 FNV-1a 定位并对状态、
帧数和每一帧完整比较，hash 碰撞不会误合并。相同绝对地址在 DLL unload/reload 后因 ModuleId 不同
不会复用旧 stack_id。
同一 writer 的 API 共用一个 stack dictionary，相同栈可以跨 API 复用同一 stack_id。dictionary 容量固定，
满后重置当前索引 segment，但 stack_id 继续单调递增；definition 总在引用它的 Event chunk 之前落盘。

SEH 第一遍 filter 只写固定事件并返回 `EXCEPTION_CONTINUE_SEARCH`。异常派发期间不执行栈展开；请求
深度非零时 stack 标为 failed，同时生成 stack-capture-failed Loss。`RtlAllocateHeap` 的
`HEAP_GENERATE_EXCEPTIONS` 和 Full Page Heap 下 `RtlFreeHeap` 非常规 flags 的异常都保留原 NTSTATUS，
failure event 仍参与统计守恒。

## 5. Loss 与计数守恒

writer 生成以下 Loss：

| 原因 | 位置 | count | sequence/tick range |
|---|---|---:|---|
| stack_capture_failed | agent_queue | 1 | 对应事件的精确范围 |
| queue_full | agent_queue | 所选 hook dropped 的和 | 无；被拒绝事件没有 sequence |
| queue_full | agent_queue | module notification dropped 的和 | 无；模块通知使用独立 queue |
| trace_full | writer | 未落盘事件数 | 首末丢失事件的精确范围 |

Statistics 同时保存 aggregate 与所选模式下的 `api_id=1..9`。每个内存 API 及 aggregate 都必须
满足：

~~~text
successful_operations + failed_operations == observed_calls
written_events + filtered_before_queue + queue_dropped_events + trace_dropped_events == observed_calls
decoded_events == observed_calls - filtered_before_queue - dropped_events
~~~

其中 decoded events 为 `observed - filtered_before_queue - dropped_events`。异常计入
failed_operations；stack-only Loss 不丢失事件。所有累计加法先检查 uint64 overflow，正式 decoder
再次校验 Statistics 与实际 Event 数量。过滤语义见
[WINDOWS_HOOK_PROFILES.md](WINDOWS_HOOK_PROFILES.md)。

## 6. 文件硬上限

TraceWriter 强制保留至少 1 KiB 文件尾。普通 metadata/stack/event chunk 只能使用
`max_file_size - reserve`；任何完整 chunk 放不下时不写半块，并把当前及后续已观察事件计为
trace-full。

最终 drain 后释放 reserve。九 API 上限下的终止 Statistics、Loss 与 EndOfTrace 仍小于预留的 1 KiB；
终止 chunk 固定使用 none codec，因此 reserve 不依赖 LZ4/Zstd compression bound，且实际文件不会
超过配置上限。

## 7. 自动验证

原 allocate-only 集成测试继续覆盖 empty、normal、queue-limit、file-limit 和 exception 五种模式。
组合测试另覆盖：

- writer 拒绝两个独立 queue；
- matched allocate/free 共享 allocation_id；
- allocation 在线程 A、free 在线程 B；
- capture 前 allocation 的成功 free 标为 preexisting；
- null free 标为 unmatched；
- capture 结束仍 live 的 allocation 被 GenerationTracker 保留；
- 原地、跨线程、零大小、失败和 preexisting realloc 的 generation 转换；
- create/destroy 的 HeapId、多 heap、destroy-with-live 和 raw handle reuse；
- 五组 ApiStatistics、aggregate Statistics、EventStream 数量和 completeness 一致；
- queue/trace dropped 均为零的正常组合路径。

VM trace 另覆盖 reserve/commit/decommit/release、preexisting、失败 NTSTATUS、真实 remote child、
outstanding generation、MappingId 复用、两组 ApiStatistics 以及正式 EventStream/GenerationTracker 回读。

section map/unmap 增加两组逻辑 ApiStatistics。local map 创建独立 MappingId，view 内地址 unmap 规范化为基址；
remote 不创建 ID，未知成功 unmap 按 CaptureScope 归类为 preexisting/unmatched。pagefile/file-backed、
多 view、wrapper、remote 与 outstanding 均经正式 EventStream/GenerationTracker 回读。

模块跟踪增加初始模块快照、固定 loader-notification queue、PE/CodeView identity、ModuleLoad/Unload codec
和 generation-aware stack dictionary。真实 fixture 覆盖 unload/reload、同基址复用、相同绝对 PC 的
不同 StackId，以及模块卸载后的离线符号化。详见 [MODULE_TRACKING.md](MODULE_TRACKING.md)。

另覆盖 profile 构造方式和九 API 单 queue 端到端测试。测试在持续 heap/VM worker 与线程 churn
下先逻辑停录，确认九组 recordable counter 冻结；writer 在物理 revert 前结束，目标 worker 停止后
才 uninstall。三种 creation-side filter、每 API/aggregate Statistics、九个 API ID、GenerationTracker
和 EndOfTrace 均由正式 decoder 校验。

`RtlFreeHeap` 与 `RtlReAllocateHeap` 合同、fail-fast、quiescence、CFG/CET 和 Full Page Heap 证据见
[RTL_FREE_HEAP_HOOK.md](RTL_FREE_HEAP_HOOK.md) 与
[RTL_REALLOCATE_HEAP_HOOK.md](RTL_REALLOCATE_HEAP_HOOK.md) 及
[RTL_HEAP_LIFECYCLE_HOOK.md](RTL_HEAP_LIFECYCLE_HOOK.md) 及
[NT_VIRTUAL_MEMORY_HOOK.md](NT_VIRTUAL_MEMORY_HOOK.md) 及
[NT_SECTION_VIEW_HOOK.md](NT_SECTION_VIEW_HOOK.md)。

~~~powershell
. .\scripts\Enter-NoleaxDevShell.ps1
cmake --build --preset windows-x64-debug
cmake --build --preset windows-x64-release
ctest --preset windows-x64-debug -R "windows-native-profile|rtl-heap-trace-writer|trace-writer" --output-on-failure
ctest --preset windows-x64-release -R "windows-native-profile|rtl-heap-trace-writer|trace-writer" --output-on-failure
~~~
