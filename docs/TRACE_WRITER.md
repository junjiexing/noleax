# Windows RtlAllocateHeap Background Trace Writer

> 状态：P4.7 Windows x64 完成
> 范围：单一 `RtlAllocateHeap` API 的进程内 trace path；P4.8 已接入安全停止 barrier

## 1. 目标与边界

P4.7 把 P4.5/P4.6 的定长原始事件队列接到正式 `.nlx` writer 和 EventStream decoder。allocator
replacement 仍只调用 original、保存固定宽度字段、捕获原始 PC 并尝试入队；压缩、容器分配、文件
I/O、栈去重和 record codec 全部位于后台线程。

当前只生成 `RtlAllocateHeap` Allocation event，固定 `api_id=1`。P5 才会加入 free/reallocate、heap
generation、模块 generation、过滤和 profile。P5.6 前 StackDefinition 只保存绝对地址，module_id 和
module_offset 为零。

## 2. 启动与停止顺序

安全的 P4.7 调用顺序是：

1. 构造 `RtlAllocateHeapHook`，预分配 queue 并取得固定 TEB TLS guard slot。
2. 在 hook 安装前构造 `RtlAllocateHeapTraceWriter`；它写 CaptureScope metadata，启动 worker，并在
   worker 上建立 `InternalThreadScope`。
3. 安装 hook，再调用 `begin_capture()` 唤醒 worker。
4. 目标线程调用 allocator；worker 并发 drain。
5. 卸载/flush hook；P4.8 gate 关闭新 producer 并等待已进入 replacement 的 producer 退出。
6. 调用 `finish()`，worker 最终 drain、写终止记录并 join。
7. 最后 shutdown HookBackend、关闭输出流。

若构造 writer 时 hook 已安装、guard runtime 尚未初始化、选项越界或 metadata 放不进文件，都会在
冷路径拒绝启动。worker 必须先于 hook 安装，这保证其后续 allocator 调用都被 guard 分类为
internal，不会递归进入记录队列。`finish()` 会拒绝仍处于 installed 或 teardown-pending 状态的
hook，避免调用方主动生成一个过早宣称正常结束的 trace。

P4.8 后，hook 只有在 recording gate 已关闭、target 已恢复、replacement in-flight 为零且 Hoox
flush 完成后才离开 teardown-pending。`finish()` 的 final drain 因此不会与 queue producer 并发。
完整顺序见 [HOOK_QUIESCENCE.md](HOOK_QUIESCENCE.md)。

## 3. Drain、时间与栈去重

worker 以单 consumer 顺序读取 queue sequence。原始事件必须满足连续 sequence、非零 thread、有效
success/result 组合、合法栈状态和不早于 FileHeader origin；违反不变量会使 writer 返回
`kWriterError`，不会伪造完整 trace。

不同线程按 queue reservation 排序时，QPC tick 可能轻微倒退。writer 保留事件顺序并把倒退值提升
到上一事件 tick，同时累计 `timestamp_adjustments`。EndOfTrace 使用最后一个规范化 tick。

成功或截断的原始栈使用 FNV-1a hash 定位，再对状态、帧数和每一帧做完整比较，hash 碰撞不会误合并。
dictionary 在启动前固定分配；满后清空当前索引 segment，但 stack_id 继续单调递增。新 definition
总是在引用它的 Event chunk 之前写出。统计中的 unique/reused 只计算最终成功落盘的事件。

## 4. Loss 与计数守恒

writer 生成三类 Loss：

| 原因 | 位置 | count | sequence/tick range |
|---|---|---:|---|
| stack_capture_failed | agent_queue | 1 | 对应事件的精确范围 |
| queue_full | agent_queue | exchange 得到的累计值 | 无；被拒绝事件没有 sequence |
| trace_full | writer | 未落盘事件数 | 首末丢失事件的精确范围 |

stack capture 失败仍写 allocation event，只降低 stack completeness。queue/file 丢失会设置 event loss，
因此 analyzer 不会把不完整生命周期误报为完整。

结束时必须满足：

~~~text
successful_operations + failed_operations == observed_calls
written_events + queue_dropped_events + trace_dropped_events == observed_calls
decoded_events == observed_calls - dropped_events
~~~

writer 侧所有累计加法先检查 uint64 overflow。最终 Statistics 同时保存 aggregate 和 `api_id=1` 的
相同计数；正式 decoder 再次校验统计与实际 Event 数量。

## 5. 文件硬上限

TraceWriter 为 P4.7 强制保留至少 1 KiB 文件尾。普通 metadata/stack/event chunk 只能使用
`max_file_size - reserve`；任何完整 chunk 放不下时不写半块，并把当前及后续已观察事件计为
trace-full。

最终 drain 后释放 reserve。尾部最多包含两个 56-byte Loss record、一个含单 API 的 136-byte
Statistics record、一个 48-byte EndOfTrace record 及三个 56-byte chunk header，共 464 bytes。
这些终止 chunk 固定使用 none codec，因此 1 KiB reserve 不依赖 LZ4/Zstd 的压缩 bound，能够同时
保留 Loss、Statistics、EndOfTrace 且保证实际文件大小不超过配置上限。

## 6. 自动验证

真实 hook 集成测试覆盖：

- empty：不安装 hook、不开始 capture，仍生成零事件 Statistics 与正常 EndOfTrace，重复 finish 幂等；
- normal：LZ4、1,000 次显式 allocation、零事件丢失、栈 definition/reference 和统计一致；
- queue-limit：2-slot queue、20,000 次 allocation，稳定生成 queue-full Loss；
- file-limit：32,768-slot queue、none codec、8 KiB 上限，稳定生成 trace-full Loss；
- 三种模式均验证 writer 内部分配被归为 internal、正式 reader/decoder 可完整读取、Statistics 和
  EndOfTrace 存在、文件实际大小等于 writer 报告且不超过硬上限。

stack dictionary 单元测试另覆盖完整 hash collision 比较、segment reset 和 ID 不复用；codec 测试
覆盖 StackDefinition golden layout、malformed input 与 record-size limit。

~~~powershell
. .\scripts\Enter-NoleaxDevShell.ps1
cmake --build --preset windows-x64-debug
cmake --build --preset windows-x64-release
ctest --preset windows-x64-debug -R "trace-writer|stack definition|raw stack" --output-on-failure
ctest --preset windows-x64-release -R "trace-writer|stack definition|raw stack" --output-on-failure
~~~
