# Windows V1 Hook Profiles

> 状态：P5.7 Windows x64 完成
> 范围：registry、profile 选择、热路径过滤、统计与产品停止顺序

## 1. 单一 registry

产品代码只维护一份 Windows hook registry。每项给出稳定 `api_id`、规范名称、模块、逻辑 API 组和
物理 export；profile 协调器、writer 和测试均以此表为边界。

| api_id | 规范 API | 物理 export | 组 | `capture.min_size` |
|---:|---|---|---|---|
| 1 | RtlAllocateHeap | RtlAllocateHeap | NT Heap | 是 |
| 2 | RtlFreeHeap | RtlFreeHeap | NT Heap | 否 |
| 3 | RtlReAllocateHeap | RtlReAllocateHeap | NT Heap | 否 |
| 4 | RtlCreateHeap | RtlCreateHeap | NT Heap | 否 |
| 5 | RtlDestroyHeap | RtlDestroyHeap | NT Heap | 否 |
| 6 | NtAllocateVirtualMemory | NtAllocateVirtualMemory | Virtual Memory | 是 |
| 7 | NtFreeVirtualMemory | NtFreeVirtualMemory | Virtual Memory | 否 |
| 8 | NtMapViewOfSection | NtMapViewOfSection | Virtual Memory | 是 |
| 9 | NtUnmapViewOfSection | NtUnmapViewOfSection、NtUnmapViewOfSectionEx | Virtual Memory | 否 |

因此 V1 是九个逻辑 API、十个物理入口。legacy 与 Ex unmap 共用 `api_id=9`、统计和 mapping
generation。独立 test registry 必须为每个逻辑 API 指定合同测试；自动测试双向检查两份 registry
恰好一一对应，并确认所有物理 export 都能从 `ntdll.dll` 解析。

## 2. Profile

| profile | 逻辑 API | 物理入口数 |
|---|---:|---:|
| `windows-nt-heap` | 1–5 | 5 |
| `windows-virtual-memory` | 6–9 | 5 |
| `windows-native` | 1–9 | 10 |

`WindowsMemoryHooks` 按 registry 构造所选 hook family。三个 profile 都只有一个预分配
`RtlHeapEventQueue`；native 模式让 heap 与 VM family 引用同一 queue，所以九种逻辑事件共享严格递增
的 queue sequence。NT Heap 外层 guard 会抑制其 backing VM 调用，防止同一 heap allocation 在
`RtlAllocateHeap` 和 `NtAllocateVirtualMemory` 两层重复记账。

用户选择方式：

~~~powershell
noleax run --hook-profile windows-nt-heap --capture-min-size 4KiB --trace app.nlx -- app.exe
~~~

~~~toml
[capture]
hook_profile = "windows-nt-heap"
min_size = "4KiB"
~~~

命令行与配置文件冲突时仍以命令行为准。

## 3. 最小尺寸过滤

阈值为零时不过滤。阈值非零时，只有尺寸严格小于阈值的以下 creation-side 事件会在 replacement
热路径被过滤：

- `RtlAllocateHeap`：使用请求大小；
- `NtAllocateVirtualMemory`：成功时使用系统返回的实际 region size，失败/异常时使用请求大小；
- `NtMapViewOfSection`：成功时使用系统返回的实际 view size，失败/异常时使用请求大小。

过滤发生在栈捕获和 queue reservation 之前，因此被过滤调用没有事件、sequence 或 stack ID，但仍
计入 observed、success/failure 和 `filtered_before_queue`。以下事件不按大小过滤：

- `RtlReAllocateHeap`；
- `RtlFreeHeap`、`NtFreeVirtualMemory`、`NtUnmapViewOfSection/Ex`；
- `RtlCreateHeap`、`RtlDestroyHeap`。

保留这些转换和结束事件，可以让已经观察到的 generation 正确关闭；过滤不能制造伪泄漏。若创建
事件本身被过滤，后续结束事件会按 CaptureScope 归类为 preexisting 或 unmatched，不虚构 ID。

每 API 与 aggregate Statistics 必须同时满足：

~~~text
successful_operations + failed_operations == observed_calls
written_events + filtered_before_queue + dropped_events == observed_calls
decoded_events == observed_calls - filtered_before_queue - dropped_events
~~~

## 4. 逻辑停录与物理卸载

产品 profile 不在目标线程持续运行时直接改写 NT API 入口。停止分为两个阶段：

1. 所有 replacement 从 `record` 切到 `original`。
2. 等待进入时快照为 `record` 的调用全部退出；新调用只透传 original，不访问 queue。
3. writer 做 final drain，写 Statistics 和 EndOfTrace，并停止 worker。
4. controller 停止或挂起目标 worker，消除持续进入 hook 入口的线程。
5. profile 才执行物理 revert、等待完整 replacement quiescence、释放 trampoline lease 并 flush Hoox。

`recording_in_flight` 与物理 teardown 使用的 `in_flight` 分开：前者证明 writer 可以安全结束，后者只在
物理 revert 后保护 trampoline 和 hook state。profile 会拒绝在仍记录或 record 调用未退出时卸载。

## 5. 自动验证

`hook.windows-native-profile` 同时覆盖：

- 三个 profile 的精确 API family 与共享 queue；
- 九个逻辑 API 在同一 native trace 中全部出现；
- 三种 creation-side 过滤和每 API/aggregate Statistics 守恒；
- heap、VM 与 section generation 经正式 EventStream/GenerationTracker 回读；
- 多个持续 worker 和线程 churn 下逻辑停录，停录后的 recordable counter 不再增长；
- writer 在物理 revert 前完成，目标 worker 停止后才 uninstall；
- queue/trace 零丢失以及完整 EndOfTrace。

最终门禁结果：Debug/Release 各 205/205、hardened 230/230、25 个 PE 的 CFG/CET metadata 通过；
五组既有 race 与 native profile 各连续 100/100，MD/MT 8×20,000×2 长差分 3/3。Application
Verifier/Full Page Heap 下 workload、race、writer/contract 和 native profile 各三轮通过，19 个 IFEO
key 全部清理。
