# Windows NtAllocateVirtualMemory/NtFreeVirtualMemory Hook

> 状态：P5.4 allocate/free 门禁完成；P5.5 已并入 section-view 协调器
> 范围：NT virtual-memory reserve/commit/decommit/release、MappingId generation、远程进程分类与安全卸载

## 1. Adapter 合同

`NtMemoryHooks` 使用 Windows x64 的精确 NTAPI ABI，一次协调安装：

- `NtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG)`；
- `NtFreeVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG)`。

两个 replacement 都只调用 original 一次，保存原始 `NTSTATUS`，并在记录完成后恢复调用者的
`LastError`。调用前后的 base/size 都保留在 raw event 中。无效输出指针由 SEH 安全读取；原函数若
抛出异常，filter 记录固定宽度 failure event 后继续搜索，`__finally` 保证 guard 和 replacement
in-flight 计数恢复。

两个 hook 共用预分配 `NtVirtualMemoryEventQueue` 和唯一 queue sequence。固定 TEB guard 把同线程
嵌套的 NT VM 调用归类为 recursive；带 `InternalThreadScope` 的 writer 调用归类为 internal。真实
`RtlAllocateHeap` 扩容可能进入 NT VM，因此在 NT Heap hook 已处于 outermost 时，这些 backing 操作
只透传、不重复产生 mapping lifecycle。

## 2. Mapping generation

writer 使用 `api_id=6/7`，只为当前进程成功操作分配 `MappingId`：

| 操作 | generation 行为 |
|---|---|
| `MEM_RESERVE` | 以系统规范化后的 allocation base/size 创建 generation |
| `MEM_COMMIT` | 命中已有 reservation 时复用同一 `MappingId`；预存 reservation 则补建并标记 preexisting |
| `MEM_DECOMMIT` | 记录事件并关联 `MappingId`，但不结束 reservation generation |
| `MEM_RELEASE` | 只在成功时结束完整 reservation generation |

成功 allocate 返回后，adapter 在 guard 内用 `VirtualQuery` 得到 `AllocationBase` 和当前规范化范围，
因此指定子页的 commit 不会被误建成独立 mapping。writer 允许系统/runtime 对同一 reservation 发出
多次成功 commit，并验证更新范围没有越出已知 generation。

真实远程进程句柄会在 hook 当下解析为目标 PID。远程操作保留原 handle、PID、参数、结果和调用栈，
但不创建本进程 `MappingId`；PID 不在后台延迟查询，避免句柄在 writer 消费前已关闭。

## 3. Trace 与分析

P5.4 将统一 raw event 扩展为 640 bytes；P5.5 加入 section 字段后为 664 bytes。
`VmAllocateEvent` 的 wire payload 同步增加规范化 generation base/size，完整 record 为 152 bytes。
`GenerationTracker` 对 commit 视为已有 generation 更新，对 decommit 保持 live，只让 release 结束它。

`NtVirtualMemoryTraceWriter` 是现有后台 writer 的 VM-only 别名。它在 hook 安装前启动 internal worker，
按 queue sequence 写 StackDefinition、VmAllocate/VmFree、Loss、Statistics 和 EndOfTrace；queue、stack
dictionary 和文件大小上限沿用 [TRACE_WRITER.md](TRACE_WRITER.md) 的合同。

## 4. 自动验证

合同和 trace 测试覆盖：

- reserve、指定页 commit、decommit、release 以及 reserve+commit；
- null/指定 base、系统大小对齐、零大小失败 NTSTATUS、`VirtualAlloc`/`VirtualFree` 包装路径；
- pseudo handle、真实当前进程 handle和真实 suspended child remote handle；
- preexisting reservation、MappingId 复用、outstanding generation 与正式 EventStream 回读；
- NT Heap 外层调用造成的真实嵌套 NT VM 递归抑制；
- queue overflow 计数守恒、模块 pin、并发 thread churn 和 quiescent teardown。

2026-07-30 验收结果：Debug/Release 各 193/193，hardened 213/213；20 个 PE 通过 CFG/CET metadata，
五个 quiescence 目标报告 `cfg=1 cet=1`。新增 NT VM race 连续 100/100，MD/MT 8×20,000×2 长差分
3/3。Application Verifier/Full Page Heap 下 workload、五组 race、trace 和合同各三轮通过；本轮
54 份 `.dat` 日志按 15 个 image 导出 XML 后为零 `LogEntry`，15 个 IFEO key 全部清理。

P5.7 已将 VM 与 section-view family 接入 `windows-virtual-memory` 和 `windows-native` 产品 profile；
native 模式与 NT Heap 共用 queue，并通过完整组合、过滤、统计和逻辑停录门禁。详见
[WINDOWS_HOOK_PROFILES.md](WINDOWS_HOOK_PROFILES.md)。
