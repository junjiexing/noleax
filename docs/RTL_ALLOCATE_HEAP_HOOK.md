# RtlAllocateHeap Hook Prototype

> 状态：P4.9 Windows x64 adapter 完成；P5.3 已接入五 hook 共享队列，产品 profile 仍 disabled
> 范围：guarded raw-stack event queue 与后台 trace writer，可独立或参与五 hook 组合

## 1. 目的

P4.3 首次在正式测试路径 hook `ntdll!RtlAllocateHeap`，验证 Hoox trampoline、精确 ABI、original
发布顺序和卸载生命周期。P4.4 增加无分配 recursion/internal-thread guard，P4.5 为 outermost
调用增加预分配 MPSC 原始事件队列，P4.6 在成功取得 queue slot 后捕获原始调用栈。replacement
自身仍不写 trace；P4.7 由预先启动并标记为 internal 的后台线程消费队列、去重调用栈并写 trace。
P4.8 已增加 replacement gate、并发 revert 和 fail-safe 模块生命周期。P4.9 增加 SEH-safe 清理、
异常失败事件以及 CFG/CET hardened 门禁。

P5.3 保留原 allocate-only 构造方式，同时把 raw event 扩展为统一 608-byte `RtlHeapEvent`；组合路径由
`RtlHeapHooks` 让 create/allocate/reallocate/free/destroy 引用同一个 queue，跨 API 共用唯一
sequence。生命周期语义见 [RTL_FREE_HEAP_HOOK.md](RTL_FREE_HEAP_HOOK.md)、
[RTL_HEAP_LIFECYCLE_HOOK.md](RTL_HEAP_LIFECYCLE_HOOK.md) 和 [TRACE_WRITER.md](TRACE_WRITER.md)。

精确函数类型为：

~~~cpp
PVOID (NTAPI*)(PVOID heap, ULONG flags, SIZE_T size)
~~~

replacement 执行 guard 入口分类、无锁原子诊断计数、acquire-load original trampoline 和一次
original 调用。outermost 调用随后保存 `LastError`、取得 queue slot、填充定长原始事件和栈并恢复
`LastError`，最后退出 guard。original 或已发布 event queue 不可能安全缺失；若该不变量被破坏则
fail-fast，不能递归调用已被替换的 target。guard 的 TLS 崩溃根因和固定 TEB 槽设计见
[HOOK_GUARD.md](HOOK_GUARD.md)，队列设计和 overflow 语义见
[EVENT_QUEUE.md](EVENT_QUEUE.md)，原始栈和失败语义见 [STACK_CAPTURE.md](STACK_CAPTURE.md)。

## 2. 激活前发布

allocator hook 不能采用“先激活、函数返回后再保存 original”的普通顺序。hook 一旦生效，backend
尾部的容器或运行库 bookkeeping 就可能再次进入 `RtlAllocateHeap`。

`HookBackend::install_fast` 因此使用外层 Hoox transaction：

1. 创建 trampoline，但保持 transaction 未提交；
2. 完成 backend entry bookkeeping；
3. 以 release-store 将 original 写入调用方提供的 `OriginalTrampolineSlot`；
4. 结束 transaction，最后激活目标代码 patch。

replacement 使用 acquire-load。这样任何观察到已激活 patch 的线程都不会遇到尚未发布的
original；backend 自身在步骤 2 中发生的分配仍走未 hook 的原函数。

## 3. 合同测试拓扑

P4.1 的两个 workload executable 不链接 Hoox 或 agent。P4.3 新增独立 MD harness DLL，显式导出
install/call-count/stop；同一 executable 通过可选 `--hook-harness DLL` 参数决定是否加载它：

~~~text
noleax-rtl-heap-baseline-md.exe ─┐
                                ├─ unhooked / hooked 使用完全相同的 workload 和摘要
noleax-rtl-heap-baseline-mt.exe ─┘
                    │
                    └─ LoadLibrary → hook harness DLL → HookBackend → Hoox v0.1.1
~~~

这种结构避免把 Hoox 的动态 CRT 链接进 `/MT` 目标，也更接近后续 agent DLL 注入边界。hook 必须在
所有 worker 结束后 revert/flush/shutdown，随后 harness 才能 `FreeLibrary`。

自动测试逐字节比较以下四份 stdout：

- MD unhooked；
- MT unhooked；
- MD hooked；
- MT hooked。

摘要覆盖成功/失败返回、零填充、live block 内容、释放结果、直接与间接入口、process/显式 heap、
`LastError` change count/hash 和确定性 checksum。harness 安装后会先真实制造 outermost、recursive
与 internal-thread 入口，要求只有对应分类计数增加；随后创建 worker 线程并运行 workload。它还
要求 replacement 调用数至少覆盖全部直接 Rtl workload。停止时，harness 在卸载 hook 后 drain
256-slot 测试队列，验证 event 内容、连续 sequence、生产捕获方法、请求深度、成功/失败栈编码、
强制 overflow，以及
`recordable = dequeued + dropped`，防止“安装报告成功但 replacement/queue 未执行”的假阳性。

## 4. 验证结果

Debug 与 Release 的快速合同测试全部通过，并各连续重复 20 次。Release 长压力参数为 8 个线程、
每线程 20,000 次操作、2 个 round；MD/MT hooked 与各自 baseline 逐字节一致：

~~~text
attempts=160024 successes=160000 expected_failures=24 frees=160000
rtl_last_error_changes=8 win32_last_error_changes=8
rtl_last_error_hash=0x2fc65ff63169b923
win32_last_error_hash=0xdb3089d8201ac1a3
checksum=0x7caf2ccfa0606232
~~~

Release x64 object disassembly 中，replacement 调用 unscoped guard、original、`Get/SetLastError` 和
静态实例化的无锁 `try_emplace`；该 helper 的外部调用只有 `QueryPerformanceCounter`、
`GetCurrentThreadId` 和受审计的 raw stack capture。SEH filter 只增加 `Get/SetLastError`、QPC 和 thread
ID。Noleax 正常路径没有 allocator、文件、loader、日志、符号或显式锁调用。guard 继续直接访问
`gs:[TEB]` 固定槽，object 中没有 `.tls$` 段或 CRT `_tls_index` 引用。

writer 以 empty、normal、2-slot queue-limit、8 KiB file-limit 和 exception 五种模式验证。每个
生成文件均由正式 EventStream 回读，检查 StackDefinition 引用、Loss、统计守恒、终止记录和文件
硬上限；exception 模式额外检查 NTSTATUS failure event 和 SEH stack-detail Loss。P5.3 当前
Debug/Release 全量各 189 项通过。writer 重复压力和完整说明见
[TRACE_WRITER.md](TRACE_WRITER.md)。

P4.9 的隔离进程 SEH 合同确认 baseline/hooked 都抛出 `STATUS_NO_MEMORY (0xc0000017)`，exception
flags/parameters 一致，且 `LastError` 同为 8。异常 unwind 后 hook depth 和 replacement in-flight
均为零，下一次普通 allocation 仍被记录，hook 可正常 quiesce/shutdown。P5.3 hardened 产物全量
206/206 通过，17 个真实 PE 都包含 CFG/CET 标记；当前机器的四个 hook quiescence 进程均报告
`cfg=1, cet=1`，四组 race 各 100 次及 MD/MT 8×20,000×2 三轮长差分通过。详见
[WINDOWS_HOOK_HARDENING.md](WINDOWS_HOOK_HARDENING.md)。

运行方法：

~~~powershell
. .\scripts\Enter-NoleaxDevShell.ps1
cmake --build --preset windows-x64-release
ctest --preset windows-x64-release -R "bounded MPSC|hook guard|stack capture|trace-writer|rtl-allocate-heap-passthrough" --output-on-failure
ctest --preset windows-x64-release -L passthrough --output-on-failure
ctest --preset windows-x64-release -L passthrough --repeat until-fail:20
~~~

## 5. 未完成边界

P5.3 的五 hook Application Verifier/Full Page Heap 三轮压力、日志 review 和 12 个 IFEO key 回滚均
已通过。产品 profile 仍保持 disabled，不是因为 NT Heap adapter 留有稳定性门禁，而是 P5 尚未实现
VM/section-view、模块 generation 等配套生命周期能力。P4.8 生命周期见
[HOOK_QUIESCENCE.md](HOOK_QUIESCENCE.md)。
