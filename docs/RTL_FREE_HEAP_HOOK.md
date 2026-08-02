# Windows RtlFreeHeap Hook

> 分支：`feat/rtl-free-heap-hook`

## 1. ABI 与行为基线

adapter 使用 ntdll 的精确签名：

~~~cpp
BOOLEAN NTAPI RtlFreeHeap(PVOID heap, ULONG flags, PVOID address);
~~~

replacement 返回 original 的原始 `BOOLEAN`，不把 NTSTATUS、Win32 BOOL 或 C++ bool 混入 ABI。普通
Windows 11 x64 环境中，当前合同探针得到：

| case | 结果 | LastError |
|---|---|---|
| valid allocation | TRUE | 不变 |
| null address | TRUE | 不变 |
| null heap + null address | TRUE | 不变 |
| `flags=0xffffffff` | TRUE | 不变 |

这些值只描述当前系统实测，不作为跨 Windows 版本的硬编码替代品；自动测试始终比较同一环境中的
baseline 与 hooked 行为。

## 2. 热路径合同

`RtlFreeHeapHook` 复用 allocate hook 已验证的基础设施：

- 安装前解析 ntdll export、预检 `RtlCaptureStackBackTrace` 并取得固定 TEB TLS guard 引用；
- replacement 入口先计入独立的 in-flight lifecycle，再取得 `record/original/target` 路由；
- record 路径按 outermost、recursive、internal 分类；只有 outermost 记录事件；
- original 返回后立即保存 LastError，再做无锁计数、定长栈捕获和非阻塞入队，最后恢复 LastError；
- 热路径不执行 heap allocation、mutex、condition variable、文件 I/O、压缩或符号解析；
- 返回失败不修改 original 结果，异常不被吞掉或转换。

outermost 的 `successful + failed == recordable`；SEH 异常同时计入 failed 和 exceptional。每个 hook
拥有独立的饱和 dropped counter，即使 alloc/free 共用 queue，Statistics 仍能按 API 归因。

## 3. 统一事件与共享队列

统一 664-byte `RtlHeapEvent` 保留以下 free 字段：

- 全局 queue sequence、QPC tick、thread ID；
- heap handle、address、flags 和 original raw BOOLEAN result；
- success/failure/exception 及 NTSTATUS；
- 固定容量原始调用栈。

`RtlFreeHeapHook` 可单独拥有 queue，用于隔离合同测试；产品组合路径使用 `RtlHeapHooks`，让五个
NT Heap adapter 引用同一个 `RtlHeapEventQueue`。唯一 reservation sequence
保证跨线程、跨 API 的生命周期总顺序。组合 writer 会拒绝两个独立 queue，不能退化为按时间戳猜测
allocate/free 先后。

## 4. 异常与破坏性输入

MSVC replacement 使用内层 `__finally` 和外层 exception filter：

- filter 只在 outermost original 尚未完成时记录 exception event，并返回
  `EXCEPTION_CONTINUE_SEARCH`；
- `__finally` 无条件退出 hook guard 和 replacement lifecycle；
- filter 保存并恢复 LastError；
- 异常派发期间不展开调用栈，stack 明确标为 failed/disabled。

Application Verifier Full Page Heap 下，`flags=0xffffffff` 的 baseline 会抛出 `0xc0000005`。hooked
路径必须保留相同 returned/result/exception/LastError，并在 handler 返回后满足 hook depth 和
in-flight 均为零、exception event 可出队、后续普通调用及卸载仍正常。

以下输入可能直接触发进程 fail-fast，不能在主测试进程内探测：

| case | baseline | hooked |
|---|---:|---:|
| bad address | `0xc0000374` | `0xc0000374` |
| allocation 交给错误 heap | `0xc0000374` | `0xc0000374` |
| double free | `0xc0000374` | `0xc0000374` |

每个 case 都在新子进程中运行；父进程只比较退出码，避免测试框架或前一例的 heap 状态污染结果。

## 5. 生命周期配对

后台 writer 按 `(heap_handle, address)` 维护 live allocation map。只有成功 free 会结束 generation：

- 命中时写入原 allocation_id 并删除 map entry；
- 未命中的非零地址按 CaptureScope 写 `preexisting` 或 `unmatched`；
- null address 写 `unmatched`；
- 返回失败或异常时不删除 entry。

allocation 和 free 可以来自不同线程。配对与调用栈去重都在 internal writer 线程完成，不进入 hook
热路径。具体 trace、Loss 和 Statistics 合同见 [TRACE_WRITER.md](TRACE_WRITER.md)。

## 6. 安全卸载

五个 hook 使用独立的 replacement lifecycle 和 trampoline lifetime lease。卸载顺序
仍遵守：关闭 recording gate、revert target、发布 restored-target route、等待 replacement quiescence、
释放 trampoline lease、完成 Hoox flush。`RtlHeapHooks` 负责让五个 hook 都达到完成态；任一仍处于
teardown-pending 时，组合 writer 不允许写正常 EndOfTrace。

replacement 所在模块由 adapter 持有普通 +1 引用；patch rendezvous 证明 `.nlxhk` 段已排空后释放引用并允许
新实例重装（见 [HOOK_QUIESCENCE.md](HOOK_QUIESCENCE.md) §5）。析构时若有限次
flush 仍无法证明 quiescence 或 rendezvous 无法通过，会把仍可能被旧 replacement 读取的 state、guard 引用
和模块引用转交进程生命期。
组合对象同时释放共享 queue 的所有权，使 queue 也保留到进程退出；不能只保留 hook state 却析构其
指向的外部 queue。正常 quiescent 路径仍按常规顺序释放全部对象。

## 7. 自动验证

free hook 引入、并在五 hook 组合中持续执行的验证包括：

- free return/LastError/outermost/recursive/internal/SEH 合同；
- bad address、wrong heap、double free 隔离 fail-fast 差分；
- free 独立并发 quiescence race；
- alloc/free 共享 queue 的顺序、溢出和计数守恒；
- matched、cross-thread、preexisting、unmatched 和 outstanding generation 的正式 trace 回读；
- MD/MT 8×20,000×2 baseline/hooked 长差分；
- 10 个 PE 的 CFG/CET metadata、allocate/free runtime mitigation；
- Application Verifier/Full Page Heap 三轮；15 个目标 IFEO key 全部不存在。

常用定向命令：

~~~powershell
. .\scripts\Enter-NoleaxDevShell.ps1
ctest --preset windows-x64-debug -R "rtl-free-heap|rtl-heap-trace-writer" --output-on-failure
ctest --preset windows-x64-release -R "rtl-free-heap|rtl-heap-trace-writer" --output-on-failure
.\scripts\Test-WindowsHookHardening.ps1 -SkipApplicationVerifier -RequireCetRuntime
~~~

## 8. 覆盖边界

free hook 已随 `windows-nt-heap` 与 `windows-native` 产品 profile 启用；heap create/destroy、NT VM
allocate/free、section view、模块 generation 和注入链路均已完成。剩余边界是内部切分大块 VM 的
第三方 allocator：只能看到 backing mapping，不能宣称完整 Windows 内存泄漏覆盖。
