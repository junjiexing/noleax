# Windows `RtlReAllocateHeap` Hook

> 状态：P5.2 Windows x64 自动门禁完成
> 范围：精确 ABI、guard/SEH、共享队列、reallocation generation 与安全卸载

## 1. Adapter 合同

目标函数使用精确 ABI：

~~~cpp
PVOID NTAPI RtlReAllocateHeap(PVOID heap, ULONG flags, PVOID address, SIZE_T size);
~~~

replacement 与 allocate/free adapter 使用相同的固定 TEB guard、`ReplacementLifecycle`、模块 pin、
trampoline lifetime lease 和 quiescent teardown。只有 outermost 调用记录事件；recursive 与
internal-thread 调用只透传 original。original 返回后立即保存 `LastError`，完成固定字段写入、栈捕获
与无等待入队后恢复。SEH 第一遍 filter 只生成固定大小的 exception event，然后
`EXCEPTION_CONTINUE_SEARCH`，不改变目标异常派发。

统一 `RtlHeapEvent` 的 realloc 字段语义为：

- `address`：旧地址；
- `result_address`：返回的新地址，失败/异常为零；
- `requested_size`：请求的新大小；
- `heap_handle`、`flags`：原始参数；
- `raw_result`：固定为零；
- `operation`：`kReallocate`。

## 2. Generation 转换

writer 继续维护 `(heap_handle,address) -> allocation_id` live map，并使用 `api_id=3` 输出
`ReallocationEvent`：

| 原始结果 | old generation | effect | live map 变化 |
|---|---|---|---|
| 成功，旧地址已知 | 写入 old ID | `new_generation` | 删除旧 key，分配全新 ID 并写入新 key |
| 成功，旧地址未知 | `preexisting` 或 `unmatched` | `new_generation` | 仍为结果创建全新 ID |
| 返回 null | 若已知则写入 old ID | `no_change` | 不改变旧 generation |
| 抛出异常 | 若已知则写入 old ID | `no_change` | 不改变旧 generation |

即使原地 realloc 的地址未变，也必须结束旧 generation 并创建不同的 allocation ID。零大小调用按
系统实际返回值处理；Windows x64 当前基线返回非空最小块，因此同样是 `new_generation`。不使用
`freed` 推断：只有可以与普通失败可靠区分的平台语义才能输出该 effect。

## 3. 组合生命周期

`RtlHeapHooks` 按 allocate → reallocate → free 安装三个 adapter，并共享同一个预分配 MPSC queue。
安装中任一后续 hook 失败都会协调卸载已安装部分。析构时只要任一 replacement 无法证明 quiescent，
共享 queue 所有权就转移到进程生命周期，避免尚在执行的 replacement 写入已析构存储。

三 hook writer 构造方式要求三个 adapter 都引用同一 queue；`begin_capture()` 要求全部已安装，
`finish()` 要求全部完成卸载。allocate-only 和 alloc/free 构造方式继续兼容。

## 4. 自动验证

P5.2 新增的测试覆盖：

- 原地缩小、真实移动、普通增长、零大小和可控 OOM 失败；
- 返回形态、原数据、`LastError`、outermost/recursive/internal 分类和 raw event 字段；
- `HEAP_GENERATE_EXCEPTIONS` 的 baseline/hooked SEH 逐字段差分，异常后旧块仍可用；
- bad address、wrong heap、freed address 在隔离进程中的 baseline/hooked 终止码一致；
- 8 worker 与线程 churn 并发下 uninstall/quiescence race；
- allocation → 原地/跨线程/零大小/失败/preexisting realloc → free 的 trace 回读；
- 三个 API 的独立 queue/trace drop 归因、Statistics 与 aggregate 守恒；
- Debug/Release 各 186/186，hardened 200/200；
- 三个 quiescence race 各连续 100 次，14 个 PE 的 CFG/CET metadata 与 runtime 检查；
- Application Verifier/Full Page Heap 下三轮组合 workload、三轮 quiescence 和三轮合同/trace。

管理员门禁结束后 10 个 IFEO key 均不存在。平台强化门禁由
[WINDOWS_HOOK_HARDENING.md](WINDOWS_HOOK_HARDENING.md) 和
`scripts/Test-WindowsHookHardening.ps1` 统一执行；profile 在 P5.7 前仍不启用。
