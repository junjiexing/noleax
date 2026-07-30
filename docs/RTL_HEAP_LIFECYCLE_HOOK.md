# Windows RtlCreateHeap/RtlDestroyHeap Hook

> 状态：P5.3 Windows x64 全部门禁完成
> 范围：NT Heap create/destroy adapter、HeapId generation、五 hook 组合与安全卸载

## 1. ABI 与原始事件

两个 adapter 直接解析 `ntdll.dll` 导出并使用精确 NTAPI ABI：

~~~cpp
PVOID NTAPI RtlCreateHeap(
    ULONG flags,
    PVOID heap_base,
    SIZE_T reserve_size,
    SIZE_T commit_size,
    PVOID lock,
    PVOID parameters);

PVOID NTAPI RtlDestroyHeap(PVOID heap);
~~~

`RtlCreateHeap` 返回非空表示成功；`RtlDestroyHeap` 返回 NULL 表示成功。replacement 在 original
返回后保存 `LastError`，完成固定字段、QPC、thread ID、栈和 queue publish 后恢复。MSVC SEH
`__finally` 保证异常路径也释放 fixed TEB guard 与 replacement in-flight；第一遍 filter 只写固定事件
并继续搜索。

P5.4 扩展后的统一 640-byte `RtlHeapEvent` 的 create 字段映射为：

| 字段 | 值 |
|---|---|
| heap_handle | 输入 `heap_base` |
| requested_size | `reserve_size` |
| result_address | 返回 heap handle |
| address | `lock` |
| raw_result | `commit_size` |
| auxiliary_address | `parameters` |
| flags | `flags` |

destroy event 的 `heap_handle` 是输入 handle，`raw_result` 是原始返回指针，其余专用参数字段为零。
create/allocate/reallocate/free/destroy 共用一个预分配 MPSC queue，因此跨 API 生命周期具有唯一
1-based sequence。

## 2. HeapId generation

后台 writer 为每次观察到的成功 create 分配单调递增且永不复用的 `HeapId`，并维护
`raw heap handle -> HeapId`：

- 已知 heap 上的 allocate/reallocate/free 携带当前 HeapId。
- destroy 成功且命中当前 HeapId 时，`HeapDestroyEvent` 携带该 ID；GenerationTracker 以
  `heap_destroyed` 结束该 heap 下全部 live allocation。
- destroy 失败或异常不移除 heap 和 allocation state。
- capture 前已存在的 heap 没有 HeapId；其成功 destroy 按 CaptureScope 标记
  `preexisting` 或 `unmatched`。
- destroy 后相同 raw handle 再次被系统复用时，新 create 必须取得不同 HeapId。

测试使用连续 create/destroy 强制观察 Windows 地址复用，并通过正式 EventStream 与
GenerationTracker 回读验证旧 ID 已结束、新 ID 不相同、destroy-with-live 只有一次
`heap_destroyed` generation end。

## 3. Guard、安装与卸载

两个 adapter 复用固定 TEB slot guard、replacement route、backend trampoline lifetime lease、模块
pin 和 Hoox Windows RWX patch quiescence。`RtlHeapHooks` 按 create、allocate、reallocate、free、
destroy 安装，并在安装/卸载协调路径使用 `InternalThreadScope`，防止 Hoox 自身的 heap 活动进入
用户 trace。

recursive 与 internal-thread 调用仍执行真实 original，但不记录事件。Full Page Heap 会在一次外层
调用中产生不固定数量的 verifier 内部递归，因此合同验证“递归计数增加且 recordable 不变”，不假设
内部次数固定。五个 hook 任一 teardown 未完成时，共享 queue 与所有 hook state 一起保留。

## 4. 失败与异常差分

合同覆盖 growable heap、固定 reserve/commit、不可满足 reserve 和
`HEAP_GENERATE_EXCEPTIONS`。普通环境下最后一种返回 NULL；Application Verifier Full Page Heap 下
同一输入抛出 `0xc0000017`。测试先取得 baseline，再要求 hooked 的返回方式、异常码和 LastError
完全一致，同时验证 raw event 分别为 failure 或 exception。

destroy 的危险输入在隔离子进程中比较 baseline/hooked：

| 输入 | 本机结果 |
|---|---|
| NULL | 两者均返回 NULL |
| `0x1` bad handle | 两者均退出 `0xc0000005` |
| double destroy | 两者均退出 `0xc0000005` |

这些值用于本机证据；正式断言以 baseline/hooked 相等为核心，避免把 OS 或 verifier 版本差异误判成
hook 行为。

## 5. 自动门禁

P5.3 结果：

| 门禁 | 结果 |
|---|---:|
| Debug 全量 | 189/189 |
| Release 全量 | 189/189 |
| hardened 全量 | 206/206 |
| CFG/CET PE | 17 |
| allocate/reallocate/free/lifecycle race | 各 100/100 |
| MD/MT 8×20,000×2 差分 | 3/3 |
| AppVerifier/Full Page Heap workload、race、trace、contract | 各 3/3 |
| 本轮 IFEO key 清理 | 12/12 |

~~~powershell
.\scripts\Test-WindowsHookHardening.ps1 -SkipApplicationVerifier -RequireCetRuntime

# 64-bit 管理员 PowerShell
.\scripts\Test-WindowsHookHardening.ps1 -RequireCetRuntime
~~~

产品 profile 仍保持 disabled；P5.4 已完成 VM reserve/commit/decommit/release，P5.5 补齐
section-view 生命周期后，才能继续把 Windows agent 推进为完整候选。
