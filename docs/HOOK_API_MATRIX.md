# Windows V1 Hook API Matrix

> 状态：P0 基线
> backend：Hoox v0.1.1 replace_fast
> target：Windows x64

## 1. Profile

| Profile | API |
|---|---|
| windows-nt-heap | RtlCreateHeap、RtlDestroyHeap、RtlAllocateHeap、RtlReAllocateHeap、RtlFreeHeap |
| windows-virtual-memory | NtAllocateVirtualMemory、NtFreeVirtualMemory、NtMapViewOfSection、NtUnmapViewOfSection |
| windows-native | 两组并集 |

## 2. 通用合同

每个 adapter 必须：

- 使用与 Windows x64 ABI 完全匹配的函数类型。
- 使用 Hoox replace_fast 获得 original trampoline。
- 调用 original 恰好一次。
- 在 original 返回后保存其 LastError，并在记录后恢复。
- 对 NTSTATUS 直接保存原始返回值。
- 不在 replacement 中分配 heap、解析符号、写文件或等待阻塞锁。
- 只写入预分配事件队列。
- 提供独立 in-flight counter。
- 支持关闭记录后安全 revert/flush。

## 3. NT Heap

### 3.1 RtlCreateHeap

模块：ntdll.dll

概念签名：

~~~
PVOID NTAPI RtlCreateHeap(
  ULONG Flags,
  PVOID HeapBase,
  SIZE_T ReserveSize,
  SIZE_T CommitSize,
  PVOID Lock,
  PVOID Parameters);
~~~

注意：具体 SDK 声明在实现时以当前 Windows SDK 为准，不从文档复制 typedef。

语义：

- 返回非 null 为成功。
- 成功时创建 heap_id。
- 记录 raw heap handle、flags、reserve 和 commit size。

必要测试：

- 默认参数成功。
- reserve/commit 组合。
- 显式 HeapBase 可支持场景。
- 失败路径。
- create 后 alloc/free/destroy。

### 3.2 RtlDestroyHeap

概念签名：

~~~
PVOID NTAPI RtlDestroyHeap(PVOID HeapHandle);
~~~

语义：

- 返回 null 表示成功。
- 成功时结束该 heap 所有 live allocation generation。
- 失败时不修改状态。

必要测试：

- 空 heap。
- 含 live allocations 的 heap。
- 多 heap 隔离。
- 失败/无效场景使用子进程测试，结果与未 hook 基线比较。

### 3.3 RtlAllocateHeap

概念签名：

~~~
PVOID NTAPI RtlAllocateHeap(
  PVOID HeapHandle,
  ULONG Flags,
  SIZE_T Size);
~~~

语义：

- 返回非 null 为成功。
- 成功时生成 allocation_id。
- 记录 heap、flags、requested size 和 result address。

必要测试：

- size 0。
- 常见大小和大块。
- HEAP_ZERO_MEMORY。
- HEAP_GENERATE_EXCEPTIONS 使用隔离进程。
- 可控制分配失败。
- 单线程、多线程、递归保护。
- exact Rtl API 与 HeapAlloc/CRT 间接调用。
- Page Heap、CFG、CET。

### 3.4 RtlReAllocateHeap

概念签名：

~~~
PVOID NTAPI RtlReAllocateHeap(
  PVOID HeapHandle,
  ULONG Flags,
  PVOID BaseAddress,
  SIZE_T Size);
~~~

语义：

- 成功条件和零大小行为以 Windows 实际合同及差分测试为准。
- 成功时结束旧 allocation generation 并创建新 generation。
- 地址不变仍创建新 generation。
- 失败时旧 generation 保持 live。

必要测试：

- 原地成功。
- 移动成功。
- HEAP_REALLOC_IN_PLACE_ONLY。
- size 0。
- 失败后旧内存仍有效。
- 不同 heap 的错误输入在子进程中做基线差分。

### 3.5 RtlFreeHeap

概念签名：

~~~
BOOLEAN NTAPI RtlFreeHeap(
  PVOID HeapHandle,
  ULONG Flags,
  PVOID BaseAddress);
~~~

语义：

- 返回 TRUE 为成功。
- 成功时仅结束同一 `(heap_handle, address)` 的匹配 allocation generation。
- 成功但未知的非零地址在 CaptureScope 声明存在未知旧分配时写 `preexisting`，否则写
  `unmatched`；成功的 null address 写 `unmatched`。
- 返回失败或以 SEH 离开时保持原 generation live；异常事件保留 NTSTATUS。
- alloc/free 必须共用一个 queue，不能用两个独立队列的时间戳推断生命周期顺序。

必要测试：

- 正常 free。
- null/zero 行为差分。
- 未跟踪的 preexisting allocation。
- double free/错误 heap 只在隔离子进程中与基线比较。
- 多线程跨线程 free。

## 4. NT Virtual Memory

### 4.1 NtAllocateVirtualMemory

概念签名：

~~~
NTSTATUS NTAPI NtAllocateVirtualMemory(
  HANDLE ProcessHandle,
  PVOID* BaseAddress,
  ULONG_PTR ZeroBits,
  PSIZE_T RegionSize,
  ULONG AllocationType,
  ULONG Protect);
~~~

语义：

- NT_SUCCESS(status) 为成功。
- 记录调用前后的 BaseAddress 和 RegionSize。
- 只为当前进程成功操作创建 mapping_id。
- 其他进程操作保留 raw event，但不进入本进程状态。

必要测试：

- reserve、commit、reserve+commit。
- requested null base 和指定 base。
- protection 组合。
- 大小对齐后的输出。
- 失败 NTSTATUS。
- 直接调用和 VirtualAlloc 包装调用。

### 4.2 NtFreeVirtualMemory

概念签名：

~~~
NTSTATUS NTAPI NtFreeVirtualMemory(
  HANDLE ProcessHandle,
  PVOID* BaseAddress,
  PSIZE_T RegionSize,
  ULONG FreeType);
~~~

语义：

- NT_SUCCESS(status) 为成功。
- 记录调用前后的 base/size。
- MEM_RELEASE 和 MEM_DECOMMIT 分开建模。
- 只有 release 结束完整 mapping generation；decommit 改变 committed range，不等价于释放 address reservation。

必要测试：

- MEM_RELEASE。
- MEM_DECOMMIT。
- 部分区域。
- 失败 NTSTATUS。
- VirtualFree 包装路径。

### 4.3 NtMapViewOfSection

概念签名：

~~~
NTSTATUS NTAPI NtMapViewOfSection(
  HANDLE SectionHandle,
  HANDLE ProcessHandle,
  PVOID* BaseAddress,
  ULONG_PTR ZeroBits,
  SIZE_T CommitSize,
  PLARGE_INTEGER SectionOffset,
  PSIZE_T ViewSize,
  SECTION_INHERIT InheritDisposition,
  ULONG AllocationType,
  ULONG Win32Protect);
~~~

语义：

- NT_SUCCESS(status) 为成功。
- 当前进程成功映射创建 mapping_id。
- 记录输出 base/view size 和 section offset。

必要测试：

- pagefile-backed section。
- file-backed section。
- read-only/read-write。
- offset 和 view size。
- MapViewOfFile 包装路径。

### 4.4 NtUnmapViewOfSection

概念签名：

~~~
NTSTATUS NTAPI NtUnmapViewOfSection(
  HANDLE ProcessHandle,
  PVOID BaseAddress);
~~~

语义：

- NT_SUCCESS(status) 为成功。
- 成功时结束匹配 mapping_id。
- 未匹配地址记录 unmatched。

必要测试：

- 正常 unmap。
- 非 view 基址输入。
- 重复 unmap。
- UnmapViewOfFile 包装路径。

## 5. 间接覆盖但不直接 hook

默认 profile 不直接 hook：

- HeapAlloc/HeapReAlloc/HeapFree。
- LocalAlloc/LocalReAlloc/LocalFree。
- GlobalAlloc/GlobalReAlloc/GlobalFree。
- malloc/calloc/realloc/free。
- C++ new/delete。
- CoTaskMemAlloc/Realloc/Free。
- VirtualAlloc/VirtualFree。
- MapViewOfFile/UnmapViewOfFile。

这些调用落到规范化底层 API 时仍被捕获。第三方 allocator 只进行大块 VM 申请并在内部切分时，V1 只能看到 backing mapping；后续 custom symbol hook 才能看到其逻辑 allocations。

## 6. 测试注册状态

实现阶段维护以下状态，任何 enabled API 不得缺少 mandatory tests：

| API | Adapter | Unit | Contract | Concurrency | CFG/CET | Page Heap | Enabled |
|---|---:|---:|---:|---:|---:|---:|---:|
| RtlCreateHeap | pending | pending | pending | pending | pending | pending | no |
| RtlDestroyHeap | pending | pending | pending | pending | pending | pending | no |
| RtlAllocateHeap | P4.9 hardened prototype | guard/shared-queue/stack/SEH pass | ABI/LastError/exception/overflow/stack pass | 8x20k + alloc/free quiescence pass | PE + runtime pass | AppVerifier Full 3/3 pass | no |
| RtlReAllocateHeap | pending | pending | pending | pending | pending | pending | no |
| RtlFreeHeap | P5.1 review candidate | guard/shared-queue/stack/SEH pass | return/LastError/exception/fail-fast/trace pass | cross-thread + 8x20k + quiescence pass | PE + runtime pass | AppVerifier Full 3/3 pass | no |
| NtAllocateVirtualMemory | pending | pending | pending | pending | pending | pending | no |
| NtFreeVirtualMemory | pending | pending | pending | pending | pending | pending | no |
| NtMapViewOfSection | pending | pending | pending | pending | pending | pending | no |
| NtUnmapViewOfSection | pending | pending | pending | pending | pending | pending | no |

P5.1 在 P4.9 allocate prototype 上增加 `RtlFreeHeap`，并把两种事件放入同一个预分配 MPSC queue，
形成跨 API 的唯一 sequence。组合 writer 按 `(heap,address)` 关联 allocation_id，覆盖 matched、
cross-thread、preexisting、unmatched 和 outstanding generation；每个 API 的调用/成功/失败/丢失统计
分别守恒。free 合同覆盖普通返回与 SEH；bad address、wrong heap、double free 的隔离进程
baseline/hooked 均为 `0xc0000374`。

完整门禁为 Debug/Release 182/182、hardened 192/192、alloc/free quiescence 各 100/100、10 个 PE 的
CFG/CET metadata/runtime 和 Application Verifier/Full Page Heap 三轮；本轮 27 份 verifier 日志为零
记录，7 个 IFEO key 全部回滚。默认 profile 仍保持 disabled，因为 realloc、heap generation 和 VM/
section-view API 尚未补齐。workload 与 hardening 证据见
[RTL_HEAP_BASELINE.md](RTL_HEAP_BASELINE.md) 和
[RTL_ALLOCATE_HEAP_HOOK.md](RTL_ALLOCATE_HEAP_HOOK.md)，guard 设计与崩溃根因见
[HOOK_GUARD.md](HOOK_GUARD.md)，队列合同见 [EVENT_QUEUE.md](EVENT_QUEUE.md)，栈合同见
[STACK_CAPTURE.md](STACK_CAPTURE.md)，free 设计见
[RTL_FREE_HEAP_HOOK.md](RTL_FREE_HEAP_HOOK.md)，平台门禁见
[WINDOWS_HOOK_HARDENING.md](WINDOWS_HOOK_HARDENING.md)。
