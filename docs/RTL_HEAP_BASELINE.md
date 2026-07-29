# Noleax Rtl Heap 未 Hook 基线

> 状态：P4.1 Windows x64 完成

## 1. 目的

P4.1 建立不加载 Noleax agent、不链接 Hoox 的独立压力目标。它是后续 Rtl hook 合同测试的行为
基线，不是产品可执行文件，也不是性能结论。

P4.2/P4.3 复用同一 workload 和摘要格式：分别运行未 hook 与 hooked 目标，比较返回状态、
内存内容、释放结果、`LastError` 指纹和确定性 checksum。不能为 hooked 场景另写一个更容易通过的
workload。

## 2. 测试目标

| 目标 | MSVC runtime | 用途 |
|---|---|---|
| `noleax-rtl-heap-baseline-md` | `/MDd` 或 `/MD` | 动态 CRT 路径 |
| `noleax-rtl-heap-baseline-mt` | `/MTd` 或 `/MT` | 静态 CRT 路径 |

两个目标由同一源文件构建，且都不链接 `noleax-agent`、Hoox 或 analyzer。CTest 先分别运行目标，
再由独立进程逐字节比较两种 CRT 的 stdout 摘要。

P4.3 为同一 executable 增加测试专用 `--hook-harness DLL` 参数。未提供时仍是 P4.1 原始路径；提供
时由独立 DLL 安装 passthrough hook，workload 本身仍不链接 Hoox。四路差分设计见
[RTL_ALLOCATE_HEAP_HOOK.md](RTL_ALLOCATE_HEAP_HOOK.md)。

## 3. Workload

每个 round 创建一个显式 heap，并同时使用 process heap。所有 worker 就绪后一起开始，每个 worker
按固定 seed 生成相同操作序列：

- 直接调用从 `ntdll.dll` 解析的 `RtlAllocateHeap` / `RtlFreeHeap`；
- 通过 `HeapAlloc` / `HeapFree` 间接进入 NT Heap；
- 通过 `malloc` / `calloc` / `free` 覆盖 CRT 间接路径；
- 覆盖零大小、1 至 4096 字节和周期性 64 至 128 KiB 分配；
- 覆盖 process heap、显式 heap、普通分配和 `HEAP_ZERO_MEMORY`；
- 每个 worker 保持最多 32 个同时存活 block，写入并重新校验确定性 payload，再逆序释放；
- 每个 worker 对 Rtl、Win32 Heap 和 CRT 各执行一次确定失败的超大分配；
- 多个 round 必须生成完全相同的摘要。

零填充分配会在第一次写入前检查所有字节。非零 payload 在释放前逐字节复核，因此重叠 live
allocation、越界影响、错误 heap 释放和内容损坏都会使目标返回非零。

## 4. 确定性摘要

成功时 stdout 只写一行 `status=ok version=1` 摘要。摘要不包含地址、线程调度顺序或耗时。

| 字段 | 含义 |
|---|---|
| `attempts` / `rtl` / `win32` / `crt` | 总尝试数和各入口尝试数 |
| `successes` / `expected_failures` / `frees` | 成功分配、预期失败和成功释放数 |
| `requested_bytes` | 成功分配请求的总字节数 |
| `zero_size` / `zero_verified_bytes` | 零大小调用数和验证过的零填充字节数 |
| `payload_verified_bytes` | 释放前重新验证的 payload 字节数 |
| `process_heap` / `explicit_heap` | 两类 Windows heap 的调用数 |
| `rtl_last_error_changes` / `win32_last_error_changes` | 调用后值不同于预置 sentinel 的次数 |
| `rtl_last_error_hash` / `win32_last_error_hash` | 每次调用实际 `LastError` 值的有序哈希 |
| `checksum` | API、大小、seed、内容和 worker 摘要的确定性哈希 |

对 `T` 个线程、每线程 `I` 次正常操作，固定满足：

- `attempts = T * (I + 3)`；
- `successes = frees = T * I`；
- `expected_failures = T * 3`；
- `payload_verified_bytes = requested_bytes`；
- `process_heap + explicit_heap = rtl + win32`。

原始 Windows Heap 在部分失败场景会修改 `LastError`，因此基线不假设 change count 必须为零。
同一参数的多轮运行必须得到相同 change count 和 hash；后续 hook 必须保持该原生指纹，不能用统一
恢复 sentinel 的方式改变系统本身的行为。

## 5. 运行方法

快速自动验证：

~~~powershell
. .\scripts\Enter-NoleaxDevShell.ps1
cmake --build --preset windows-x64-debug
ctest --preset windows-x64-debug -L baseline --output-on-failure
~~~

默认长压力运行：

~~~powershell
.\build\windows-x64-release\bin\noleax-rtl-heap-baseline-md.exe
.\build\windows-x64-release\bin\noleax-rtl-heap-baseline-mt.exe
~~~

自定义可重复运行：

~~~powershell
.\build\windows-x64-release\bin\noleax-rtl-heap-baseline-md.exe `
  --threads 16 --iterations 100000 --rounds 3 --seed 5642812718451281972
~~~

限制为 1 至 64 个线程、每线程 1 至 1,000,000 次操作和 1 至 100 个 round。seed 是 uint64 十进制
数。参数错误、API 解析失败、分配/内容/释放失败、round 摘要变化或 CRT 摘要不一致均返回非零。

## 6. P4.1/P4.3 边界

P4.1 路径不安装任何 hook。P4.3 已验证 passthrough trampoline、安装/卸载和 callback ABI，但尚未
记录事件。CFG/CET、Page Heap、Application Verifier 和 `HEAP_GENERATE_EXCEPTIONS` 隔离进程场景
保留到对应 P4 门禁。当前摘要不输出耗时；p50/p95/p99 必须使用独立计时，避免把正确性 oracle
变成不稳定快照。
