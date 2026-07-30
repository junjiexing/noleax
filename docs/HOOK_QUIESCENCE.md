# Windows replacement quiescence

> 状态：P4.8 Windows x64 完成；P5.5 已对五个 NT Heap 与五个 NT memory 物理入口复用
> 范围：Windows memory adapter 的停止记录、并发 revert、trampoline 回收和代码生命周期

## 1. 要解决的窗口

Hoox v0.1.1 的 `flush` 只跟踪 original trampoline。它看不到 replacement 已进入但尚未调用
original、original 已返回但 replacement 尚未退出，以及已经取到 target 跳转但尚未执行
replacement 第一条指令的线程。仅在 replacement 入口加一个计数器，不能证明 DLL 可以卸载。

Windows RWX patch 路径还有一个独立问题。本机 Windows x64 上，Hoox 对
`ntdll!RtlAllocateHeap` 覆盖 18 字节：5 字节跳转后跟 NOP padding。v0.1.1 在 RWX 页面上直接写入
这段多字节 patch，不暂停其他线程。最初的并发卸载测试在第 17 次重复时出现进程崩溃，证明“先
revert，再等 replacement counter”仍不安全。

## 2. replacement 路由和顺序

每次 replacement 先以顺序一致原子操作增加 in-flight，再读取一次路由快照。路由只有三种：

| 路由 | 行为 |
|---|---|
| `record` | 调用 trampoline，执行 guard、计数、栈捕获和 queue publish |
| `original` | 只调用 trampoline，不再产生事件 |
| `target` | 调用对应的已恢复 target，不访问 session、queue、guard 或 trampoline |

正常停止严格按以下顺序执行：

1. `record -> original`，先关闭新事件。
2. 调用 `HookBackend::uninstall(target, 0)`，只 revert，禁止 Hoox flush。
3. Hoox overlay 在改写 target 前暂停其他线程；Windows 上重复线程快照，直到没有新线程需要暂停，
   再写 patch、flush instruction cache 并恢复线程。
4. revert 返回后发布 `target` 路由。
5. 等待 Noleax replacement in-flight 归零。
6. 释放 trampoline lifetime lease，随后才允许 Hoox flush 和 deinit。
7. 清除活动 session；writer 此时可以 final drain、写 Statistics/EndOfTrace 并退出。

入口计数和路由快照使用同一个顺序一致原子序。读取到旧路由的线程必然已经计入 in-flight；在路由
切换后才执行第一条 replacement 指令的线程会读取 `target`，不再访问已经回收的 session。

## 3. Hoox lifetime lease

adapter 在激活 patch 前取得 backend 的 trampoline lifetime lease。lease 存在时：

- revert 仍可执行；
- `flush` 返回 false，不调用 Hoox flush；
- `shutdown` 可以 revert target，但不能释放 interceptor/trampoline；
- backend 析构失败时故意保留 Hoox 引用，由进程退出回收。

这解决了 replacement 暂停在 original 调用之前、而 Hoox 自己的 trampoline usage counter 仍为零的
窗口。多个 target 共用 backend 时，lease 会保守地阻止该 backend 的全部 pending teardown。

## 4. 超时和析构的 fail-safe

`uninstall(0)` 一定留下显式 `teardown_pending`；调用方通过 `flush(max_attempts)` 重试。若
replacement 未在有界等待内退出，lease 不释放，Hoox 不 flush。若对象在此状态析构，session、
original trampoline、event queue、guard runtime 引用和 backend lease 都转为进程级保留，不能为了
避免泄漏而释放仍可能被线程使用的状态。

P5.3 heap 组合对象与 P5.5 `NtMemoryHooks` 的 event queue 都由独立所有权持有。若协调安装的 hook
任一无法 quiesce，协调器会
连同 hook state 一起保留共享 queue，避免只保留单 hook state、却随后析构其外部 queue 的
use-after-free。

writer 只有在 hook 不再 installed 且不再 teardown-pending 时才接受 `finish()`，所以 final drain
之后不会再出现 queue producer。

## 5. DLL pin 和当前限制

在 patch 激活前，adapter 使用 `GetModuleHandleExW(..., GET_MODULE_HANDLE_EX_FLAG_PIN)` 将承载
replacement 的模块固定到进程退出。即使线程已取到旧跳转但尚未被入口计数覆盖，replacement 代码也
不会被 `FreeLibrary` 解除映射；该线程随后读取 `target` 路由并走已恢复入口。

因此当前 adapter 有两个刻意限制：

- `FreeLibrary` 可以释放调用方引用，但包含 replacement 的 DLL 仍驻留到进程退出；
- adapter 集合各自每进程只允许一次成功安装，避免旧跳转被误归入下一捕获 generation。

真正可重复安装并可解除模块 pin 的方案需要可证明覆盖所有线程 PC 的 patch rendezvous，留给后续
注入生命周期设计。当前接口不会把“停止记录”误报为“DLL 已可解除映射”。

## 6. Windows patch overlay

`ports/hoox/windows-rwx-patch-quiescence.patch` 不改变 Hoox 版本、relocator 或 trampoline 布局，只修改
Windows 代码更新临界区：

- RWX 页面也暂停 peer threads；
- 重复枚举并去重 thread ID，覆盖卸载同时发生的线程创建；
- 检查 `SuspendThread`/`ResumeThread` 返回值；
- 使用 Hoox 已有的 VirtualAlloc-backed metal array，patch apply 临界区不走 process heap。

无法打开或暂停的受保护线程仍是当前边界；当前版本不支持 protected process。运行中安装的线程 PC
重定位也不在本阶段范围内，只在 hook 激活后创建压力线程并验证并发停止。

## 7. 自动验收

测试覆盖：

- held entry、路由快照和有界 quiescence 的确定性单测；
- lifetime lease 阻止 uninstall flush 和 shutdown deinit；
- allocate/reallocate/free 各自用 8 个持续 worker；五 hook heap 组合及五入口 NT memory 组合另用持续
  memory lifecycle 循环和线程 churn，同时执行 `uninstall(0)` 与后续 flush；
- 停止完成后继续执行至少 20,000 次分配，确认记录计数不再变化；
- queue 的 `recordable = dequeued + dropped` 守恒；
- 成功 stop 和 `FreeLibrary` 后模块仍被 pin，导出代码仍可执行；
- 原有 writer final drain、MD/MT ABI 差分和全量回归。

P5.4 Debug/Release 全量均为 193/193，hardened 为 213/213。加入 Windows RWX 暂停 overlay 后，
allocate/reallocate/free、五 hook heap lifecycle 和双 hook NT VM 并发 race（含 thread churn）各连续
100 次通过；overlay
前原 allocate Debug 测试在第 17 次出现崩溃。Release module-retention、passthrough、writer 与组合
生命周期测试也全部通过。

P5.5 将 NT memory 组合扩展到 allocate/free/map/legacy unmap/Ex unmap 五个物理入口。Debug/Release
各 195/195、hardened 216/216；五组 race 各 100/100，其中 NT memory workload 同时执行 direct
section map/legacy unmap 与 `MapViewOfFile`/Ex unmap。停止后四种逻辑 operation 的计数均保持稳定，
共享 queue 的 `recordable = dequeued + dropped` 守恒。

Release x64 object 的 replacement 反汇编复核确认，正常路径只调用 original/恢复后的 target、
固定 TEB 槽 guard、`GetLastError`/`SetLastError`、`QueryPerformanceCounter`、
`GetCurrentThreadId`、静态无锁 queue helper 和受审计的 raw stack capture；queue helper 的 relocation
只包含 QPC、thread ID 和 stack capture。没有 allocator、I/O、loader、mutex、TLS API 或 CRT TLS
引用。`terminate` 和
fast-fail 只位于 counter overflow/underflow、空路由等不可恢复内部不变量分支。

Release MD/MT ABI 长差分使用 8 个线程、每线程 20,000 次操作、2 个 round，hooked 与各自 baseline
逐字节一致：

~~~text
attempts=160024 successes=160000 expected_failures=24 frees=160000
rtl_last_error_changes=8 win32_last_error_changes=8
rtl_last_error_hash=0x2fc65ff63169b923
win32_last_error_hash=0xdb3089d8201ac1a3
checksum=0x7caf2ccfa0606232
~~~

运行方法：

~~~powershell
. .\scripts\Enter-NoleaxDevShell.ps1
cmake --build --preset windows-x64-debug
ctest --preset windows-x64-debug -R "replacement lifecycle|lifetime lease|quiescence|module-retention" --output-on-failure
ctest --preset windows-x64-debug -R "hook.(rtl-.*heap|nt-virtual-memory).*quiescence-race" --repeat until-fail:100 --output-on-failure
ctest --preset windows-x64-release -R "hook.(rtl-.*heap|nt-virtual-memory).*quiescence-race" --repeat until-fail:100 --output-on-failure
~~~
