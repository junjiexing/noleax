# Windows replacement quiescence

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

此外另维护 `recording_in_flight`：只有读取到 `record` 快照的调用计入它；所有 replacement 调用仍计入
原有 `in_flight`。产品停止严格按以下顺序执行：

1. 所选 hook 一次性执行 `record -> original`，关闭新事件。
2. 等待 `recording_in_flight` 归零；新进入调用仍可透传 original，但不会访问 queue。
3. writer final drain、写 Statistics/EndOfTrace 并退出。
4. controller 停止或挂起目标 worker，避免物理 patch 时仍持续创建并运行目标线程。
5. 调用 `HookBackend::uninstall(target, 0)`，只 revert，禁止 Hoox flush。
6. revert 返回后发布 `target` 路由，再等待完整 replacement `in_flight` 归零。
7. 释放 trampoline lifetime lease，随后才允许 Hoox flush 和 deinit。

入口计数和路由快照使用同一个顺序一致原子序。读取到 `record` 的线程必然先计入
`recording_in_flight`；因此步骤 2 返回后 writer 可安全结束。物理卸载仍使用完整 `in_flight`；读取到
旧路由的线程必然已经计数，在 target 路由发布后才进入 replacement 的线程不再访问已经回收的
session。

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

heap 组合对象与 `NtMemoryHooks` 的 event queue 都由独立所有权持有。若协调安装的 hook
任一无法 quiesce，协调器会
连同 hook state 一起保留共享 queue，避免只保留单 hook state、却随后析构其外部 queue 的
use-after-free。

writer 在 hook 已完全卸载，或仍 installed 但已逻辑停录、`recording_in_flight=0` 时接受
`finish()`；teardown-pending 或仍记录时拒绝结束。后者是产品 profile 的标准路径，保证 final drain
之后不会再出现 queue producer，同时把危险的物理 patch 延后到目标 worker 停止之后。

## 5. 模块引用和 patch rendezvous

在 patch 激活前，adapter 使用 `GetModuleHandleExW(..., GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS)`
对承载 replacement 的模块持有普通 +1 引用，不再永久 pin。入口计数看不到 in-transit 线程（已取到
旧跳转、尚未走进入口计数器的线程），所以只有在证明这类线程已经不存在之后，引用才能释放。

证明由 patch rendezvous 完成。各 replacement 入口函数和 `ReplacementLifecycle` 的 gate 与
enter/leave 计数窗口编译进专用 `.nlxhk` 段：in-transit 线程从旧跳转落地到入口计数自增之间，RIP
必然位于该段；对称地，线程在退出计数归零后到离开 replacement 之前的尾迹也在该段。段内刻意不放
其他 agent 代码（writer、tracker 等），避免无关线程造成 rendezvous 假失败；gate 读取线程深度不
调用共享的 guard 查询（它们的被调在段外会成为扫描盲区），而是走只有 gate 调用的专用 probe，
同样放进该段。gate 关闭期间停在等待循环里的线程会把 RIP 留在 CRT 原子等待代码中，对 RIP 扫描
不可见；若其中混有尚未计数的 in-transit 线程，gate 重新打开后它会继续走进入口计数并触碰 hook
state。因此 finalize 在 backend shutdown 之后先重开 gate，让可运行的 parked 线程按
restored-target 路由排空（`wait_for_drain` 等待 waiter/transition/active 计数归零）才销毁 hook
实例；仍被 controller 冻结的 waiter 无法唤醒，无法排空时按进程生命期保留 profile，让它们之后
醒来时读到的是仍然有效的状态，而不是释放仍可能被解引用的内存。相应地，未来实现 attach 卸载
agent 时，卸载决策也必须把 gate waiter 计数纳入考量（被冻结的 waiter 醒来还要执行 gate 代码）。
teardown
在 backend flush 完成之后、`finish_teardown` 之前执行 rendezvous：

1. Toolhelp 枚举进程线程，跳过当前线程，逐个 OpenThread + SuspendThread，记录到固定容量的静态
   存储；重复枚举直到一整轮没有新挂起的线程，覆盖枚举期间的线程创建。
2. 全部挂起后逐线程读取 `CONTEXT_CONTROL`，任何 RIP 落在 `.nlxhk` 段内即判本轮失败。
3. 恢复所有由本轮挂起的线程（各只 ResumeThread 一次，不影响外部既有的挂起计数），关闭句柄。
4. 全部干净才判成功；否则 yield 后有界重试。

rendezvous fail-closed：region 为空、线程无法打开/挂起/读取、静态存储容量耗尽、或并发进入
rendezvous，都判失败。挂起期间不做堆分配、不调用 loader API、不持任何锁。

rendezvous 成功后 adapter 才 `FreeLibrary` 释放模块引用（DLL 之后可真正卸载），并把
`installation_retired` 复位，允许用新实例进行下一轮安装；实例级 `State::kRetired` 不变，旧实例
不复用。rendezvous 失败时保持 teardown-pending、保持模块引用和 retired 标志，每次 `flush()` 重试
都会重新执行 rendezvous：被 controller 冻结在 replacement 入口的 worker 会让 rendezvous 持续失败，
worker 恢复后 in-transit 线程按 `target` 路由排空，后续 flush 即可成功。
`abandon_pending_teardown` 路径不变：失败就故意保留全部状态与模块引用。

`--unload-on-stop`（仅 attach）在收尾完成后把 agent DLL 从仍在运行的目标卸载：agent 在
finalize 后启动一个卸载 watchdog，轮询全部证明——全部 adapter 的 replacement 模块引用都已
释放（进程级引用计数为零）、`wait_for_drain` 确认 gate 无 parked 线程且 transition/active
归零。watchdog 而不是 finalize 同步点卸载的原因：live attach 的 finalize 会冻结目标 worker，
parked waiter 要等 controller 恢复后才能排空，同步点永远等不到。证明成立后 watchdog 调
`FreeLibraryAndExitThread`（该调用不再返回）；60 秒仍不成立则保持驻留（现状语义）。live 管道
模式在 `kCaptureFinalized` 应答后启动 watchdog，直写模式在 duration 收尾后启动。

当前仍保留一个刻意限制：产品 profile 不承诺在目标线程持续运行时安全物理 revert；controller 必须
先停住目标 worker。rendezvous 证明的是"没有线程还在 replacement 代码段内"；线程 RIP 停在 patch 区
mid-instruction 的窗口由上游 hoox 的 PC guard 覆盖（见 §6），与 rendezvous 是两个不同的窗口。早先的
另外两条限制（模块永久 pin、每进程只允许一次成功安装）随 rendezvous 的排空证明移除。

## 6. Windows patch 写入安全

Hoox（上游 v0.2.0，以 amalgamation 形式 vendor 在 `third_party/hoox`）在 Windows 代码更新临界区
一律暂停 peer threads，只做临界区安全的最小改动：

- RWX 页面也暂停 peer threads；
- 重复枚举并去重 thread ID，覆盖卸载同时发生的线程创建；
- 检查 `SuspendThread`/`ResumeThread` 返回值；
- 使用 Hoox 已有的 VirtualAlloc-backed metal array，patch apply 临界区不走 process heap。

PC guard（上游默认关闭，noleax 在编译 hoox.c 的 target 上定义 `HOOX_WINDOWS_PATCH_PC_GUARD`
启用）：`hoox_memory_patch_code_pages_guarded` 接收调用方给出的 guard 区间；
`hoox_interceptor_transaction_end` 从 pending update tasks 为每个被 patch 函数生成一条
`(function_address, function_address+overwritten_prologue_len)` 开区间。挂起窗口内逐线程
OpenThread + `GetThreadContext` 读取 RIP，任何 RIP 落在区间内即恢复全部线程、Sleep(1)、
重新挂起并重扫，最多 100 次；耗尽则 patch 失败走 `hx_abort`。读取线程上下文失败同样按"不干净"处理
（fail-closed）。开区间设计对两个方向都安全：apply 时停在 addr+0 的线程恢复后执行 jump 进
replacement，revert 时停在 addr+0 的线程执行已恢复的原指令；patch 激活期间不可能有线程 PC 停在
开区间内，因此 revert 方向实践中不触发重试。

无法打开或暂停的受保护线程仍是当前边界；当前版本不支持 protected process。线程 PC 停在 patch 区
mid-instruction 的风险已由上述 PC guard 覆盖，不再是"运行中安装/卸载必须停 worker"的原因。

## 7. 自动验证

测试覆盖：

- held entry、路由快照和有界 quiescence 的确定性单测；
- lifetime lease 阻止 uninstall flush 和 shutdown deinit；
- allocate/reallocate/free 各自用 8 个持续 worker；五 hook heap 组合及五入口 NT memory 组合另用持续
  memory lifecycle 循环和线程 churn，同时执行 `uninstall(0)` 与后续 flush；
- 停止完成后继续执行至少 20,000 次分配，确认记录计数不再变化；
- queue 的 `recordable = dequeued + dropped` 守恒；
- patch rendezvous 单测：`.nlxhk` region 解析、空 region fail-closed、段内自旋线程有界判失败、
  线程离开后判成功；
- patch PC guard 确定性集成测试：worker 线程自旋在待 patch 的 stub 字节内，`install_fast_forced`
  被 guard 阻塞、直到 worker 离开区间后才成功；随后 stub 走 replacement、original trampoline 正常
  返回、uninstall 成功；
- 成功 stop 和 `FreeLibrary` 后模块引用已释放，harness DLL 真正解除映射；
- allocate 单 adapter、五 hook heap 组合和 NT memory 组合各自卸载复位后用新实例重装，分配/VM
  操作仍被记录，再次卸载后引用同样释放；
- 原有 writer final drain、MD/MT ABI 差分和全量回归。

native profile 组合验证：九个逻辑 API 共用一个 queue；持续 heap/VM worker 与线程 churn
期间先逻辑停录，停录后的九组 recordable counter 保持不变；writer 先完成并退出，worker 停止后才
物理 uninstall。该组合同时验证 `written + filtered + dropped = observed` 和正式 trace 回读。

整体验证中，五组既有 race 与 native profile 各连续 100/100；Debug/Release 各 205/205、hardened
230/230，Application Verifier/Full Page Heap 三轮通过。

NT VM 组合加入时，Debug/Release 全量均为 193/193，hardened 为 213/213。加入 Windows RWX 暂停
overlay 后，allocate/reallocate/free、五 hook heap lifecycle 和双 hook NT VM 并发 race（含 thread
churn）各连续 100 次通过；overlay 前原 allocate Debug 测试在第 17 次出现崩溃。Release
module-retention、passthrough、writer 与组合生命周期测试也全部通过。

section 入口加入后，NT memory 组合扩展到 allocate/free/map/legacy unmap/Ex unmap 五个物理入口。
Debug/Release 各 195/195、hardened 216/216；五组 race 各 100/100，其中 NT memory workload 同时执行
direct section map/legacy unmap 与 `MapViewOfFile`/Ex unmap。停止后四种逻辑 operation 的计数均保持
稳定，共享 queue 的 `recordable = dequeued + dropped` 守恒。

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
