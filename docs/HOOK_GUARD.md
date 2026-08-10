# Hook Recursion and Internal-Thread Guard

> 范围：入口分类与抑制判定；尚不生成内存事件

## 1. 目标

allocator replacement 必须在不分配内存、不获取锁、不执行 I/O、不过 loader API，且不修改
`LastError` 的前提下区分三类入口：

- `outermost`：应用线程的最外层 hook，可以记录；
- `recursive`：同一线程已经位于任一 hook 中，必须抑制；
- `internal-thread`：agent 自身线程或作用域，必须抑制，优先级高于 recursive。

每个入口都会增加该线程的 hook depth，退出时恢复。`InternalThreadScope` 支持嵌套，最外层作用域
退出后才清除 internal 状态。guard 只维护分类计数，用来证明真实 replacement 执行了正确分支；事件
队列在 guard 分类之后接入。

## 2. static TLS 崩溃根因

开发中的第一版使用了 trivial、`constinit` 的 `thread_local` 状态。它不需要动态构造，但在真实
`RtlAllocateHeap` hook 下仍会使新线程崩溃。CDB 栈显示线程正位于：

~~~text
ntdll!LdrpGetNewTlsVector
ntdll!LdrpAllocateTls
...
ntdll!RtlAllocateHeap
noleax replacement
~~~

此时 loader 正在为新线程建立模块 static TLS vector，`RtlAllocateHeap` 已经进入 replacement；
replacement 再访问 DLL 的 static TLS，会读取尚未发布的 vector。故障指令为
`mov rdx, qword ptr [rax+rdx*8]`，其中 `rax == 0`。

问题是 static TLS 查找本身发生得太早，而不是对象是否有构造函数。因此 trivial
`thread_local`、延迟初始化或删除 TLS 析构函数都不能解决该递归。

## 3. Windows 固定 TLS 槽设计

安装 hook 前，guard runtime 在冷路径调用一次 `TlsAlloc`。只接受
`0 <= index < TLS_MINIMUM_AVAILABLE` 的索引，即直接位于 `TEB::TlsSlots[64]` 的固定槽；如果只剩
expansion slot，则立即 `TlsFree` 并拒绝创建 hook adapter。这样不会在热路径访问尚未建立的
static TLS vector 或 expansion storage。

一个槽使用指针宽度的位模式保存两个计数：

~~~text
63                         32 31             16 15              0
+----------------------------+-----------------+-----------------+
|          reserved          | internal depth  |   hook depth    |
+----------------------------+-----------------+-----------------+
~~~

两个 depth 均为 16 bit，零值表示线程尚未进入 guard。热路径通过 SDK 声明的
`NtCurrentTeb()->TlsSlots[index]` 直接读写，不调用 `TlsGetValue`/`TlsSetValue`，因此：

- 新线程不需要模块 static TLS vector；
- 不会触发 TLS storage 分配；
- 不会因 `TlsGetValue` 的合同修改 `LastError`；
- 不需要每线程对象、析构回调或释放动作。

索引通过原子变量发布。runtime 使用进程内引用计数，多个 adapter 可以共享同一槽；最后一个
adapter 只有在 hook 已进入 inactive 状态后才释放槽。索引缺失、索引越界、depth 上溢或不配对的
退出均是内部不变量损坏，采用 fail-fast，而不是静默把事件分类错。

非 Windows 的 `thread_local` 分支当前只是可编译占位，不代表 Linux/macOS allocator hook 已通过
动态加载安全审计。对应平台启用 profile 前必须替换或证明其 TLS 模型不会在 hook 热路径分配。

## 4. Replacement 路径

`RtlAllocateHeap` replacement 的顺序为：

1. 进入 unscoped guard 并增加 hook depth；
2. 按 `internal-thread > recursive > outermost` 分类；
3. 增加无锁诊断计数；
4. acquire-load original trampoline 并调用；
5. MSVC `__finally` 恢复 hook depth；普通 RAII `HookInvocationGuard` 继续供非 replacement 作用域使用。

步骤 4 之后，outermost 调用写入预分配 event queue；这不改变 guard 的 TLS 路径或
recursive/internal-thread 抑制规则，详见 [EVENT_QUEUE.md](EVENT_QUEUE.md)。

Release x64 object 反汇编确认 guard 正常路径只有原子 index load、`gs:[TEB]` 固定槽访问、整数
位运算和 store；没有 heap、锁、文件、loader、日志或 TLS API 调用。对象中不存在 `.tls$` 段或
CRT `_tls_index` 引用。`TlsAlloc`/`TlsFree` 只存在于 adapter 安装前和安全 teardown 后的冷路径。

`HEAP_GENERATE_EXCEPTIONS` 隔离进程合同已完成。original 以 SEH 离开时，C++ `/EHsc` RAII
不作为异步异常清理保证；replacement 因此通过显式 enter/leave pair 和 `__finally` 恢复 guard，外层
handler 返回后 depth 必须为零。replacement in-flight/quiescence 见
[HOOK_QUIESCENCE.md](HOOK_QUIESCENCE.md)。

## 5. 验证

单元测试覆盖：

- runtime acquire/release 与多个 owner 的引用计数；
- outermost/recursive 分类和 depth 恢复；
- unscoped enter/leave 的平衡恢复；
- 嵌套 internal scope 及其分类优先级；
- 新线程初始状态和线程间隔离。

真实 hook harness 在安装后、运行 workload 前，分别制造 outermost、recursive 和 internal-thread
入口，要求只有对应计数增加。随后才创建 workload worker，这同时回归 loader 建立新线程 TLS 的
原始崩溃。

Debug/Release 的定向测试均通过；真实 passthrough 在两个配置下各连续重复 20 次。Release
8×20,000×2 长压力中，MD/MT 的 hooked 与 unhooked 摘要逐字节一致，包括 `LastError` 计数和 hash。

~~~powershell
. .\scripts\Enter-NoleaxDevShell.ps1
cmake --build --preset windows-x64-debug
cmake --build --preset windows-x64-release
ctest --preset windows-x64-debug -R "hook guard|rtl-allocate-heap-passthrough" --output-on-failure
ctest --preset windows-x64-release -R "hook guard|rtl-allocate-heap-passthrough" --output-on-failure
ctest --preset windows-x64-release -L passthrough --repeat until-fail:20
~~~

## 6. Linux 实现：initial-exec TLS

> 状态：已实现（Linux 移植 M1）。非 Windows 分支此前是"仅保证可编译"的占位，现已按本节模型固化。

Linux 侧的崩溃类与第 2 节相同，触发点不同：glibc 默认 TLS 模型（global-dynamic）首次访问
要过 `__tls_get_addr`，该函数可能分配内存——在 malloc hook 的热路径里等于递归进入被 hook 的
分配器。Linux 模型的选择是把分配可能性从结构上消掉，而不是找"安全的调用点"：

- agent 侧 target（`noleax-hook-backend`、`noleax-agent`）以 `-ftls-model=initial-exec` 编译，
  guard 状态保持 `constinit thread_local` POD。编译产物中对 guard 状态的访问是直接的
  `%fs` 段寻址：无函数调用、无分配、无锁。
- LD_PRELOAD 在进程启动期加载 agent，静态 TLS 块随模块加载分配，constructor 运行前由 ld.so
  完成初始化；新线程的静态 TLS 镜像由 pthread_create 按初始镜像复制。因此 guard 在任何
  可达上下文（含信号 handler、loader 早期）都可用。
- `runtime_ready` 门控语义与 Windows 一致：`acquire_hook_guard_runtime` 前读写按未就绪处理
  （probe 返回零深度，直接读写 terminate）。
- 结构回归：`tests/cmake/VerifyLinuxAgentTls.cmake` 用 readelf 断言 agent DSO 不含
  `__tls_get_addr` 引用与 `R_X86_64_TLS_GD/LD` 重定位，防止任何 TU 退回动态 TLS 模型。
- 行为回归：POSIX 信号 handler 内做 guard 进出并断言分类正确（模拟最苛刻的异步上下文）。

已知边界：attach（M6，ptrace dlopen 迟加载 agent）依赖 glibc 的静态 TLS 盈余区
（`TLS_STATIC_SURPLUS`）；agent 的 TLS 占用仅数字节，常规进程不成问题，盈余耗尽时 dlopen
失败、attach 以注入失败报错——可接受的失败语义，届时在 attach 文档记录。
