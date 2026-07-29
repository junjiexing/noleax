# Hoox v0.1.1 可行性审计

> 状态：P0 初步通过，Windows x64 仍受 P4 专项门禁约束
> 审计日期：2026-07-29
> 审计对象：https://github.com/junjiexing/hoox
> tag：v0.1.1
> commit：d1511fd92200180a57a029a4fbc4390a9549f25a

## 1. 结论

Hoox v0.1.1 可以作为 Noleax 的指定 hook backend 进入工程集成，但不能依据上游 README 直接认定为生产稳定。

当前结论：

- 源码 tag、项目版本和 commit 一致。
- Windows x64 MSVC Debug 构建及上游 16 项测试全部通过。
- Windows x64 MSVC Release 构建成功，但上游 16 项测试中有 5 项失败。
- Release 失败集中在优化后非常短、位于同一编译单元的测试函数；独立目标函数、amalgam、decoder 和 relocator 测试通过。
- 上游 CI 的 MSVC job 只运行 Debug，未覆盖上述 Release 失败。
- Noleax 自建的 Windows x64 Release 探针使用 replace_fast hook RtlAllocateHeap，通过并发和重复运行验证。
- 带 Control Flow Guard 和 CET compatible 标记的探针同样通过。
- 上游没有针对 RtlAllocateHeap 的测试，也没有发现独立的 replace_fast 合同测试。
- v0.1.1 的 Windows FLS callback 未在 deinit 注销；P4.2 通过受审计的 overlay patch 修复，并以
  agent DLL 卸载/进程退出测试覆盖。

因此采用“有条件接受”：

1. 工程只固定使用 v0.1.1，不使用浮动版本。
2. 低层内存 API 优先使用 replace_fast，并由 Noleax 提供精确函数签名的 replacement。
3. 不把 Hoox 的普通 listener 热路径直接用于 RtlAllocateHeap。
4. P4 必须对每个真实目标 API 执行 Debug/Release、ABI、并发、CFG/CET 和卸载测试。
5. 任一真实 API 无法通过 P4 时暂停该 API，不隐藏失败，也不自动替换 Hoox 版本。

## 2. 来源与版本

本地审计副本位于 _temp/hoox-v0.1.1，不进入 Noleax Git。

验证结果：

| 项目 | 结果 |
|---|---|
| CMake project version | 0.1.1 |
| tag 指向 | d1511fd92200180a57a029a4fbc4390a9549f25a |
| commit subject | chore: release v0.1.1 |
| commit date | 2026-07-15T21:27:18+08:00 |
| 实现语言 | C99 |
| 默认链接 | static |
| 默认 allocator | system allocator |
| 外部运行时依赖 | 上游声明无 |

## 3. 许可证

Hoox 主许可证为 wxWindows Library Licence Version 3.1，NOTICE 说明：

- 代码从 frida-gum 提取和调整。
- frida-gum extraction baseline 为 commit a2ebd7b8f570a0aa82ef6823ffa0f7d39703ffa4，tag 17.15.4。
- 指令 decoder 受到 Microsoft Detours 实现启发，相关部分包含 MIT attribution。

Noleax 的发布包必须：

- 携带 Hoox 的 COPYING。
- 携带 Hoox 的 NOTICE。
- 保留需要的版权及许可证声明。
- overlay port 固定源码和校验值。
- 不直接修改或提交 `_temp` 中的 Hoox 审计副本；必要调整必须作为可 review 的 overlay patch，
  保留上游许可证并记录原因和验证证据。

当前 overlay source patches：

- `install-rules.patch`：只增加 vcpkg 所需的安装/export 规则。
- `windows-fls-lifecycle.patch`：补齐私有线程键 deinit，避免 DLL 卸载后遗留 FLS callback；不改变
  hook、relocation 或 trampoline 逻辑。
- `windows-rwx-patch-quiescence.patch`：在 Windows RWX 多字节 patch 更新期间暂停 peer threads，并以
  重复线程快照覆盖 thread churn；P4.8 并发 revert 门禁要求该补丁。

这是一项工程合规记录，不替代正式法律意见。

## 4. 上游能力

上游声明的支持矩阵：

| 平台 | x86 | x64 | ARM64 |
|---|---:|---:|---:|
| Windows | supported | supported | supported |
| Linux | supported | supported | supported |
| macOS | N/A | supported | supported |

源码中存在：

- Windows、Linux、Darwin backend。
- x86/x64、ARM、ARM64 writer、reader、relocator 和 interceptor backend。
- Windows TLS、代码页修改和线程/进程支持。
- x86 CET shadow-stack 特性检测。
- Darwin ARM64 W^X patch 路径。
- transaction、revert 和 flush API。
- invocation thread ignore API。

这些信息证明存在实现和上游测试，不等价于 Noleax 已完成跨平台验收。

## 5. 公开 API 适配结论

Noleax 只通过内部 HookBackend wrapper 使用以下 Hoox API：

- hoox_init / hoox_deinit
- hoox_interceptor_obtain / unref
- hoox_interceptor_replace_fast
- hoox_interceptor_revert
- hoox_interceptor_begin_transaction / end_transaction
- hoox_interceptor_flush

默认不让业务代码直接依赖 Hoox 类型。

P4.2 已将上述 API 收口到 `noleax::agent::HookBackend`。公开 adapter 头文件不包含 Hoox 类型；安装
状态、original trampoline、revert、deferred teardown、flush 和 shutdown 均有独立测试。实现和
replacement in-flight 边界后续已在 P4.8 解决，见 [HOOK_QUIESCENCE.md](HOOK_QUIESCENCE.md)。

P4.3 进一步要求 allocator hook 使用嵌套 transaction：在代码 patch 激活前完成 backend
bookkeeping，并通过原子 slot 发布 original。真实 `RtlAllocateHeap` passthrough 的 MD/MT、
Debug/Release ABI 与 `LastError` 差分已通过；证据见
[RTL_ALLOCATE_HEAP_HOOK.md](RTL_ALLOCATE_HEAP_HOOK.md)。

### 5.1 为什么选择 replace_fast

普通 listener/replace 路径会维护 invocation context 和每线程 invocation stack。源码显示线程第一次进入该路径时会延迟创建 thread context，并通过系统 allocator 分配多个对象。

Hoox 自身有 TLS guard，可让这类递归调用绕过 listener，但 Noleax hook 的目标正是最底层 heap API，不应把正确性建立在复杂的懒分配路径上。

replace_fast：

- 直接进入精确签名的 replacement。
- 提供可调用原实现的 trampoline。
- 不需要 Hoox invocation-context bookkeeping。
- 允许 Noleax 自己实现固定、可测试、无分配的热路径。

代价：

- Noleax 必须为每个 API 编写正确签名的 adapter。
- Noleax 必须自行保存和恢复 LastError/NTSTATUS 相关状态。
- Noleax 必须自行实现 recursion/internal-thread exclusion。
- Noleax 必须自行处理 in-flight callback 和安全卸载。

这与逐 API 严格测试的产品要求一致。

## 6. 本地构建验证

审计环境：

| 项目 | 值 |
|---|---|
| OS | Windows 10 Pro 10.0.19045 x64 |
| CPU | AMD Ryzen 9 9900X |
| CMake | 4.3.1 |
| Ninja | 1.12.0 |
| Visual Studio shell | 17.14.34 |
| MSVC compiler | 19.38.33145 x64 |

### 6.1 Debug

配置：

~~~
cmake -S . -B build-audit-debug -G Ninja
  -DCMAKE_BUILD_TYPE=Debug
  -DHOOX_ENABLE_TESTS=ON
  -DHOOX_BUILD_AMALGAMATION=ON
~~~

结果：

- build 成功。
- 16/16 ctest 通过。
- static library 和 amalgamation 均成功。

### 6.2 Release

配置与 Debug 相同，但 CMAKE_BUILD_TYPE=Release。

结果：

- build 成功。
- 11/16 ctest 通过。
- 失败测试：
  - interceptor_smoke
  - interceptor_selfhost
  - interceptor_threads
  - interceptor_listener_snapshot
  - interceptor_limits
- 失败点均首先表现为对同一编译单元内短测试函数 attach 未返回 OK。
- 基础 interceptor suite 通过。
- amalgam suite 通过。
- x86 writer/relocator 和 decoder 测试通过。

该现象必须保留为已知上游测试缺口。Noleax 不使用这些短测试函数推断真实 ntdll API 是否可 hook，而是为真实地址建立独立合同测试。

### 6.3 RtlAllocateHeap Release 探针

临时探针位于 _temp/hoox-rtl-probe，不进入 Noleax Git。

探针行为：

- 使用 hoox_interceptor_replace_fast hook ntdll!RtlAllocateHeap。
- replacement 调用 Hoox 提供的 original trampoline。
- 8 个线程，每线程执行 20,000 次直接 RtlAllocateHeap 和 HeapFree。
- 验证分配成功、内存可写、释放成功、hook 计数和 revert/flush。

结果：

- 普通 Release 单次通过。
- 连续运行 20 次全部通过。
- 累计至少 3,200,000 次显式测试分配。
- 每次运行还捕获了线程和运行库产生的额外 RtlAllocateHeap 调用。

### 6.4 CFG/CET 探针

探针以以下安全标记重建：

- compiler /guard:cf
- linker /guard:cf
- linker /CETCOMPAT

dumpbin 确认输出包含：

- Control Flow Guard
- CET compatible

相同 RtlAllocateHeap 并发探针通过。

P4.9 已用独立 hardened preset 扩展为五个正式产物的 PE 标记门禁，并在真实 quiescence hook 进程中
查询 CFG/CET runtime policy；当前机器报告二者均启用。完整证据见
[WINDOWS_HOOK_HARDENING.md](WINDOWS_HOOK_HARDENING.md)。该结果仍只覆盖当前 OS/CPU，不能替代后续
Windows 版本矩阵。

### 6.5 P4.2 FLS 生命周期回归

原始 v0.1.1 在 agent DLL 执行 `hoox_init`/`hoox_deinit` 并由 `FreeLibrary` 卸载后，会在进程退出的
`ntdll!RtlpFlsDataCleanup` 中访问已卸载的 Hoox FLS callback，退出码为 `0xC0000005`。

应用 `windows-fls-lifecycle.patch` 后：

- vcpkg Debug/Release Hoox 包均重建成功；
- 5 个 HookBackend 合同测试在 Debug/Release 全部通过；
- agent load/link/unload/exit smoke 在 Debug/Release 各连续运行 20 次，全部正常退出；
- 同一进程 25 次 HookBackend init/install/call/revert/deinit 循环通过。

该结论只证明当前无 replacement in-flight 的 P4.2 fixture 可安全卸载；真实 allocator replacement
已在 P4.8 增加 Noleax 自有 quiescence、trampoline lease 和 module pin 门禁。

## 7. 已知风险和缺口

| 风险/缺口 | 当前处理 |
|---|---|
| 上游明确警告项目由 AI vibe coding 开发、未严格生产验证 | Noleax 建立独立门禁 |
| MSVC 上游 CI 只运行 Debug | Noleax CI 强制 Debug/Release |
| 上游 Release 有 5 项测试失败 | 记录并使用真实 API 合同测试 |
| 无 RtlAllocateHeap 上游测试 | P4 首个专项目标 |
| 未发现独立 replace_fast 合同测试 | Noleax 自建 test target |
| system allocator 可能与被 hook API递归 | 使用 replace_fast 和无分配 replacement |
| 真实 Windows build 间 ntdll prologue 可能变化 | 支持矩阵按 OS build 验收 |
| CFG/CET 仅覆盖当前 OS/CPU | P4.9 hardened 门禁已通过，CI/支持矩阵继续扩展 |
| Page Heap/Application Verifier 需要管理员设置 | P4.9 回滚脚本已完成，提权验收待执行 |
| v0.1.1 deinit 遗留 Windows FLS callback | overlay 生命周期补丁及 agent unload/exit 回归 |
| 安全卸载需要 flush 及自有 in-flight 计数 | HookBackend wrapper 统一实现 |

## 8. P4 强制验证项

进入默认 profile 前，每个 API 必须验证：

- replace_fast 返回 OK 且 original trampoline 非空。
- 原始参数、返回值和输出参数完全一致。
- LastError 在有定义和无定义场景下不被日志路径污染。
- replacement 内无 heap allocation、文件 I/O、符号解析和阻塞锁。
- recursion/internal-thread exclusion 可证明生效。
- 多线程调用、安装、revert、flush 和进程退出。
- Debug/Release。
- CFG/CET compatible 测试目标。
- Page Heap/Application Verifier。
- 目标 API 所在模块的实际 prologue 记录到测试报告。

## 9. 最终 P0 决策

Hoox v0.1.1 不阻塞 P1 工程初始化。

它被接受为“需由 Noleax 安全层和测试门禁约束的底层机制”，而不是无需验证的成熟依赖。任何失败都必须在 HookBackend 边界暴露并阻止对应 profile 启用。
