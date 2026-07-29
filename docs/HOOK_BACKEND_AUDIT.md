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
- 不修改 vendored Hoox 源码；若未来必须修改，先单独审查许可证和维护策略。

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

该结果只覆盖当前机器和该探针，不替代 P4 的完整矩阵。

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
| CFG/CET 只完成单机初测 | P4/CI 扩展矩阵 |
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
