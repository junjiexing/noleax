# ADR 0001：规范化 Hook 与 Hoox Adapter

> 状态：Accepted
> 日期：2026-07-29

## Context

Windows 同一次逻辑 heap allocation 可能经过 CRT malloc、HeapAlloc 和 RtlAllocateHeap 多层 API。直接 hook 每一层会产生重复事件、递归和不一致的失败语义。

RtlAllocateHeap 又处于系统 allocator 最底层，hook callback 中的任何动态分配都可能导致递归、死锁或目标进程崩溃。

Hoox v0.1.1 提供 listener、replace 和 replace_fast。普通 listener 路径维护每线程 invocation context，并会在线程首次进入时通过系统 allocator 延迟分配状态。

## Decision

1. V1 默认直接 hook 规范化的 NT Heap 和 NT Virtual Memory API。
2. Win32、CRT、COM 和 C++ 包装层默认不直接 hook。
3. 使用 Hoox replace_fast，而不是 listener，安装精确签名 replacement。
4. 每个 API 使用独立 adapter，负责参数、成功条件、生命周期和错误状态。
5. replacement 热路径只允许：
   - 调用 original trampoline。
   - 保存结果和错误状态。
   - 捕获有界原始栈。
   - 原子计数。
   - 写入预分配队列。
6. HookBackend 是 Noleax 唯一可见的 Hoox 边界。
7. API 只有通过 HOOK_API_MATRIX 中全部门禁后才能在 profile 中启用。

## Consequences

优点：

- 避免多层重复记账。
- 低层 hook 热路径可审计。
- 每个 API 的行为可以独立测试。
- 未来替换 backend 时不影响事件模型。

代价：

- 默认事件显示规范化底层 API，不一定显示用户调用的包装 API。
- 需要为每个签名维护 adapter。
- 需要自行实现 recursion、internal thread exclusion、LastError 保存和安全卸载。
- 第三方 allocator 的内部小分配需要后续 custom symbol hook。

## Alternatives rejected

直接 hook 所有包装层：

- 重复事件和嵌套语义复杂。
- 动态加载 CRT 模块增加安装竞态。
- 不作为 V1 默认方案。

Hoox listener：

- API 参数读取方便，但低层 heap hook 首次调用存在额外 per-thread 状态分配。
- 可用于非 allocator 的后续诊断，不用于 V1 核心 allocator hook。
