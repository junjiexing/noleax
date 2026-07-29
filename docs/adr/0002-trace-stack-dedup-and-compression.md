# ADR 0002：Trace 栈去重与按块压缩

> 状态：Accepted
> 日期：2026-07-29

## Context

每个内存事件都保存完整栈会快速放大文件。直接在 hook callback 中去重或压缩又会引入 hash table、动态分配、锁和不可预测延迟。

LZ4 相比 Zstd CPU 和延迟更低；Zstd 通常有更高压缩率。Noleax 需要优先保证目标进程稳定，同时允许用户选择更小文件。

## Decision

1. hook callback 为每个事件捕获原始有界帧数组，并临时写入预分配队列。
2. 后台 writer 规范化并去重栈。
3. 新栈写一次 StackDefinition，事件只保存 stack_id。
4. hash 命中后必须逐帧比较，不能只依赖 hash。
5. stack dictionary 有内存上限；达到上限时清空 writer 索引并继续分配新的全局 stack_id。
6. trace 按独立 chunk 压缩，每个 chunk 保存 codec。
7. 支持 none、lz4、zstd。
8. 默认 LZ4，Zstd level 1 为可选项。
9. CRC32C 对未压缩 payload 计算。
10. 压缩永远不在 hook callback 中执行。

## Consequences

优点：

- 大量重复调用栈只写一次。
- 默认压缩对目标 CPU 影响较低。
- reader 不被单一 codec 锁死。
- chunk 损坏或截断时可恢复此前数据。

代价：

- agent 队列中的临时事件仍包含完整帧数组。
- writer 需要栈字典和 module generation 映射。
- 字典 reset 后同一栈可能获得不同 ID。
- 支持多个 codec 增加测试矩阵和依赖。

## Alternatives rejected

每个事件内联完整栈：

- 实现简单，但文件体积不可接受。

hook callback 中全局去重：

- 会把共享 hash table 和内存分配带入最危险的热路径。

只支持 Zstd：

- 文件更小，但不适合作为目标进程内默认低开销策略。

只支持 LZ4：

- 简单，但无法满足更重视文件大小的使用场景。
