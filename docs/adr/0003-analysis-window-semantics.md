# ADR 0003：a/b/c 时间窗口语义

> 状态：Accepted
> 日期：2026-07-29

## Context

“在 a、b 之间分配，到 c 仍未释放”需要明确边界、realloc、地址复用、失败调用、heap destroy 和不完整 trace 的行为。

## Decision

1. 候选窗口为 a 小于等于 event_time 且 event_time 小于 b。
2. c 未提供或超过 trace 结束时间时使用 trace 结束时间。
3. 必须满足 a 小于等于 b 且 b 小于等于 c。
4. c 的状态包含时间等于 c 的全部已排序事件。
5. 每次成功 allocation 生成唯一 allocation_id。
6. 成功 realloc 结束旧 generation 并创建新 generation，即使地址不变。
7. realloc 失败不结束旧 generation。
8. free 只有成功时结束 generation。
9. heap destroy 成功时结束该 heap 全部 live generation。
10. 状态还原使用全部事件，过滤器只应用于最终候选结果。
11. attach 盲区、Loss 或截断使结果标记 incomplete。

## Consequences

- 相邻窗口不会重复包含 b 时刻事件。
- 地址复用不会混淆不同分配。
- 用户看到的是调用事件代次，而不是简单的 address set。
- 不完整 trace 仍可给出已知结果，但退出码为 2，不能宣称确定无泄漏。
