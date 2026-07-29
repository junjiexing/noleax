# Noleax Analyzer

> 状态：P3.1 events、P3.2 generation 状态机与 P3.3 outstanding 窗口完成

## 1. P3.1 范围

`analyze_event_stream` 使用正式 TraceReader、RecordCursor 和 V1 record decoder，按 trace 顺序
回调 FileHeader、CaptureScope、Event、Loss、CaptureStatistics 和 EndOfTrace。它一次只保留一个
受 reader 上限约束的 chunk，不把整个 trace 或全部事件加载到内存。

每个 chunk 在触发任何 Event/Loss 回调前先完成 record framing、解码和 chunk 内语义校验。
因此损坏 chunk 不会产生部分输出；已经完成并回调的前序 chunk 在尾部截断时仍然有效。

## 2. 语义校验

events 流当前强制执行：

- CaptureScope 恰好出现一次，并先于 Event、Statistics 和 EndOfTrace。
- Event sequence 跨 chunk 严格递增，monotonic ticks 不回退。
- event chunk header 的 sequence range 与已知 Event/Loss record 一致；包含未知 record 时至少
  覆盖所有已知 record。
- CaptureStatistics 只出现一次；在格式完全理解时，其 aggregate 和每个 api_id 的 recorded
  event 数都与已解码 Event 完全相同。
- EndOfTrace 只出现一次，其 final sequence/ticks 不早于所有已知 Event/Loss 范围，并且其后
  不允许出现已知 chunk。
- metadata、statistics 和 end chunk 不得声明 event sequence range。

单 record 默认上限为 1 MiB，chunk 解压和存储上限继承 TraceReaderOptions。格式、CRC、压缩和
长度错误由底层 reader/decoder 拒绝；跨 record/chunk 的语义错误抛出 TraceAnalysisError。

## 3. 完整性传播

结果用 CompletenessTracker 合并：

- CaptureScope 中的 attach/进程启动范围。
- 每条 Loss 的生命周期或栈信息损失。
- 截断尾部和缺少 EndOfTrace。
- reader 无法完全理解的 header/chunk 扩展。
- 跳过的未知 record 或尚未实现的 module/stack record。
- EndOfTrace 写入的 aggregate completeness 和 abnormal stop。

只要存在任一 completeness issue，推荐退出码为 2；不支持或损坏到不能继续解析的输入由 CLI
在接入阶段映射为退出码 4。

## 4. Generation 状态机

GenerationTracker 消费已按 sequence 排序的 Event，只保留当前 live generation，并以
allocation_id 或 mapping_id 作为身份，不以可复用的地址作为身份。

| 创建事件 | generation kind | 结束事件 |
|---|---|---|
| 成功 Allocate、产生新 generation 的 Reallocate | heap allocation | 成功 Reallocate、Free、HeapDestroy |
| 当前进程成功 VmAllocate | virtual allocation | 当前进程成功 VmFree |
| 当前进程成功 Map | mapped view | 当前进程成功 Unmap |

- realloc 即使返回原地址，也先以 reallocated 结束旧 ID，再创建新 ID。
- realloc failure/no_change、失败 free 和 unmatched/preexisting end 不改变已知 live 状态。
- realloc 的 adapter effect 为 freed 时只结束旧 generation，不创建新 generation。
- 成功 heap destroy 按 allocation_id 顺序结束该 heap 的所有 live allocation。
- 远程进程 VM 操作保留在 events 输出中，但不进入本进程 generation 状态。
- 地址结束后可以复用；allocation_id 和 mapping_id 在整个 trace 中不得复用。
- 若 end 引用了当前状态中不存在的有效 ID，继续处理并增加 orphan counter，以支持存在 Loss 的
  trace；若 ID 存在但地址、heap 或 mapping kind 矛盾，则拒绝该 trace 的状态语义。

创建和结束回调在状态变更点同步触发，供 P3.3 只保存候选窗口内的 generation。状态机同时保留
所有历史 generation ID 的集合以检测 ID 重用；该索引受输入 trace 文件大小上限约束。

## 5. Outstanding 窗口

`analyze_outstanding` 将 EventStream 与 GenerationTracker 组合，语义固定为：

- 候选 creation time 满足 `a <= time < b`。
- 要求 `0 <= a <= b <= c`；省略 c 时使用 trace end。
- c 超过 trace end 时 clamp 到 trace end；clamp 后 b 若超过 trace end 则拒绝该窗口。
- 观察点包含 time 等于 c 的全部 end event，因此恰好在 c free/realloc/destroy/unmap 的候选不再
  outstanding。
- c 之后才结束的候选仍在 c outstanding，即使读取完整 trace 后它已不在 tracker 的最终 live
  集合中。
- 只保存 `[a,b)` 中的候选及其可选结束时间；状态还原仍消费全部事件。
- 输出保持候选创建顺序，覆盖 heap allocation、当前进程 virtual allocation 和 mapped view。

用户时间是相对 FileHeader.monotonic_origin 的纳秒数。边界比较直接比较 tick/frequency 与纳秒
有理数，避免乘法溢出和提前取整；展示 trace end 时向下取整到纳秒，同时保留原始
trace_end_monotonic_ticks。若状态机发现引用缺失 creation 的有效 ID，结果增加 event_loss，继续
输出可确定候选并使用退出码 2。

## 6. 后续阶段

P3.1-P3.3 尚未连接公开 CLI 输出。P3.4 将在完整状态还原后应用过滤器；console、JSON、CSV
以及 module/stack 符号展示分别在后续 P3 工作项接入。
