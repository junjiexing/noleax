# Noleax Analyzer

> 状态：P3.1 events 流式解码核心完成

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

## 4. 后续阶段

P3.1 只提供事件流和摘要模型，尚未连接公开 CLI 输出。P3.2 将以同一回调流实现 allocation
generation 状态机；console、JSON、CSV 以及 module/stack 符号展示分别在后续 P3 工作项接入。
