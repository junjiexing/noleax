# Noleax Console 输出

> 状态：P6.7 formatter、元数据与公开 CLI 完成
> 日期：2026-07-29

## 1. 目标与边界

console 输出面向人工诊断，不作为机器可解析的稳定 schema。JSON 和 CSV 分别提供版本化或固定列的
机器接口。P3.5 提供 ConsoleWriter、`analyze_events_to_console` 和
`analyze_outstanding_to_console`；P6.7 已通过公共调度接入文件、退出码和 Module/Stack resolver，
避免为每种格式复制分析状态机。

events 管线边读 trace 边写匹配事件和 Loss，不缓存全部事件。outstanding 管线复用窗口分析器，只
输出它保留的最终候选。若读取或校验在中途失败，events 输出可能包含已经原子校验完成的前序 chunk，
但不会追加成功 summary。

## 2. 固定展示规则

| 数据 | console 表示 |
|---|---|
| 地址、handle | `0x` 小写十六进制，按 trace pointer width 补零 |
| flags、错误码、raw result | `0x` 小写十六进制，不强制补零 |
| size | 精确十进制字节数加 `B` |
| 相对时间 | 相对 monotonic origin 向下取整的纳秒数，同时显示原始 ticks |
| ID | 十进制；无有效 ID 时为 `none` |
| API | `module!canonical-name`；缺少定义时为 `api#ID` |
| stack | capture status 和多行 frame；定义缺失时保留 stack ID 并明确显示 unavailable |

stack status 使用 complete、truncated-by-depth、unwind-failed 或 unavailable。frame 优先显示
`module!symbol+offset`，其次显示 `module+offset`，并始终保留方括号中的绝对地址。
符号、模块或 stack definition 不可用时不猜测名称。

## 3. events 布局

输出依次包含：

1. trace 平台、架构、pointer width、文件序号和时钟原点。
2. capture 是否从进程启动开始。
3. 按 trace 顺序出现的匹配 Event 与所有 Loss。
4. matched/filtered、trace event、Loss、字节、capture statistics 和终止摘要。
5. 完整性状态和逐项 warning。

每种 Event 都输出规范化 payload 的全部关键字段；heap allocation、VM 和 mapping 的 ID 空间不会
混用。size、地址和系统错误保留原始精度。

## 4. outstanding 布局

窗口显示 `[a,b)`、有效观察点 c、c 来自配置还是 trace end，以及原始 trace-end ticks。每个结果
显示 generation kind、allocation/mapping ID、size、地址、heap 信息、创建事件和创建栈。summary
分别显示候选数、截至 c 已结束数、最终过滤数和 outstanding 数。

## 5. 完整性警告

summary 同时显示 overall、lifecycle、stack-detail 和 understanding 状态。已知 issue 按稳定顺序列出：

- capture-did-not-start-at-process-start
- preexisting-allocations-unknown
- event-loss
- trace-truncated
- writer-error
- unknown-record-skipped
- missing-end-of-trace
- abnormal-stop
- stack-data-loss
- partially-understood-format

未来 issue bit 以 `unknown-issue-bits=0x...` 保留。任何 issue 仍对应推荐退出码 2。

## 6. 颜色

ConsoleOptions 只接受已经解析后的 `use_color`。调用方负责把用户的 auto/always/never 转换为布尔值；
auto 仅在目标是交互终端时启用。颜色只使用 ANSI SGR：标题加粗，成功事件为绿色，失败事件为红色，
unmatched/preexisting、Loss 和 warning 为黄色。关闭颜色时输出不包含控制字符。
