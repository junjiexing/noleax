# Noleax Console 输出

> 日期：2026-07-29

## 1. 目标与边界

console 输出面向人工诊断，不作为机器可解析的稳定 schema。JSON 和 CSV 分别提供版本化或固定列的
机器接口。实现提供 ConsoleWriter、`analyze_events_to_console` 和
`analyze_outstanding_to_console`；二者已通过公共调度接入文件、退出码和 Module/Stack resolver，
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

## 4. leaks 布局

leaks（原 outstanding）报告标题为 `noleax leaks`。窗口显示 `[from,effective_to)`、有效观察点 c、
c 来自配置还是 trace end，以及原始 trace-end ticks；`--to` 缺省或超过 trace 终点时使用严格位于
最后事件之后的排他边界，确保半开窗口包含最后事件。
窗口界按种类显示：时间界为 `123ns`，sequence 界为 `#123`；未设置的 to 显示 `trace-end`。
每个结果显示 generation kind、allocation/mapping ID、size、地址、heap 信息、创建事件和创建栈。
mapping 类 generation 的 size 是观察点 c 处的剩余**虚拟**地址空间字节（行内标注
`size=NB (virtual)`），不是驻留内存；heap allocation 的 size 是请求大小。
summary 分别显示候选数、截至 c 已结束数、最终过滤数、outstanding 数，以及
`outstanding-virtual-bytes`（mapping 类 generation 剩余虚拟字节合计）。

## 5. stacks 布局

`--group-by` 产生按排名排序的分组报告。events 聚合（标题 `noleax event stacks`）每组一行
`#rank calls=N alloc=C/B free=C/B net=B apis=名1,名2`，leaks 聚合（标题 `noleax leak stacks`）
每组一行 `#rank calls=N bytes=B apis=名1,名2`，均随附展开后的调用栈。apis 列出组内涉及的
分配 API 规范名（按首次出现去重）。summary 给出组数、合计计数与字节；events 聚合
额外给出 aggregated-events 与 unmatched-frees（无法追踪到 allocation 的 free 数），leaks 聚合的
窗口行与 leaks 报告一致。

## 5.1 memory 布局

`--mode memory` 的报告标题为 `noleax memory`，窗口行与 events 一致（`[from, to)`，缺省上界显示
`trace-end`），但只有时间界有效。`snapshots:` 段每个采样 tick 一行：相对时间后跟该 tick 到期的
采样字段——计数器为 `working-set=`、`peak-working-set=`、`private=`、`commit=`，map 聚合为
`committed=`、`reserved=`、`free=`、`largest-free=`、`regions=`，列表截断时追加 `truncated`；
该 tick 未到期的采样器对应字段整组留空。区域明细不进 console。

`peaks:` 段给出各计数器的峰值及其首次出现的采样 tick（working-set、private、commit 来自计数器
采样，committed、reserved 来自 map 采样）；相应采样器从未出现时该段显示 `none`。summary 依次列出
窗口内的 snapshots、counter-snapshots、map-snapshots 计数与公共 trace 摘要。

## 6. 完整性警告

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
- custom-hook-install-failed

未来 issue bit 以 `unknown-issue-bits=0x...` 保留。任何 issue 仍对应推荐退出码 2。

custom hook 安装失败时，summary 在 warnings 之后追加 `custom-hook-failures:` 明细段，每个失败
一行：`module=`、`role=`（alloc/realloc/free/point）、`reason=`（module-not-loaded、
export-not-found、forwarded-export、invalid-rva、wrong-signature、image-identity-mismatch、
backend-unavailable、other）与人读 `detail=`。

## 6.1 捕获会话行（Linux）

`run`/`attach` 的汇总行有两种形态：正常收尾输出 `capture finalized:`（trace 为最终路径，
agent 已在 EndOfTrace + flush + close 成功后把 `.partial` 原子 rename 过去）；最终路径缺失时
回退到保留的 `.partial` 并输出 `capture incomplete:`，附 `note=` 说明（异常结束或 controller
分类出的失败原因）。两行都回读 trace 给出 `observed/written/filtered/dropped/bytes`。

`--live` 在等待期间每秒打印一行实时状态：

~~~
status: state=capturing observed=1442 written=1442 filtered=0 dropped=0 queued=0/16384 high_water=1142 consumed=1442 bytes=62030 last_flush_age_ms=7
~~~

字段：`state`（idle/starting/capturing/drained/finalized/failed）、守恒计数
`observed/written/filtered/dropped`、`queued=占用/容量`、`high_water`（消费侧采样的队列占用高
水位）、`consumed`（累计出队数）、`bytes`（writer 已写字节）、`last_flush_age_ms`（距上次
flush；从未 flush 显示 `last_flush=never`）。

## 7. 颜色

ConsoleOptions 只接受已经解析后的 `use_color`。调用方负责把用户的 auto/always/never 转换为布尔值；
auto 仅在目标是交互终端时启用。颜色只使用 ANSI SGR：标题加粗，成功事件为绿色，失败事件为红色，
unmatched/preexisting、Loss 和 warning 为黄色。关闭颜色时输出不包含控制字符。
