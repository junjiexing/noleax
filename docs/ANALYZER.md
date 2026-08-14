# Noleax Analyzer


## 1. 范围

`analyze_event_stream` 使用正式 TraceReader、RecordCursor 和 V1 record decoder，按 trace 顺序
回调 FileHeader、CaptureScope、Event、Loss、MemoryCounters、MemoryMap、CaptureStatistics 和
EndOfTrace。它一次只保留一个受 reader 上限约束的 chunk，不把整个 trace 或全部事件加载到内存。

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
- metadata、statistics、memory 和 end chunk 不得声明 event sequence range。
- memory 记录（minor 2 起）的 ticks 不得小于 monotonic origin 且不得回退；memory chunk 不携带
  event sequence，也不参与 EndOfTrace 的边界校验。

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
映射为退出码 4。

## 4. Generation 状态机

GenerationTracker 消费已按 sequence 排序的 Event，只保留当前 live generation，并以
allocation_id 或 mapping_id 作为身份，不以可复用的地址作为身份。

| 创建事件 | generation kind | 结束事件 |
|---|---|---|
| 成功 Allocate、产生新 generation 的 Reallocate | heap allocation | 成功 Reallocate、Free、HeapDestroy |
| 当前进程成功 VmAllocate | virtual allocation | 当前进程成功 VmFree（整段或累计部分释放） |
| 当前进程成功 Map | mapped view | 当前进程成功 Unmap，或累计部分 VmFree |

- realloc 即使返回原地址，也先以 reallocated 结束旧 ID，再创建新 ID。
- realloc failure/no_change、失败 free 和 unmatched/preexisting end 不改变已知 live 状态。
- realloc 的 adapter effect 为 freed 时只结束旧 generation，不创建新 generation。
- 成功 heap destroy 按 allocation_id 顺序结束该 heap 的所有 live allocation。
- 远程进程 VM 操作保留在 events 输出中，但不进入本进程 generation 状态。
- mapping generation 的 live 范围是区间集（与 Linux writer 共用同一 IntervalSet 语义）：
  带 release 位且 `region_size != 0` 的 VmFree 按 `[base, base+region_size)` 相减，对匿名和
  文件视图 generation 都适用，剩余字节为 0 时代结束；`region_size == 0` 是 Windows 整段
  release 线形，base 必须等于代基址、kind 必须是 virtual allocation。同 mapping_id 的
  VmAllocate 更新（in-place mremap resize）按连续片段run扩缩。
- 地址结束后可以复用；allocation_id 和 mapping_id 在整个 trace 中不得复用。
- 若 end 引用了当前状态中不存在的有效 ID，继续处理并增加 orphan counter，以支持存在 Loss 的
  trace；若 ID 存在但地址、heap 或 mapping kind 矛盾，则拒绝该 trace 的状态语义。同一存活
  片段的重复释放（相减与任何存活片段都不相交）同样是状态语义错误。

创建和结束回调在状态变更点同步触发，供窗口分析器只保存候选窗口内的 generation。状态机同时保留
所有历史 generation ID 的集合以检测 ID 重用；该索引受输入 trace 文件大小上限约束。

## 5. Outstanding 窗口

`analyze_outstanding` 将 EventStream 与 GenerationTracker 组合，语义固定为：

- 候选 creation time 满足 `a <= time < b`；窗口界也可以是事件 sequence（`a <= sequence < b`）。
- 要求 `0 <= a <= b <= c`（b 缺省时要求 `a <= c`），顺序校验每个共有分量；不同种类的界没有
  可静态判断的顺序。b、c 省略或超过 trace end（时间轴或最终 sequence）时不再报错：effective b
  使用严格位于最后事件之后的排他边界，effective c 使用包含最后事件的 trace 终点。混合界按分量
  独立截断，未越界分量继续生效。
- 观察点包含 time 或 sequence 等于 c 的全部 end event，因此恰好在 c free/realloc/destroy/unmap
  的候选不再 outstanding。
- c 之后才结束的候选仍在 c outstanding，即使读取完整 trace 后它已不在 tracker 的最终 live
  集合中。
- 只保存 `[a,b)` 中的候选；确定在 c 之前结束的候选在结束事件到达时即从候选集淘汰
  （early eviction），状态还原仍消费全部事件。mapping generation 在 c 点存活当且仅当它的
  剩余虚拟字节 > 0：Linux 的部分 VmFree（前缀/后缀/中段/跨映射/逐出/裁剪）按区间相减，
  在 c 之前的相减会更新候选报告的剩余字节，c 之后的不影响。
- 输出保持候选创建顺序，覆盖 heap allocation、当前进程 virtual allocation 和 mapped view。

用户时间是相对 FileHeader.monotonic_origin 的纳秒数。边界比较直接比较 tick/frequency 与纳秒
有理数，避免乘法溢出和提前取整；展示 trace end 时向下取整到纳秒，同时保留原始
trace_end_monotonic_ticks。若状态机发现引用缺失 creation 的有效 ID，结果增加 event_loss，继续
输出可确定候选并使用退出码 2。

## 6. 过滤器

AnalysisFilter 使用固定组合规则：一个类别中的多个值为 OR，不同类别之间为 AND；最小值和
最大值均为包含边界。空列表或未设置的范围不限制结果。构造时拒绝反向大小范围以及空 API 名称
或空模块 pattern。

| 类别 | events 模式 | outstanding 模式 |
|---|---|---|
| size | 事件自身可解释的 size | generation 的创建大小 |
| event | 当前事件 operation | generation 的创建 operation |
| thread | 当前事件 thread_id | 创建 generation 的 thread_id |
| API/module/stack module | 当前事件元数据 | 创建 generation 的事件元数据 |
| allocation ID | alloc/free ID；realloc 的 old 或 new ID | heap allocation generation ID |
| status | 当前事件 status | 创建 generation 的 status |

events 的 size 定义为：heap alloc/realloc 使用 requested_size；VM alloc 成功时使用
result_size、失败时使用 requested_size；VM free 使用 region_size；map 使用 view_size。
HeapCreate、HeapDestroy、heap Free 和 Unmap 没有可独立解释的 size，存在 size 过滤时不会匹配。
outstanding 直接使用 MemoryGeneration.size，因此 heap allocation 为 requested_size，mapping 类
generation（virtual allocation / mapped view）为 c 点的剩余**虚拟**字节（不等于驻留内存）。
`--allocation-id` 不匹配独立编号空间中的 mapping_id。

API 名称按 ApiDefinition canonical name 做 UTF-8 精确、区分大小写匹配。模块 pattern 支持 `*`
和 `?`，ASCII 字母不区分大小写，`/` 与 `\` 等价；pattern 含路径分隔符时匹配规范化完整路径，
否则只匹配 basename。多个 stack module pattern 中任意一个匹配任意一帧即可。元数据无法解析时，
依赖该元数据的类别不匹配。

当前 ApiDefinition、Module 和 StackDefinition 已由 EventStream 解码并通过 TraceMetadata 聚合；
过滤器通过 EventMetadataResolver 注入解析结果；配置 API/module/stack-module 过滤而未提供 resolver 时明确
报错，不会静默输出空结果。

`analyze_filtered_events` 仍以流式方式逐事件回调，并分别统计 matched 与 filtered 数量。
`analyze_filtered_outstanding` 始终先让所有事件进入 GenerationTracker，确定 c 时刻存活集合之后
才过滤最终候选；结果中的 candidate_count、ended_by_c_count 和 filtered_out_count 可解释每个阶段。

## 7. Console 输出

ConsoleWriter 支持 events 的逐事件流式输出和 outstanding 的最终候选输出。两种模式统一显示
trace/capture 元数据、固定宽度地址、精确 size、相对纳秒与原始 ticks、API、payload、调用栈、
summary 和完整性 warning。`analyze_events_to_console` 与 `analyze_outstanding_to_console` 把
analyzer callback 直接接到 writer；events 不缓存全部结果。memory 模式由
`analyze_memory_to_console` 输出快照时间序列与峰值汇总（见 [CONSOLE_OUTPUT.md](CONSOLE_OUTPUT.md)
第 5.1 节）。

API/module/stack 定义尚不可用时分别回退为 api ID、原始 stack ID 和明确的 definition unavailable；
ConsoleMetadataResolver 可注入 module+offset、symbol+offset 和绝对地址组成的多行 frame。可选 ANSI
颜色由调用方在解析终端状态后启用。完整字段和 warning 名称见 [CONSOLE_OUTPUT.md](CONSOLE_OUTPUT.md)。

## 8. JSON 输出

JsonWriter 生成 `noleax.analysis` schema version 4。events 模式把匹配 Event 和全部 Loss 直接从
analyzer callback 流式写入数组；outstanding 模式输出窗口和最终存活 generation；memory 模式输出
窗口与按采样 tick 合并的 `snapshots` 数组（计数器和/或 map，map 含完整区域明细）。根对象统一包含
metadata、实际 filters、summary（含 `custom_hook_failures` 明细）和 completeness，地址/handle/flags/错误码使用十六进制字符串，
64 位 size、ID、sequence 和 ticks 使用无损 JSON integer。

EventPresentationResolver 为 console 和 JSON 共享 API/module、stack status 与解析帧。trace 内仍以
stack_id 去重；JSON 保留 ID 并为自包含消费展开可用帧。所有文本严格验证 UTF-8，v4 根对象、九类
payload 和 memory 快照结构由 [JSON_OUTPUT.md](JSON_OUTPUT.md) 与
[noleax-analysis-v4.schema.json](schema/noleax-analysis-v4.schema.json) 固定；旧版结构继续由
[noleax-analysis-v1.schema.json](schema/noleax-analysis-v1.schema.json)、
[noleax-analysis-v2.schema.json](schema/noleax-analysis-v2.schema.json) 和
[noleax-analysis-v3.schema.json](schema/noleax-analysis-v3.schema.json) 固定。

## 9. CSV 输出

CsvWriter 为 events 和 outstanding 提供两套 schema version 2 固定列。events 逐行写匹配 Event 和
全部 Loss，outstanding 每个最终 generation 一行；两种模式都以 summary 行结束。memory 模式是独立的
扁平时间序列表（每个采样 tick 一行计数器/聚合列，不含区域明细与 summary 行）。CSV 固定 UTF-8、
逗号和 CRLF，按 RFC 4180 引用包含逗号、双引号或换行的字段，并无损保留 64 位整数。

调用栈在单字段中使用可逆的五元组子格式，仍保留 stack ID、capture status、绝对地址和可用符号。
字段顺序、空值、summary 和转义规则见 [CSV_OUTPUT.md](CSV_OUTPUT.md)。

## 10. Windows 离线符号解析

`OfflineSymbolizer` 在 analyzer 进程内封装 DbgHelp。每个 module generation 使用独立 module ID
和 session 内合成基址，因此可以解析复用同一历史加载地址的模块。默认 search path 显式为空，
只有用户提供时才加入本地 symbol path 或 `srv*URL`。

加载后校验 PE timestamp/checksum/image size 和可选 PDB GUID/age。映像或 PDB identity 不匹配时
卸载该符号，不冒险展示错误函数名；PDB 缺失时仍可使用匹配映像的 export。任何失败都保留
module+offset 和绝对地址。所有 DbgHelp 调用跨实例全局串行，module map 支持并发只读查询。完整
状态、回退和线程模型见 [SYMBOLIZATION.md](SYMBOLIZATION.md)。

## 11. CLI 集成

`TraceMetadata` 对输入执行一次受限预扫描，保留历史 ModuleId、StackId 和符号模块；正式
events/outstanding 分析再从文件头重新读取。两次读取均使用相同的 TraceReader/EventStream 校验，
第二次仍保持 formatter 的流式特性。API 名来自固定 Windows hook registry，module generation 和
stack frame 来自 trace，符号失败时稳定回退到 module+offset 和绝对地址。

`noleax analyze` 已映射全部 V1 filter 和 console/JSON/CSV。完整性 issue 返回 2，损坏到无法继续的
trace 返回 4。CLI 每次调用只接受一个 trace；多文件/rotation 合并在实现明确的跨文件 sequence、
module generation 和输出 schema 前返回 5。
