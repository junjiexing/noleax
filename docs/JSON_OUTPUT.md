# Noleax JSON 输出

> schema：`docs/schema/noleax-analysis-v4.schema.json`
> 日期：2026-08-05

## 1. 目标与边界

JSON 输出是面向程序消费的版本化接口。V2 提供 `JsonWriter`、`analyze_events_to_json` 和
`analyze_outstanding_to_json`。公开 CLI 已统一接入文件、退出码和真实符号展示，三种格式
共享 filter 和 presentation resolver。

events 管线边读 trace 边写匹配 Event 和全部 Loss，只保留当前受限 chunk，不将全部事件构造成
DOM。outstanding 分析本身需要保留 `[a,b)` 内候选，writer 只遍历最终结果。若输入在中途损坏，
events 输出可能包含已完成校验的前序记录，但不会包含闭合数组或成功 summary，因此消费者必须把
未通过完整 JSON 解析的文件视为失败结果。

## 2. 版本和根对象

每个文档固定包含：

| 字段 | V4 含义 |
|---|---|
| `schema` | 固定为 `noleax.analysis` |
| `schema_version` | 固定为整数 `4` |
| `mode` | `events`、`leaks`、`stacks` 或 `memory` |
| `metadata` | trace header 和 capture scope |
| `filters` | 本次实际使用的全部过滤条件；未设置的范围为 `null`，空枚举为 `[]`（memory 模式恒为空） |
| `summary` | trace、完整性、统计、custom hook 失败明细和对应 mode 的计数 |

events 文档另有 `events` 数组；leaks 文档另有 `window` 和 `allocations`；stacks 文档另有
`dataset`、`window` 和 `groups`；memory 文档另有 `window` 和 `snapshots`。V4 schema 对根对象、
所有已定义对象及九类 payload 禁止未知字段。V4 相对 V3 增加 `summary.custom_hook_failures`
数组（元素为 `module`、`role`、`reason`、`detail` 四字段的对象，无失败时为空数组）并在
completeness issue 命名中新增 `custom_hook_install_failed`；这是结构和枚举变化，因此提升
schema version。V3 相对 V2 增加 `memory` mode（含
`memory_window`/`memory_snapshot` 结构与对应 summary 计数字段）。仓库保留只接受旧结构的
V1/V2/V3 schema。后续新增字段、改变字段类型或新增枚举值也必须按消费者无法静默误解的兼容
策略处理。

## 3. 基础编码规则

| 数据 | JSON 表示 |
|---|---|
| size、ID、sequence、ticks、计数 | 十进制 JSON integer，保留完整 64 位值 |
| 相对时间和 UTC 时间 | 有符号十进制 JSON integer，单位为 ns |
| 地址和 handle | `0x` 小写十六进制字符串，按 trace pointer width 补零 |
| flags、错误码、raw result、offset、完整性 mask | `0x` 小写十六进制字符串 |
| 无效 ID、缺失定义或缺失可选值 | JSON `null` |
| 文本 | 严格 UTF-8；引号、反斜杠和 U+0000–U+001F 按 JSON 转义 |

64 位整数不降级为浮点数。使用只支持 IEEE-754 double 的消费者时，应选用能够无损保存 JSON
integer 的 parser，或把数值 token 作为十进制字符串解析。地址和 handle 使用十六进制字符串，
避免 JavaScript number 精度和有符号解释问题。

## 4. events 模式

`events` 按 trace 顺序混合两种 record：

- `record_type: "event"`：公共 header、API 展示信息、operation、status、stack、system error 和
  规范化 payload。
- `record_type: "loss"`：丢失原因、位置、估算数量及可用的 sequence/tick 范围。

过滤器只决定 Event 是否进入数组；Loss 始终保留，用于解释完整性。九类 payload 的 `kind` 为
`heap_create`、`heap_destroy`、`allocation`、`reallocation`、`free`、`vm_allocation`、`vm_free`、
`map` 和 `unmap`，各自字段由 v2 schema 严格定义。

summary 的 mode 专属字段为 `matched_events` 和 `filtered_events`。公共字段包括 trace event/Loss 数、
读取字节、已知末尾、截断与格式理解状态、capture statistics、termination 和 completeness。

## 5. leaks 模式

`window` 保留请求的 `a_ns`、可空的 `b_ns`、截断后的 `effective_b_ns`、可空的 `requested_c_ns`、
实际 `effective_c_ns`、c 是否采用 trace end，以及原始 `trace_end_monotonic_ticks`。每个窗口界
同时有一个可空的 sequence 对应字段（`a_sequence`、`b_sequence`、`effective_b_sequence`、
`requested_c_sequence`、`effective_c_sequence`）：时间界填写 `_ns` 字段而 sequence 字段为
`null`，sequence 界反之。窗口语义为在 `[a,effective_b)` 创建并在包含 c 时刻（时间或 sequence
均在 c 之内）所有结束事件后仍存活。`b` 缺省或超过 trace 终点时，effective b 使用严格位于最后
事件之后的纳秒/sequence 边界，保证半开窗口仍包含最后事件；effective c 使用包含最后事件的 trace
终点。程序化 API 的混合界按分量独立截断，未越界分量继续生效。

`allocations` 中每项包含 generation kind、allocation/mapping/heap ID、heap handle、地址、size 和
完整的 `created_by` Event。非 heap generation 的 `heap_handle` 为 `null`。summary 另外包含候选数、
截至 c 已结束数、最终过滤数、outstanding 数以及两类 orphan end 计数。

## 5.1 stacks 文档

`--group-by` 的输出 `mode` 为 `stacks`，`dataset` 为 `events` 或 `leaks`。events 数据集的
`window` 为 `{from_ns, to_ns|null, from_sequence|null, to_sequence|null}`，leaks 数据集沿用
leaks 窗口结构（含 `effective_b_ns`）。
`groups` 按排序键降序排列：events 组包含 `rank`、`calls`、`alloc_calls`、`alloc_bytes`、
`free_calls`、`free_bytes`、`net_bytes`，leaks 组包含 `rank`、`calls`、`bytes`；两者都带
`apis`（组内涉及的分配 API 规范名数组，按首次出现排序）、`stack_id` 与完整 `sample_event`
（含调用栈）。events 数据集 summary 含 `groups`、`calls`、
`alloc_bytes`、`free_bytes`、`net_bytes`、`aggregated_events` 和 `unmatched_frees`；leaks 数据集
summary 含 `groups`、`calls` 和 `bytes`。

## 5.2 memory 文档

`--mode memory` 的输出 `mode` 为 `memory`。`window` 为 `{from_ns, to_ns|null}`（快照没有事件
sequence，不接受 `#sequence` 窗口界）。`snapshots` 按采样 tick 升序，每项包含
`monotonic_ticks`、`relative_time_ns`，以及按该 tick 到期情况出现的 `counters` 和/或 `map`
（键缺省表示该 tick 无此采样）：

- `counters`：`working_set_bytes`、`peak_working_set_bytes`、`private_bytes`、`commit_bytes`。
- `map`：全量 walk 的聚合 `committed_bytes`、`reserved_bytes`、`free_bytes`、
  `largest_free_bytes`，外加 `region_count`、`truncated` 和完整 `regions` 数组（`base` 为按
  pointer width 补零的十六进制字符串，`size` 为十进制整数，`state` 为 `commit`/`reserve`、
  `type` 为 `image`/`mapped`/`private`、`protect` 为十六进制字符串）。区域明细只进 JSON；
  console/CSV 只给聚合。

summary 的 mode 专属字段为 `snapshots`、`counter_snapshots` 和 `map_snapshots`（均为窗口过滤
后的计数），公共字段与其他 mode 一致。

## 6. API、调用栈和符号

事件始终保留数值 `api.id` 和 `stack.id`。定义尚不可用时，API name/module 为 `null`；有效 stack ID
仍会输出，`definition_available` 为 false，status 可为 `null`，frames 为空。无 stack ID 的事件使用
`id: null`、`status: "unavailable"`。

解析信息可用时，stack status 为 `complete`、`truncated_by_depth`、`unwind_failed` 或
`unavailable`。每帧始终包含绝对地址，并可包含 module/symbol 及各自 offset。trace 文件内部相同
调用栈只写一次 StackDefinition，事件只保存 `stack_id`；分析 JSON 为自包含结果，因此会在每个输出
事件中展开可用 frames，同时保留原始 ID。

## 7. 完整性与校验

`completeness` 同时提供 mask、overall、lifecycle、stack detail、format understanding、已知 issue
列表和未来未知 bit。issue 名称使用稳定 snake_case。任何不完整结果仍由上层映射为推荐退出码 2。

`summary.custom_hook_failures` 列出 custom hook 安装失败明细：`module`（声明的模块名）、
`role`（`alloc`/`realloc`/`free`，point 级失败为 `point`）、`reason`（`module_not_loaded`、
`export_not_found`、`forwarded_export`、`invalid_rva`、`wrong_signature`、
`image_identity_mismatch`、`backend_unavailable`、`other`）与人读 `detail`。对应的
completeness issue 名为 `custom_hook_install_failed`。

单元测试使用独立的小型 JSON parser 和 schema 验证器检查 events、Loss、outstanding、九类 payload、
UTF-8/控制字符、64 位整数边界、调用栈展示、流式管线、writer 状态和输出流失败。正式 writer 不依赖
第三方 JSON DOM，因此大 events 结果的内存占用不随事件总数增长。
