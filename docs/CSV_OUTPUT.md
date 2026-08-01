# Noleax CSV 输出

> schema version：1
> 日期：2026-07-29

## 1. 目标与边界

CSV 面向表格工具和逐行数据管线。V1 提供 `CsvWriter`、`analyze_events_to_csv` 和
`analyze_outstanding_to_csv`。events 边读 trace 边写 Event/Loss，不缓存全部事件；outstanding 写入
最终候选。每个文件最后固定写一条 `summary`，因此消费者可以把“存在完整的末行 summary”作为输出
成功结束的结构信号。输入或输出在中途失败时，文件可能保留已验证的前序行，但不会有 summary。

CSV 不替代信息最完整的 JSON：V1 CSV 保留事件、payload、Loss、窗口、主要统计和完整性，省略
per-API statistics、完整 trace metadata 和 filter 对象。需要完整层级数据时使用 JSON。

## 2. 文件编码与引用

- UTF-8，不写 BOM；所有外部文本在写出前严格校验 UTF-8。
- 逗号分隔，记录结尾固定为 CRLF。
- 字段包含逗号、双引号、CR 或 LF 时使用双引号包围；字段内 `"` 写成 `""`。
- 缺失定义、无效 ID 和未提供的可选值写为空字段；数值零仍明确写为 `0` 或 `0x0`。
- 每一行都有 `csv_schema_version=1`；字段名和顺序属于版本化接口。
- 地址和 handle 使用按 pointer width 补零的小写十六进制；flags、错误码和 raw result 使用不补零的
  小写十六进制；size、ID、ticks 和计数使用无损十进制整数。

CSV 会原样保留以 `= + - @` 开头的 API、模块和符号文本，不做会改变数据的 spreadsheet 公式转义。
把不可信 trace 导入电子表格时，应把文本列显式设为 text，或使用禁用公式求值的导入方式。

## 3. events 表

events 文件的 `record_type` 为：

- `event`：一条匹配 Event；规范化公共字段及对应 payload 列有值。
- `loss`：一条 Loss；只填充 loss 列。
- `summary`：固定末行；包含 matched/filtered、trace、capture、termination 和 completeness 摘要。

下面各组按出现顺序拼接，构成 schema v1 的固定列顺序：

1. 行类型：`csv_schema_version, record_type`
2. Event 公共字段：`sequence, relative_time_ns, monotonic_ticks, thread_id, api_id, api_name,
   api_module, operation, status, event_flags, error_domain, error_code, stack_id, stack_status,
   stack_frames`
3. payload 公共与 heap 字段：`payload_kind, size, heap_handle, heap_id, heap_flags, reserve_size,
   commit_size, requested_size, result_size`
4. 地址和 generation 字段：`address, old_address, result_address, requested_base, result_base, base,
   region_size, allocation_id, old_allocation_id, new_allocation_id`
5. API/VM/map 字段：`api_flags, raw_result, reallocation_effect, process_scope, process_handle,
   process_id, allocation_type, free_type, protection, mapping_id, section_handle, view_size,
   section_offset`
6. Loss 字段：`loss_reason, loss_location, lost_event_count, loss_sequence_begin, loss_sequence_end,
   loss_tick_begin, loss_tick_end`
7. summary 计数：`matched_events, filtered_events, trace_events, loss_records, bytes_read,
   known_sequence_end, known_monotonic_end, truncated, partially_understood`
8. summary 完整性：`completeness_mask, completeness_overall, completeness_lifecycle,
   completeness_stack_detail, completeness_understanding, completeness_issues`
9. summary capture statistics：`capture_observed_calls, capture_successful_operations,
   capture_failed_operations, capture_filtered_before_queue, capture_dropped_events,
   capture_unique_stacks, capture_reused_stacks, capture_written_uncompressed_bytes,
   capture_written_stored_bytes`
10. summary termination：`final_sequence, final_monotonic_ticks, normal_stop, target_exit_code`

`size` 与过滤器语义一致：heap alloc/realloc 为 requested size；VM alloc 成功时为 result size、失败
时为 requested size；VM free 为 region size；map 为 view size；没有独立 size 的事件留空。具体 payload
原始 size 仍保留在对应专用列。

## 4. leaks 表

leaks（原 outstanding）文件的 `record_type` 为 `allocation` 或固定末行 `summary`。固定列顺序分组如下：

1. generation：`csv_schema_version, record_type, generation_kind, allocation_id, mapping_id, heap_id,
   heap_handle, address, size`
2. summary 窗口：`window_a_ns, window_b_ns, requested_c_ns, effective_c_ns,
   observation_uses_trace_end, trace_end_monotonic_ticks`。`window_b_ns` 填写请求的 `--to`，缺省时
   填写按 trace 终点截断的 effective 值。
3. 创建事件：`creation_sequence, creation_relative_time_ns, creation_monotonic_ticks, thread_id,
   api_id, api_name, api_module, operation, status, event_flags, error_domain, error_code, stack_id,
   stack_status, stack_frames`
4. summary 计数：`candidates, ended_by_c, filtered_out, outstanding, orphaned_allocation_ends,
   orphaned_mapping_ends, trace_events, loss_records, bytes_read, truncated, partially_understood`
5. summary 完整性和终止：`completeness_mask, completeness_overall, completeness_lifecycle,
   completeness_stack_detail, completeness_understanding, completeness_issues, normal_stop,
   target_exit_code`

窗口列只在 summary 行填写；allocation 行包含 generation 和创建 Event。即使没有 outstanding
allocation，也仍输出 header 和 summary，因此窗口及“结果为空”不会丢失。

## 4.1 stacks 表

`--group-by` 的 CSV 输出按数据集选择两种 header。`record_type` 为 `group` 或固定末行
`summary`。events 数据集的列为：

`csv_schema_version, record_type, rank, calls, alloc_calls, alloc_bytes, free_calls, free_bytes,
net_bytes, stack_id, stack_status, stack_frames, window_from_ns, window_to_ns, groups,
aggregated_events, unmatched_frees`，后接与 leaks 表相同的 trace/完整性/终止列。

leaks 数据集的列为：

`csv_schema_version, record_type, rank, calls, bytes, stack_id, stack_status, stack_frames,
window_a_ns, window_b_ns, requested_c_ns, effective_c_ns, observation_uses_trace_end, groups`，
后接同一组 trace/完整性/终止列。

events 数据集的窗口列和 leaks 数据集的窗口列均只在 summary 行填写；summary 行的 `calls` 与各字节
列为全组合计。

## 5. stack_frames 子格式

trace 内仍按 `stack_id` 去重。CSV 为自包含展示，把解析帧放在单个 `stack_frames` 字段中，每帧固定为：

```text
absolute_address|module|module_offset|symbol|symbol_offset
```

多帧用 `;` 分隔。module/symbol 内的 `\`、`|`、`;` 分别写为 `\\`、`\|`、`\;`，LF、CR、tab
写为 `\n`、`\r`、`\t`，其他 ASCII 控制字符写为 `\xHH`。缺失的 frame 子字段为空。这个子格式
先完成自身转义，再作为整体按标准 CSV 规则引用。

## 6. 测试验证

自动测试冻结两种 header 的完整字段顺序，并覆盖 Event/Loss/summary、九类 payload、outstanding
窗口、逗号/双引号/CRLF、Unicode、stack 子格式、64 位边界、非法 UTF-8、writer 状态和输出失败。
测试侧使用独立 RFC 4180 parser 反向读取结果，避免只验证字符串片段。
