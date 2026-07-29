# Noleax Trace Format

> 状态：P0 逻辑格式基线
> 文件扩展名：.nlx
> format major：1
> 默认字节序：little-endian

## 1. 设计目标

- 流式写入和流式读取。
- 跨平台、跨架构。
- 目标异常退出后恢复所有完整块。
- 每个块独立选择 none、lz4 或 zstd。
- 文件大小有硬上限。
- 相同调用栈只写一次 definition，事件引用 stack_id。
- 显式记录丢失、截断、attach 盲区和过滤。
- reader 可以跳过同一 major 版本中的未知 record。

## 2. 兼容规则

- major 不同：reader 拒绝。
- major 相同、minor 更高：reader 跳过未知 chunk/record，并把结果标记为 partially understood。
- 所有整数使用固定宽度。
- 地址字段在 wire format 中统一为 uint64。
- header 记录目标 pointer width，32 位目标的高位必须为零。
- 不写入 size_t、C++ object、裸 enum 布局或结构体 padding。
- string 使用 UTF-8，长度单独编码，不以 NUL 结尾。

## 3. File Header

固定头位于文件起始位置，至少包含：

| 字段 | 类型 | 含义 |
|---|---|---|
| magic | byte[8] | NLXTRACE |
| header_size | uint16 | header 总长度 |
| format_major | uint16 | major |
| format_minor | uint16 | minor |
| byte_order | uint8 | little/big |
| pointer_width | uint8 | 4 或 8 |
| platform | uint16 | windows/linux/macos |
| architecture | uint16 | x86/x64/arm64 |
| flags | uint32 | capture 属性 |
| session_id | byte[16] | 同一轮捕获 UUID |
| file_index | uint32 | rotation index |
| monotonic_frequency | uint64 | tick frequency |
| monotonic_origin | uint64 | trace 相对时间起点 |
| utc_origin_ns | int64 | 展示用 UTC 起点 |

header_size 允许同一 major 版本追加字段。

## 4. Chunk

文件头后为顺序 chunk。每个 chunk header 包含：

| 字段 | 类型 | 含义 |
|---|---|---|
| chunk_type | uint16 | metadata/module/stack/event/statistics/end |
| chunk_version | uint16 | chunk payload 版本 |
| header_size | uint16 | chunk header 长度 |
| flags | uint16 | chunk flags |
| codec | uint8 | none/lz4/zstd |
| reserved | byte[7] | 必须为零 |
| sequence_begin | uint64 | 首事件序号，无事件时为零 |
| sequence_end | uint64 | 末事件序号，无事件时为零 |
| uncompressed_size | uint64 | 解压后 payload 大小 |
| stored_size | uint64 | 文件中 payload 大小 |
| crc32c | uint32 | 未压缩 payload 校验 |
| reserved2 | uint32 | 必须为零 |

reader 必须在分配或解压前检查：

- header_size 合法。
- stored_size 未超过剩余文件和实现上限。
- uncompressed_size 未超过配置和实现上限。
- codec 支持。
- CRC32C 正确。

最后一个 chunk 不完整时，保留之前所有完整 chunk 并将 trace 标记为 truncated。

## 5. Record framing

chunk payload 由 record 组成：

| 字段 | 类型 |
|---|---|
| record_type | uint16 |
| record_version | uint16 |
| record_size | uint32 |
| payload | byte[record_size - 8] |

同一 major 中未知 record 可以按 record_size 跳过。record_size 小于 header、超过 chunk 或违反实现上限时，该 chunk 无效。

## 6. 标识符

| 标识符 | 类型 | 规则 |
|---|---|---|
| sequence | uint64 | 从 1 单调增加，0 表示无事件 |
| module_id | uint64 | 模块每次加载产生新 ID |
| stack_id | uint64 | 每个 stack definition 唯一，0 表示无有效栈 |
| allocation_id | uint64 | 每次成功 alloc/realloc generation 唯一 |
| heap_id | uint64 | 规范化 heap 生命周期 ID |
| mapping_id | uint64 | 每次成功 map/allocate VM generation 唯一 |
| api_id | uint32 | 内建 API 表或 custom API 表索引 |

ID 只在一个 session 中有意义。

## 7. Metadata records

### 7.1 ProcessInfo

- pid。
- parent pid，可用时。
- image path。
- command line，可用时。
- target start time。
- agent ready time。
- capture kind：launch、attach、patched。
- attach_has_preexisting_allocations。

### 7.2 CaptureConfig

保存影响解释的有效配置：

- hook profile。
- enabled API IDs。
- max stack depth。
- capture-side size filter。
- compression。
- trace full policy。

敏感或与解释无关的配置不写入。

### 7.3 ApiDefinition

- api_id。
- canonical name。
- module。
- operation kind。
- adapter version。
- custom hook metadata，可用时。

## 8. Module records

ModuleLoad：

- sequence/time。
- module_id。
- base address。
- image size。
- UTF-8 path。
- PE timestamp/checksum。
- CodeView GUID/age/PDB path，可用时。

ModuleUnload：

- sequence/time。
- module_id。

相同路径和基址重新加载仍产生新 module_id。

## 9. Stack records

### 9.1 捕获与去重

hook 回调为每个事件捕获原始 PC 数组，并把它临时放入预分配队列。后台 writer：

1. 使用事件时间对应的 module generation 规范化每一帧。
2. 对规范化帧序列计算 hash。
3. 对 hash 命中执行完整逐帧比较。
4. 已存在时复用 stack_id。
5. 不存在时分配新 stack_id 并写 StackDefinition。

事件最终只保存 stack_id。

### 9.2 StackDefinition

- stack_id。
- capture status。
- frame count。
- 每个 frame：
  - module_id，未知时为 0。
  - module-relative offset，未知时为 0。
  - absolute address，始终保留。
  - frame flags。

capture status：

- complete
- truncated_by_depth
- unwind_failed
- unavailable

stack dictionary 有独立内存上限。达到上限时：

- 清理 writer 内存索引。
- 后续栈获得新的 stack_id。
- 已写入的 definition 永不被覆盖。
- 允许同一帧序列在不同 dictionary segment 获得不同 ID。

## 10. Event 公共字段

每个事件包含：

- sequence。
- monotonic_ticks。
- thread_id。
- api_id。
- operation。
- status。
- stack_id。
- flags。
- error domain（none、Win32、NTSTATUS、POSIX 或 Mach）和固定宽度 raw error code。

operation：

- heap_create
- heap_destroy
- alloc
- realloc
- free
- vm_alloc
- vm_free
- map
- unmap

status：

- success
- failure
- unmatched
- preexisting

failure 表示底层调用失败；unmatched 和 preexisting 表示调用成功，但无法匹配当前 session
创建的 generation。后两者不得伪造 allocation_id、heap_id 或 mapping_id。

## 11. Heap events

HeapCreate：

- raw heap handle。
- heap_id，仅成功时非零。
- flags。
- reserve/commit size。

HeapDestroy：

- raw heap handle。
- heap_id，可匹配时。
- result。

成功 destroy 结束该 heap 中全部 live allocation generation。

Allocate：

- heap_id/heap handle。
- requested size。
- result address。
- allocation_id，仅成功时非零。
- API flags。

Reallocate：

- heap_id/heap handle。
- old address。
- old allocation_id，可匹配时。
- requested size。
- result address。
- new allocation_id，仅成功并产生新 generation 时非零。
- API flags。
- effect：no_change、new_generation 或 freed；用于明确区分失败、原地/迁移 realloc
  和由 size-zero adapter 语义产生的释放。

成功 realloc 即使结果地址不变也必须使用新的 allocation_id。失败时 effect 为 no_change，
旧 generation 保持存活；effect 为 freed 时不得产生新 allocation_id。

Free：

- heap_id/heap handle。
- address。
- allocation_id，可匹配时。
- result。
- API flags。

## 12. Virtual memory events

VmAllocate：

- process handle classification、raw process handle 和可用时的 process id。
- requested base。
- result base。
- requested/result region size。
- allocation type。
- protection。
- mapping_id，仅本进程成功操作时非零。

VmFree：

- process handle classification、raw process handle 和可用时的 process id。
- base。
- region size。
- free type。
- mapping_id，可匹配时。

Map：

- section handle。
- process handle classification、raw process handle 和可用时的 process id。
- result base。
- view size。
- section offset。
- protection。
- mapping_id。

Unmap：

- process handle classification、raw process handle 和可用时的 process id。
- base。
- mapping_id，可匹配时。

对其他进程地址空间的操作可以作为 raw event 输出，但不加入当前目标进程 outstanding 状态。

## 13. Loss 和完整性

Loss record：

- 原因。
- 丢失事件估计数量。
- 已知时记录 sequence/time 范围。
- 发生位置：agent queue、writer、rotation、decoder。

原因至少包含：

- queue_full
- trace_full
- writer_error
- stack_capture_failed
- rotation_limit

完整性维度：

- capture_started_at_process_start。
- attach_has_preexisting_allocations。
- event_loss。
- trace_truncated。
- writer_error。
- unknown_record_skipped。

任一影响生命周期的维度存在时，outstanding 结果标记 incomplete，默认退出码为 2。

## 14. Statistics 和 EndOfTrace

Statistics：

- observed calls。
- successful operations。
- failed operations。
- filtered before queue。
- dropped events。
- unique/reused stacks。
- written uncompressed/compressed bytes。
- per-API counts。

EndOfTrace：

- final sequence。
- final monotonic time。
- normal_stop。
- target_exit_code，可用时。
- aggregate completeness。

缺少 EndOfTrace 表示 abnormal/truncated，但不使之前完整 chunk 失效。

## 15. Compression

- codec 逐 chunk 指定。
- 默认 LZ4。
- Zstd level 1 为较高压缩率选项。
- none 用于诊断和最小依赖场景。
- hook 回调不执行压缩。
- CRC32C 针对未压缩 payload，统一覆盖所有 codec。
- reader 必须限制压缩展开比例和最大 uncompressed_size。
- codec 不支持时返回格式不支持错误，不猜测内容。

## 16. Rotation

- 同一 session 的文件共享 session_id。
- file_index 从 0 增加。
- 每个文件有独立 FileHeader。
- 默认 stop，不默认删除旧分片。
- rotate 达到 max_files 后停止并写 Loss/Statistics。
- 若未来支持删除最旧文件，必须使用不同 policy 名称并明确结果不完整。

## 17. 安全限制

reader 将 trace 视为不可信输入：

- 所有长度先检查后分配。
- 限制单块、单 record、字符串、帧数和总索引内存。
- 压缩库错误不得越界读取。
- 整数加法和乘法检查溢出。
- 符号路径不从 trace 自动加载 DLL。
- trace 内 URL 不触发联网。
- fuzz target 覆盖 header、chunk、record、compression 和生命周期状态机。
