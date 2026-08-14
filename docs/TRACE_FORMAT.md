# Noleax Trace Format

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

V1 固定头为 68 bytes，位于文件起始位置：

| offset | 字段 | 类型 | V1 编码/含义 |
|---:|---|---|---|
| 0 | magic | byte[8] | ASCII `NLXTRACE` |
| 8 | header_size | uint16 | 68 |
| 10 | format_major | uint16 | 1 |
| 12 | format_minor | uint16 | 3 |
| 14 | byte_order | uint8 | little=1、big=2；V1 writer 写 1 |
| 15 | pointer_width | uint8 | 4 或 8 |
| 16 | platform | uint16 | unknown=0、windows=1、linux=2、macos=3 |
| 18 | architecture | uint16 | unknown=0、x86=1、x64=2、arm64=3 |
| 20 | flags | uint32 | capture 属性 |
| 24 | session_id | byte[16] | 同一轮捕获 UUID |
| 40 | file_index | uint32 | rotation index |
| 44 | monotonic_frequency | uint64 | tick frequency，必须非零 |
| 52 | monotonic_origin | uint64 | 原始单调时钟中 trace 相对时间的零点 |
| 60 | utc_origin_ns | int64 | 展示用 UTC 起点，二进制补码 |

header_size 允许同一 major 版本在固定前缀后追加字段。V1 writer 拒绝 unknown
platform/architecture、非 4/8 的 pointer_width 以及零 monotonic_frequency。

## 4. Chunk

文件头后为顺序 chunk。V1 chunk header 为 56 bytes：

| offset | 字段 | 类型 | V1 编码/含义 |
|---:|---|---|---|
| 0 | chunk_type | uint16 | metadata=1、module=2、stack=3、event=4、statistics=5、end=6、memory=7（minor 2 起） |
| 2 | chunk_version | uint16 | chunk payload 版本，必须非零 |
| 4 | header_size | uint16 | 56 |
| 6 | flags | uint16 | chunk flags |
| 8 | codec | uint8 | none=0、lz4=1、zstd=2 |
| 9 | reserved | byte[7] | 必须为零 |
| 16 | sequence_begin | uint64 | 首事件序号，无事件时为零 |
| 24 | sequence_end | uint64 | 末事件序号，无事件时为零 |
| 32 | uncompressed_size | uint64 | 解压后 payload 大小 |
| 40 | stored_size | uint64 | 文件中 payload 大小 |
| 48 | crc32c | uint32 | 未压缩 payload 的 CRC32C/Castagnoli |
| 52 | reserved2 | uint32 | 必须为零 |

sequence_begin 和 sequence_end 必须同时为零或同时非零；非零时 begin 不得大于 end。

reader 必须在分配或解压前检查：

- header_size 合法。
- stored_size 未超过剩余文件和实现上限。
- uncompressed_size 未超过配置和实现上限。
- codec 支持。
- CRC32C 正确。

最后一个 chunk 不完整时，保留之前所有完整 chunk 并将 trace 标记为 truncated。

reader 将“完整 chunk 后恰好 EOF”和“已出现下一个 chunk 的部分 header、header
extension 或 payload”分别返回 end-of-file 和 truncated。完整但校验失败的 chunk 属于损坏输入，
返回错误而不是伪装成 truncated。未知 chunk 按 header_size 和 stored_size 流式跳过，并将结果
标记为 partially understood。

## 5. Record framing

chunk payload 由 record 组成。每个 record 固定头为 8 bytes：

| 字段 | 类型 |
|---|---|
| record_type | uint16 |
| record_version | uint16 |
| record_size | uint32 |
| payload | byte[record_size - 8] |

同一 major 中未知 record 可以按 record_size 跳过。record_size 小于 header、超过 chunk 或违反实现上限时，该 chunk 无效。

RecordCursor 返回原始 type/version 和零拷贝 payload view；上层 decoder 可以忽略未知
type 后继续读取下一条 record。默认单 record 上限为 1 MiB，可由调用方收紧或放宽。

record_type 在 chunk_type 内命名，不是跨 chunk 的全局编号。V1 codec 均使用
record_version=1：

| chunk | record_type |
|---|---|
| metadata | CaptureScope=1、CustomHookDefinition=2（minor 1 起）、CustomHookFailure=3（minor 3 起） |
| stack | StackDefinition=1 |
| event | HeapCreate=1、HeapDestroy=2、Allocate=3、Reallocate=4、Free=5 |
| event | VmAllocate=6、VmFree=7、Map=8、Unmap=9、Loss=10 |
| statistics | CaptureStatistics=1 |
| end | EndOfTrace=1 |
| memory | MemoryCounters=1、MemoryMap=2（minor 2 起） |

同一 type 的更高 record_version 按未知 record 跳过并标记 partially understood，不能按 V1
payload 猜测解析。

V1 writer 默认单 chunk 未压缩上限为 16 MiB、存储上限为 17 MiB。写入前会同时检查
完整 chunk 是否可放入 max_file_size；不能完整容纳时返回 file-limit，不向 stream 写入半个 chunk。

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

首个可编码 metadata record 为 CaptureScope。payload 固定 8 bytes：
started_at_process_start uint8、preexisting_allocations_unknown uint8、reserved byte[6]。
两个布尔值只接受 0/1；process-start capture 不得同时声明 preexisting allocations unknown。

format minor 1 增加 CustomHookDefinition(record_type=2)，为每个 custom symbol hook 点记录
展示名。payload:api_id uint32、module_name_size uint32、label_size uint32、reserved uint32(0),
随后是 module_name 和 label 的 UTF-8 bytes(不带 NUL)。api_id 从 0x1000 起按声明顺序分配;
label 是符号名或 `module+0x<rva>`。该记录在对应 hook 点的首个事件之前写出,通常与
CaptureScope 位于同一 metadata chunk。老 minor reader 将其按未知 record 跳过;新 reader 用
它把 custom api_id 解析为真实名称。custom hook 点的 allocation_id 按
`(api_id << 40) | counter` 合成,counter 每点从 1 递增,不与内建 allocation id 冲突。

format minor 3 增加 CustomHookFailure(record_type=3):custom hook 安装按 hook point
降级——某个 point 的任一角色装不上时只回滚该 point,失败明细写进 metadata chunk(紧接
CustomHookDefinition 之后),捕获以其余 hook 继续,并在 EndOfTrace 的 aggregate completeness
里设置 custom_hook_install_failed(bit 10)。payload:module_size uint32、detail_size uint32、
role uint8、reason uint8、reserved byte[6](0),随后是 module 和 detail 的 UTF-8 bytes
(不带 NUL)。role:alloc=0、realloc=1、free=2、point=255(整个 point 未装上,如模块未加载)。
reason:module_not_loaded=1(wait_module 超时也归此)、export_not_found=2、forwarded_export=3、
invalid_rva=4、wrong_signature=5、image_identity_mismatch=6、backend_unavailable=7、
other=255。detail 是人读消息。老 minor reader 将该记录按未知 record 跳过;新 reader 在遇到
记录时自行设置 bit 10,因此即使 EndOfTrace 缺失该 issue 也不会丢。

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

Module chunk V1 包含 ModuleLoad 和 ModuleUnload。chunk descriptor 不使用内存事件 sequence range；
record 使用与事件相同的 monotonic clock，且按 tick 非递减。相同路径和基址重新加载仍产生新
module_id。

ModuleLoad 的固定 payload 为 80 bytes，随后是不含 NUL 的 UTF-8 image path 和 PDB path；完整
`record_size = 88 + image_path_size + pdb_path_size`：

| payload offset | 字段 | 类型 | V1 编码/含义 |
|---:|---|---|---|
| 0 | module_id | uint64 | 非零且 session 内唯一 |
| 8 | monotonic_ticks | uint64 | 不早于 FileHeader origin |
| 16 | base_address | uint64 | 非零 |
| 24 | image_size | uint64 | 非零，范围不得溢出 |
| 32 | flags | uint32 | bit0=image path truncated，bit1=PDB path truncated |
| 36 | presence | uint8 | bit0=PE identity，bit1=PDB identity |
| 37 | reserved | byte[3] | 必须为零 |
| 40 | PE timestamp | uint32 | identity 不存在时为零 |
| 44 | PE checksum | uint32 | identity 不存在时为零 |
| 48 | PE image size | uint32 | identity 不存在时为零；存在时等于 image_size |
| 52 | PDB age | uint32 | identity 不存在时为零 |
| 56 | image_path_size | uint32 | 后缀第一段长度 |
| 60 | pdb_path_size | uint32 | 后缀第二段长度 |
| 64 | CodeView GUID | byte[16] | identity 不存在时全零 |
| 80 | paths | byte[] | image path 后紧跟 PDB path |

ModuleUnload payload 为 16 bytes，完整 record 为 24 bytes：

| payload offset | 字段 | 类型 | V1 编码/含义 |
|---:|---|---|---|
| 0 | module_id | uint64 | 必须引用当前 live generation |
| 8 | monotonic_ticks | uint64 | 不早于对应 load |

Windows writer 在 hook 安装前记录初始模块并用 loader 通知追加代次；详细安全边界见
[MODULE_TRACKING.md](MODULE_TRACKING.md)。

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

V1 StackDefinition 的固定 payload 为 16 bytes，随后每帧 32 bytes；完整 `record_size` 为
`24 + 32 * frame_count`：

| payload offset | 字段 | 类型 | V1 编码/含义 |
|---:|---|---|---|
| 0 | stack_id | uint64 | 必须非零且在 session 内唯一 |
| 8 | capture_status | uint8 | complete=0、truncated_by_depth=1、unwind_failed=2、unavailable=3 |
| 9 | reserved | byte[3] | 必须为零 |
| 12 | frame_count | uint32 | 必须与剩余 payload 精确匹配 |

每个 frame 从 payload offset `16 + 32 * index` 开始：

| frame offset | 字段 | 类型 | V1 编码/含义 |
|---:|---|---|---|
| 0 | module_id | uint64 | 未知时为 0 |
| 8 | module_offset | uint64 | module_id 为 0 时必须为 0 |
| 16 | absolute_address | uint64 | 必须非零，始终保留 |
| 24 | flags | uint32 | V1 必须为 0 |
| 28 | reserved | uint32 | 必须为 0 |

complete/truncated 必须至少有一帧；unwind_failed/unavailable 必须为零帧。Windows writer
命中已知 module range 时写 generation 和相对 offset；未知/JIT frame 仍写 `module_id=0`、
`module_offset=0` 并保留绝对地址。
writer 总是在引用某个新 stack_id 的 Event chunk 之前写出相应 StackDefinition chunk。

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

dictionary 以完整原始帧数组解决 hash 碰撞；segment reset 只释放进程内索引，stack_id 全局
单调递增，已经落盘的 definition 不会重写或复用。

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

monotonic_ticks 保存与 FileHeader 相同计数器的原始值，必须大于等于 monotonic_origin。用户看到的
相对时间为 `(monotonic_ticks - monotonic_origin) / monotonic_frequency`；a/b/c 边界比较使用该
有理数，不得先做有损浮点或整数取整。

V1 event record 的 payload 以前 56 bytes 作为公共头，随后紧跟具体 operation payload：

| payload offset | 字段 | 类型 |
|---:|---|---|
| 0 | sequence | uint64 |
| 8 | monotonic_ticks | uint64 |
| 16 | thread_id | uint64 |
| 24 | api_id | uint32 |
| 28 | status | uint8 |
| 29 | error_domain | uint8 |
| 30 | reserved | byte[2]，必须为零 |
| 32 | stack_id | uint64 |
| 40 | flags | uint32 |
| 44 | reserved2 | byte[4]，必须为零 |
| 48 | raw_error_code | uint64 |

status 编码：success=0、failure=1、unmatched=2、preexisting=3。error_domain 编码：none=0、
win32=1、ntstatus=2、posix=3、mach=4。

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

V1 固定 operation payload 和完整 record 大小如下；大小包含 8-byte record framing 和
56-byte event 公共头：

| record | operation payload | record_size |
|---|---:|---:|
| HeapCreate | 40 | 104 |
| HeapDestroy | 24 | 88 |
| Allocate | 48 | 112 |
| Reallocate | 72 | 136 |
| Free | 48 | 112 |
| VmAllocate | 88 | 152 |
| VmFree | 56 | 120 |
| Map | 72 | 136 |
| Unmap | 40 | 104 |

所有 operation payload 按本节后续字段出现顺序编码为 little-endian 固定宽度整数。需要对齐
的位置显式写零 reserved bytes，不使用 C++ struct padding。

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

effect 编码：no_change=0、new_generation=1、freed=2；其后为 7 个必须为零的 reserved bytes。

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
- mapping generation 的规范化 base/size；commit 更新可与原始 result range 不同。
- allocation type。
- protection。
- mapping_id，仅本进程成功操作时非零。

VmFree：

- process handle classification、raw process handle 和可用时的 process id。
- base。
- region size。
- free type。
- mapping_id，可匹配时。

**Linux 区间语义扩展（H3）**：Linux writer 发出的 VmFree 可以是部分/内部释放——base
位于 generation 内部、region size 小于该 generation 的剩余范围；一次 munmap 或一次
隐式逐出（MAP_FIXED、mremap）可以对一个 generation 产生多条 VmFree，也可以横跨多个
generation 各发一条。`free_type` 恒带 release 位（0x8000）。下游读取方必须按
`[base, base+region_size)` 从该 mapping_id 的存活区间里相减，而不是整代结束；
`region_size == 0` 仍是 Windows 的整段 release 线形（base 必须等于代基址）。文件视图
的部分释放同样以 VmFree 表达（mapping_id 指向 mapped-view generation）；Unmap 仍表示
整视图结束。部分释放的完整模型见 TRACE_WRITER.md §8.1。

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

ProcessTarget 固定为 24 bytes：scope uint8、reserved byte[7]、raw process handle uint64、
process_id uint64。scope 编码为 current_process=0、remote_process=1、unknown=2。

## 13. Loss 和完整性

Loss record：

- 原因。
- 丢失事件估计数量。
- 已知时记录 sequence/time 范围。
- 发生位置：agent queue、writer、rotation、decoder。

原因至少包含：

- unknown=0（无效）、queue_full=1、trace_full=2、writer_error=3。
- stack_capture_failed=4、rotation_limit=5、decoder_error=6。

发生位置编码：unknown=0（无效）、agent_queue=1、writer=2、rotation=3、decoder=4。
estimated_event_count 缺省表示数量未知；存在时必须大于零。sequence range 的两个端点必须
同时存在且从 1 开始，sequence/tick range 均不得反向。

V1 Loss payload 固定 48 bytes：reason uint8、location uint8、presence flags uint8、reserved
byte[5]，随后依次为 count、sequence_begin、sequence_end、tick_begin、tick_end 五个 uint64。
presence bit 0/1/2 分别表示 count/sequence/tick 是否存在；缺省字段的存储值必须为零。
存在的 tick range 两端都必须大于等于 FileHeader.monotonic_origin。

完整性维度：

- capture_started_at_process_start。
- attach_has_preexisting_allocations。
- event_loss。
- trace_truncated。
- writer_error。
- unknown_record_skipped。

任一影响生命周期的维度存在时，outstanding 结果标记 incomplete，默认退出码为 2。

完整性问题以 uint32 bit mask 保存：

| bit | issue | lifecycle | stack detail | understanding |
|---:|---|:---:|:---:|:---:|
| 0 | capture_did_not_start_at_process_start | 否 | - | - |
| 1 | preexisting_allocations_unknown | 否 | - | - |
| 2 | event_loss | 否 | 否 | - |
| 3 | trace_truncated | 否 | 否 | - |
| 4 | writer_error | 否 | 否 | - |
| 5 | unknown_record_skipped | 否 | 否 | partial |
| 6 | missing_end_of_trace | 否 | 否 | - |
| 7 | abnormal_stop | 否 | 否 | - |
| 8 | stack_data_loss | 是 | 否 | - |
| 9 | partially_understood_format | 否 | 否 | partial |
| 10 | custom_hook_install_failed | 否 | 否 | - |

表中的“是/否”表示该维度是否仍完整。未知的未来 bit 保留，并按 overall/lifecycle/stack
incomplete、understanding partial 处理。只有 mask=0 时默认退出码为 0；任何 issue 均返回 2。
stack_capture_failed 只设置 stack_data_loss，不伪称 allocation 生命周期已经丢失；其他 Loss
reason 设置 event_loss，writer_error 还同时设置 writer_error bit。

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

analyzer 校验 successful+failed=observed、filtered+dropped<=observed、per-API ID 唯一且汇总值
与 aggregate 完全一致；计数求和必须检查 uint64 overflow。

V1 CaptureStatistics payload 固定前缀为 80 bytes：9 个 aggregate uint64、per_api_count
uint32、reserved uint32；随后每个 API 使用 48 bytes（api_id uint32、reserved uint32、
5 个计数 uint64）。完整 record_size 为 88+48*per_api_count。

EndOfTrace：

- final sequence。
- final monotonic time。
- normal_stop。
- target_exit_code，可用时。
- aggregate completeness。

缺少 EndOfTrace 表示 abnormal/truncated，但不使之前完整 chunk 失效。

CompletenessTracker 在看到 EndOfTrace 前始终设置 missing_end_of_trace；正常 EndOfTrace 清除此
bit，非正常结束增加 abnormal_stop，并合并 agent 写入的 aggregate completeness。重复 EndOfTrace、
EndOfTrace 自称缺失以及 normal_stop 同时报告 abnormal_stop 都是无效状态。

V1 EndOfTrace payload 固定 40 bytes：final_sequence uint64、final_monotonic_ticks uint64、
normal_stop uint8、target_exit_code_present uint8、reserved byte[6]、target_exit_code int32、
reserved uint32、completeness mask uint32、reserved uint32。缺省 target exit code 的存储值必须为零。
final_monotonic_ticks 必须大于等于 FileHeader.monotonic_origin。

## 15. Memory snapshot records

format minor 2 增加 memory chunk（chunk_type=7）：agent 的 writer 线程按独立间隔周期采样进程
内存状态，每次写出包含一到两条 record 的一个 memory chunk。chunk descriptor 不带 event
sequence range；reader 按非 event chunk 要求其为空。两种 record 的 ticks 都来自与事件相同的
单调时钟，由单线程顺序采样，天然非递减；analyzer 校验 ticks 不小于 monotonic_origin 且不回退。
捕获开始（基线）和正常收尾各对每个启用的采样器补一条记录；DLL_PROCESS_DETACH 收尾路径不补
最终快照，以最后一条周期快照为准。老 minor reader 将整个 memory chunk 按未知 chunk 跳过并
标记 partially understood。

### 15.1 MemoryCounters（record_type=1）

payload 固定 48 bytes：monotonic_ticks uint64、working_set_bytes uint64、
peak_working_set_bytes uint64、private_bytes uint64、commit_bytes uint64、reserved byte[8]。
Windows 数据源为 `K32GetProcessMemoryInfo`（PROCESS_MEMORY_COUNTERS_EX），commit_bytes 取
PagefileUsage。codec 校验 peak 不低于当前 working set。

### 15.2 MemoryMap（record_type=2）

全量 VirtualQuery 地址空间 walk 的快照。payload 固定前缀 48 bytes：monotonic_ticks uint64、
flags uint8（bit0 = truncated，其余为零）、reserved byte[3]、region_count uint32、
committed_bytes uint64、reserved_bytes uint64、free_bytes uint64、largest_free_bytes uint64；
随后为 region_count 条各 24 bytes 的 region：base uint64、size uint64、state uint8
（commit=1、reserve=2）、type uint8（image=1、mapped=2、private=3）、protect uint32、
reserved byte[2]。

- 只列出 MEM_COMMIT/MEM_RESERVE region；MEM_FREE region 只计入 free_bytes 与
  largest_free_bytes 聚合。
- region 按 base 升序排列，不得重叠，size 不得为零；region 数上限为 32768 条
  （kMaximumMemoryMapRegions，约占单 record 1 MiB 上限的 3/4），超出时截断列表并置
  truncated 标志。
- 聚合计数（committed/reserved/free/largest_free）始终是全量 walk 的结果，不受列表截断影响。

## 16. Compression

- codec 逐 chunk 指定。
- 默认 LZ4。
- Zstd level 1 为较高压缩率选项。
- none 用于诊断和最小依赖场景。
- hook 回调不执行压缩。
- CRC32C 针对未压缩 payload，统一覆盖所有 codec。
- reader 必须限制压缩展开比例和最大 uncompressed_size。
- V1 canonical writer 对空压缩 chunk 写入零长度 stored payload；reader 要求 compressed
  uncompressed_size/stored_size 同时为零或同时非零。
- codec 不支持时返回格式不支持错误，不猜测内容。

Windows writer 对数据 chunk 使用所选 codec；最后的 Loss、Statistics 和 EndOfTrace 使用
none。终止记录较小，固定为 none 可给文件尾保留空间建立不依赖压缩 bound 的硬上限证明。

## 17. Rotation

- 同一 session 的文件共享 session_id。
- file_index 从 0 增加。
- 每个文件有独立 FileHeader。
- 默认 stop，不默认删除旧分片。
- rotate 达到 max_files 后停止并写 Loss/Statistics。
- 若未来支持删除最旧文件，必须使用不同 policy 名称并明确结果不完整。

## 18. 安全限制

reader 将 trace 视为不可信输入：

- 所有长度先检查后分配。
- 限制单块、单 record、字符串、帧数和总索引内存。
- 压缩库错误不得越界读取。
- 整数加法和乘法检查溢出。
- 符号路径不从 trace 自动加载 DLL。
- trace 内 URL 不触发联网。
- fuzz target 覆盖 header、chunk、record、compression 和生命周期状态机。

reader 默认限制：file/chunk header 各 64 KiB、stored chunk 17 MiB、uncompressed
chunk 16 MiB、最大展开比例 65536:1。所有长度在分配和解压前验证；调用方可以进一步收紧。

## 19. 合成 trace fixture

提供仅供测试使用的 SyntheticTraceBuilder，以正式 TraceWriter 和 V1 record codec 生成
fixture，再用正式 TraceReader 和 decoder 验证，不维护第二套 wire-format 实现。

生成规则：

- chunk 固定按 metadata、event、memory、statistics、end 排列；后四类在没有对应 record 时省略。
- metadata 当前包含一个 CaptureScope；event chunk 按调用顺序保存 Event 和 Loss。
- memory chunk 按调用顺序保存 MemoryCounters 和 MemoryMap，其 ticks 同样不得回退。
- event sequence 必须严格递增，monotonic ticks 不得回退。
- event chunk 的 sequence 范围覆盖事件和具有 sequence range 的 Loss；正常结束的最终 sequence
  和 ticks 自动覆盖所有事件及 Loss 范围。
- Statistics 中的 `observed - filtered_before_queue - dropped` 必须等于实际编码的 Event 数量。
- `finish_normally` 从 CaptureScope 和 Loss 派生 aggregate completeness，并清除
  missing_end_of_trace；也可故意省略 EndOfTrace 生成异常终止 fixture。
- none、LZ4 和 Zstd 均可选择；文件大小上限仍由正式 writer 强制执行。

builder 不读取当前时间、不生成随机 session ID，也不隐式改写调用者输入。因此在 file header、
CaptureScope、record、codec 和 writer 选项完全相同时，输出必须逐字节一致。三种 codec 的确定性
和全量九类事件 round trip 都由自动测试覆盖。
