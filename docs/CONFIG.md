# Noleax 配置规范

> 格式：TOML
> schema_version：1

## 1. 合并规则

~~~
built-in defaults < TOML < command line
~~~

- 缺失键继承低优先级值。
- scalar 由高优先级直接替换。
- table 按键递归合并。
- array 由高优先级整体替换，不隐式拼接。
- 命令行 operand 中的 target+args 或 trace inputs 作为一个整体替换配置数组。
- 未知键报错。
- 类型错误报错。
- 重复定义依照 TOML 标准处理，不由 Noleax 宽松接受。
- schema_version 缺失或不支持时失败。

## 2. 完整结构

~~~
schema_version = 1
operation = "run"

[target]
path = "C:/apps/example.exe"
args = ["--mode", "test"]
working_directory = "C:/apps"
pid = 0

[injection]
method = "remote-thread"
agent_path = ""
timeout = "10s"
unload_on_stop = false

[capture]
hook_profile = "windows-native"
max_stack_depth = 64
min_size = "0B"
duration = ""
live = false

[trace]
path = "example.nlx"
buffer_size = "16MiB"
max_file_size = "256MiB"
max_files = 1
on_full = "stop"
flush_interval = "250ms"
compression = "lz4"
compression_level = 0

[analysis]
inputs = ["example.nlx"]
mode = "events"
format = "console"
output = ""
from = ""
to = ""
end = ""
group_by = ""
sort = "alloc-bytes"
trim_agent_frames = true

[filters]
min_size = ""
max_size = ""
events = []
threads = []
apis = []
modules = []
stack_modules = []
allocation_ids = []
statuses = []

[symbols]
mode = "auto"
paths = []
servers = []

[patch]
input = ""
output = ""
method = "entrypoint-section"
agent_name = "noleax-agent.dll"
allow_break_signature = false
verify = true
standalone = false

[diagnostics]
log_level = "info"
color = "auto"
~~~

示例展示 schema，不表示所有键在所有 operation 中都有效。与当前 operation 无关但非默认的配置键应报错，避免用户误以为设置已生效。

当前 Windows x64 对尚未实现但已为后续阶段预留的组合返回 5：`trace.on_full` 仅支持 `stop`、
`trace.max_files` 仅支持 1，`injection.unload_on_stop` 仅 attach 支持，analysis
每次仅支持一个 input。`injection.method` 在 run 下支持 `remote-thread`、`thread-hijack`、
`entrypoint-code` 和 `static-pe-patch`（后者要求 `noleax patch` 产物），attach 下支持
`remote-thread` 和 `thread-hijack`（其余组合由配置校验以退出码 1 拒绝）。配置值不会被
静默忽略。

`operation = "patch"` 与 `[patch]` 表用于静态 PE patch：input 只接受原生 x64 EXE，
签名文件默认拒绝，输出总是新副本且不与输入相同。patched 副本通过 `run` 加
`injection.method = "static-pe-patch"` 捕获。`patch.standalone = true` 时 patch 会把
standalone 激活参数烧进镜像，patched 副本可直接运行：agent 读取
`NOLEAX_AGENT_CONFIG` 环境变量或 exe 同目录的 `noleax-agent.toml`（沿用 `[capture]` 与
`[trace]` 段），自行把事件写入 trace，无需控制器。详见
[STATIC_PE_PATCH.md](STATIC_PE_PATCH.md) 第 8 节。

`capture.min_size` 与 `--capture-min-size` 语义相同。Windows V1 只在入队前过滤严格小于阈值的
`RtlAllocateHeap`、`NtAllocateVirtualMemory` 和 `NtMapViewOfSection`；realloc、free/unmap 与 heap
生命周期事件不被过滤。命令行指定该值时覆盖配置文件。完整规则见
[WINDOWS_HOOK_PROFILES.md](WINDOWS_HOOK_PROFILES.md)。

`symbols.paths` 与 `symbols.servers` 都为空时，analyzer 回退到 `_NT_SYMBOL_PATH` 与
`_NT_ALT_SYMBOL_PATH` 环境变量（DbgHelp 惯例）；配置任一者则忽略环境变量。`symbols.servers`
的值已带 `srv*` 前缀（大小写不敏感）时原样透传，可用 `srv*缓存目录*服务器地址` 指定本地
下载缓存，否则自动补 `srv*` 前缀。

`symbols.mode`：`auto`（默认）尽可能解析、失败静默回退 module+offset；`off` 完全不触碰
DbgHelp（不探测映像、不下载符号），与 `symbols.paths`/`symbols.servers` 同时配置校验报错；
`required` 要求每个模块都解析出符号（symbols_loaded 或 exports_only），否则分析失败。

## 3. operation

允许值：

- run
- attach
- patch
- analyze
- doctor

CLI subcommand存在时覆盖 operation。若 CLI 和配置均缺失，显示顶层帮助并返回 1。

## 4. 字符串值

### 4.1 大小

允许：

- B
- KiB
- MiB
- GiB

单位区分大小写，不接受含义不明确的 KB/MB/GB。内部使用 uint64 字节数，并检查溢出。

### 4.2 时间

允许：

- ns
- us
- ms
- s
- m
- h

内部解析为有符号或无符号纳秒值，具体字段按语义检查。负值默认不允许。

### 4.3 路径

- 配置文件中的相对路径相对于配置文件所在目录。
- CLI 相对路径相对于当前工作目录。
- 合并后转为规范化绝对路径。
- Windows 输入和输出使用 Unicode API。
- 序列化回 print-effective 时统一使用正斜线，保证 TOML 易读。

## 5. 校验规则

通用：

- max_stack_depth 范围为 1 到 256。
- buffer_size 必须能容纳至少一个最大事件。
- max_file_size 必须大于文件头、metadata 和一个最大块。
- max_files 至少为 1。
- on_full=rotate 时 max_files 至少为 2。
- compression=none 或 lz4 时 compression_level 必须为 0。
- compression=zstd 时 V1 接受 0（codec 默认，即 level 1）或 1。
- trace.path 的父目录必须存在或可创建。

run：

- target.path 必须存在。
- target.pid 不得设置。
- injection.method 必须支持 run。

attach：

- target.pid 大于 0。
- target.path 和 args 不得设置。
- injection.method 必须支持 attach。

patch：

- patch.input 和 patch.output 必须设置且不同。
- output 默认不得已存在。
- capture 和 trace 设置不得非默认。
- 上述规则只验证保留 schema；V1 不执行 patch，并在校验通过后返回 5。

analyze：

- analysis.inputs 至少一个。
- events 模式不得设置 analysis.end。
- analysis.sort 必须搭配 analysis.group_by（当前唯一取值 "stack"）；events 聚合接受 calls、alloc-bytes、free-bytes 和
  net-bytes，leaks 聚合接受 calls 和 bytes。
- from 小于等于 to；end 若设置，必须大于等于 to。
- to 和 end 超过 trace 结束时间时由 analyzer 按结束时间截断，不再报错。
- min_size 不得大于 max_size。
- filters.statuses 接受 success、failure、unmatched 和 preexisting。
- filters.events、threads、apis、modules、stack_modules、allocation_ids 和 statuses 中，同一数组的
  值为 OR；不同非空过滤类别之间为 AND。

## 6. CLI 对应性测试

每新增一个功能配置必须在同一变更中增加：

1. TOML schema 字段。
2. CLI option 或 operand mapping。
3. default/config/CLI 三层 precedence 测试。
4. 正向和反向 bool override 测试。
5. print-effective snapshot。
6. CLI.md 和 CONFIG.md 更新。

CI 中维护功能设置清单，防止只实现 CLI 或只实现配置。

## 7. 向后兼容

- schema_version 的主版本不兼容时拒绝。
- 同一主版本新增可选键时保持旧配置有效。
- 删除或重命名键需要至少一个版本给出明确迁移诊断。
- 不静默解释拼写相近的旧键。
- print-effective 始终输出当前 schema。
