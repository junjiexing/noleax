# Noleax CLI 规范

> schema version：1

## 1. 命令结构

~~~
noleax [global-options] run [run-options] -- target [args...]
noleax [global-options] attach [attach-options]
noleax [global-options] patch [patch-options]
noleax [global-options] analyze [analyze-options] trace...
noleax [global-options] symbols [symbols-options] file
noleax [global-options] config validate
noleax [global-options] config print-effective
noleax [global-options] doctor [doctor-options]
~~~

命令名、选项名和枚举值使用英文，诊断信息第一版使用英文。路径按平台原生格式输入，内部统一使用 UTF-8。

## 2. 通用规则

- 功能性设置同时具有 CLI 和 TOML 表示。
- 优先级为 built-in defaults、config、CLI。
- help、version、config 文件路径属于元选项，不要求写回配置。
- 命令行出现未知选项时立即失败。
- 数值不接受静默截断或溢出。
- 大小支持 B、KiB、MiB、GiB。
- 相对时间支持 ns、us、ms、s、m、h。
- CLI 数组整体替换配置数组；名称包含 append 的选项才执行追加。
- 布尔设置同时提供 `--name` 和 `--no-name`，两者不能同时出现。
- 路径在合并配置后、执行命令前规范化。
- 参数中的地址统一使用 0x 前缀十六进制展示。

## 3. Global options

| CLI | 配置键 | 默认值 | 说明 |
|---|---|---|---|
| --config PATH | 不适用 | 无 | 读取 TOML |
| --log-level LEVEL | diagnostics.log_level | info | trace、debug、info、warn、error |
| --color MODE | diagnostics.color | auto | auto、always、never |
| --help | 不适用 | 无 | 显示帮助 |
| --version | 不适用 | 无 | 显示版本和构建信息 |

## 4. run

~~~
noleax run [capture-options] [injection-options] -- target [args...]
~~~

目标和参数可以来自命令行 operand，也可以来自 target.path 与 target.args。命令行 operand 存在时整体覆盖配置中的目标和参数。

| CLI | 配置键 | 默认值 |
|---|---|---|
| --working-directory PATH | target.working_directory | 目标文件目录 |
| --inject-method METHOD | injection.method | remote-thread |
| --agent PATH | injection.agent_path | 与 noleax 匹配的 agent |
| --inject-timeout DURATION | injection.timeout | 10s |
| --trace PATH | trace.path | 基于目标名和时间生成 |
| --capture-duration DURATION | capture.duration | 直到目标退出或用户停止 |

规划的 run 注入方法：

- remote-thread
- thread-hijack
- entrypoint-code
- static-pe-patch

全部四种 run 注入方法均已实现。`static-pe-patch` 要求目标是 `noleax patch` 生成的副本；
未打补丁的目标在执行前以退出码 1 拒绝，patched 副本的捕获语义见
[STATIC_PE_PATCH.md](STATIC_PE_PATCH.md)。

**默认（agent 直写）**：控制器把有效捕获配置写成会话 TOML 经 bootstrap 参数传入，注入后
agent 自行启动记录并直写 trace；`--capture-duration` 由 agent 到点自行 finalize（quiescence、
writer drain、物理 revert），目标继续以未插装状态运行。无 duration 时 agent 在目标退出
（`RtlExitUserProcess` hook，失败时 `DLL_PROCESS_DETACH` 兜底）时完成收尾，正常退出的 trace
带 end-of-trace。Ctrl+C 不再驱动收尾：控制器改为 detached 等待（退出码 2），agent 继续到
duration 或目标退出。汇总统计从 trace 回读，退出码由 trace 完整性驱动（0 完整、2 不完整、
3 注入失败）。

**`--live`**：恢复旧的管道会话——控制器创建 suspended 目标并在 agent ready 后才恢复主线程，
达到 duration 或 Ctrl+C 时驱动 drain 与 revert；若此时目标仍运行，不终止目标。live 下若目标
先于捕获停止自行退出，agent 随进程消失，无法执行 drain 与 revert：noleax 结束会话并保留已
按 flush 间隔落盘的 trace（缺少尾部记录），输出 target_exit_code 并以退出码 2 报告结果不
完整。`thread-hijack` 的安全语义见
[THREAD_HIJACK_INJECTION.md](THREAD_HIJACK_INJECTION.md)，`entrypoint-code` 的入口补丁与恢复
语义见 [ENTRYPOINT_INJECTION.md](ENTRYPOINT_INJECTION.md)。

## 5. attach

~~~
noleax attach --pid PID [capture-options] [injection-options]
~~~

| CLI | 配置键 | 默认值 |
|---|---|---|
| --pid PID | target.pid | 必填 |
| --inject-method METHOD | injection.method | remote-thread |
| --agent PATH | injection.agent_path | 与 noleax 匹配的 agent |
| --inject-timeout DURATION | injection.timeout | 10s |
| --trace PATH | trace.path | 基于 PID 和时间生成 |
| --capture-duration DURATION | capture.duration | 直到目标退出或用户停止 |
| --unload-on-stop / --no-unload-on-stop | injection.unload_on_stop | false |

规划的 attach 注入方法：

- remote-thread
- thread-hijack

两种 attach 注入方法均已实现（`entrypoint-code` 仅适用于 launch，attach 选择它会被配置校验
拒绝）。`--unload-on-stop` 让 agent 在捕获收尾完成后从仍在运行的目标卸载自身 DLL：
仅在全部 teardown 证明成立时执行（replacement 模块引用已释放、gate 无 parked 线程且计数
归零），任一不满足则保持驻留兜底。`run` 不支持该选项。attach 成功不表示
trace 完整；分析输出必须标记注入前分配未知。默认模式（agent 直写）下
`--capture-duration` 由 agent 自行执行，无 duration 时记录到目标退出；attach 的退出码同样由
trace 完整性驱动（preexisting 盲点使结果为 2）。`--live` 恢复管道会话语义（见 run 一节）。

## 6. Capture options

| CLI | 配置键 | 默认值 |
|---|---|---|
| --hook-profile PROFILE | capture.hook_profile | windows-native |
| --max-stack-depth N | capture.max_stack_depth | 64 |
| --capture-min-size SIZE | capture.min_size | 0B |
| --memory-counters-interval DURATION | capture.memory_counters_interval | 1s（0s 关闭） |
| --memory-map-interval DURATION | capture.memory_map_interval | 1s（0s 关闭） |
| --live / --no-live | capture.live | false（agent 直写） |
| --buffer-size SIZE | trace.buffer_size | 16MiB |
| --max-trace-size SIZE | trace.max_file_size | 256MiB |
| --max-trace-files N | trace.max_files | 1 |
| --on-trace-full POLICY | trace.on_full | stop |
| --flush-interval DURATION | trace.flush_interval | 250ms |
| --compression CODEC | trace.compression | lz4 |
| --compression-level N | trace.compression_level | codec 默认 |
| --custom-hook SPEC（可重复） | custom_hooks | 空 |

`--custom-hook` 把第三方 allocator 的分配函数声明为 hook 点，纳入与内置 API 相同的事件、
泄露聚合与展示体系，仅 `run` 与 `attach` 有效：

```
noleax run --custom-hook "myalloc.dll:alloc=my_malloc,free=my_free" -- app.exe
noleax attach --pid 1234 --custom-hook "myalloc.dll:alloc_pdb=myalloc!internal_alloc,free_rva=0x1a210,wait_module=10s"
```

SPEC 形如 `module:key=value,...`。alloc 与 free 必填、realloc 可选，每个角色三选一定位：
导出符号名（agent 在目标进程内解析）、`<role>_pdb`（controller 侧 DbgHelp 解析为 RVA）、
`<role>_rva`（直接 RVA，十六进制或十进制）。其余键：`size_arg`/`ptr_arg`（0–7，默认 0）、
`result_arg`（结果经 out-param 返回时）、`kind=calloc` 配 `count_arg`、`free_size_arg`、
`forced=true`（checked relocation 拒绝后允许 forced）、`wait_module`（模块未加载时的等待
上限，0 为立即失败）。同一模块只能声明一次，一次捕获最多 32 个 hook 点。完整语义见
[CUSTOM_HOOKS.md](CUSTOM_HOOKS.md) 与 [CONFIG.md](CONFIG.md)。

V1 profile：

| profile | API 组 |
|---|---|
| windows-nt-heap | Rtl heap create/destroy/alloc/realloc/free |
| windows-virtual-memory | NT virtual memory allocate/free/map/unmap |
| windows-native | 上述两组并集 |

`--capture-min-size` 在 Windows V1 只于 hook 热路径过滤尺寸严格小于阈值的
`RtlAllocateHeap`、`NtAllocateVirtualMemory` 和 `NtMapViewOfSection` creation-side 事件。成功 VM/
map 使用系统返回的实际大小，失败或异常使用请求大小。realloc、free/unmap、heap create/destroy
始终记录，以保留已观察 generation 的转换和关闭。被过滤调用仍计入 capture Statistics，但没有
事件、sequence 或调用栈。详见 [WINDOWS_HOOK_PROFILES.md](WINDOWS_HOOK_PROFILES.md)。

on-trace-full：

- stop
- rotate

当前实现单文件 `stop`，保证输出不超过 `max_file_size`；`rotate` 和 `max_files > 1` 在跨文件分析
协议完成前返回 5，不会静默降级。

compression：

- none
- lz4
- zstd

compression-level 只在 codec 支持时有效；不支持的组合报错。
V1 中 none、lz4 只接受 0；zstd 接受 0（codec 默认，即 level 1）或显式的 1。

`--memory-counters-interval` / `--memory-map-interval` 控制捕获期间的定时内存快照：
agent 的 writer 线程按各自间隔把进程内存计数器（working set、peak working set、private
bytes、commit 量）和全量虚拟内存 map（VirtualQuery walk 的 region 明细与聚合统计）写入
memory chunk。两者默认各 1s，`0s` 关闭对应采样器，上限 1h；捕获开始即采一次基线，正常收尾
再补一条最终快照（进程强拆的 DLL_PROCESS_DETACH 路径不补）。快照布局见
[TRACE_FORMAT.md](TRACE_FORMAT.md) 第 15 节，分析见 `--mode memory`。

## 7. patch

~~~
noleax patch --input INPUT --output OUTPUT [options]
~~~

| CLI | 配置键 | 默认值 |
|---|---|---|
| --input PATH | patch.input | 必填 |
| --output PATH | patch.output | 必填 |
| --patch-method METHOD | patch.method | entrypoint-section |
| --agent-name NAME | patch.agent_name | noleax-agent.dll |
| --allow-break-signature / --no-allow-break-signature | patch.allow_break_signature | false |
| --verify / --no-verify | patch.verify | true |
| --standalone / --no-standalone | patch.standalone | false |

规则：

- input 与 output 必须不同。
- output 已存在时失败，不提供隐式覆盖。
- V1 只接受原生 x64 EXE。
- 签名文件默认拒绝，`--allow-break-signature` 时从输出中剥离签名。
- managed、driver、EFI、packed 或结构异常文件拒绝。
- patch 只生成输出副本；写临时文件并重新解析验证后才改名。
- `--standalone` 时把 standalone 激活参数烧进参数区，patched 副本可直接运行自插装
  （agent 读配置直写 trace，无需控制器）；语义见 [STATIC_PE_PATCH.md](STATIC_PE_PATCH.md)
  第 8 节。
- 产物通过 `noleax run --inject-method static-pe-patch` 捕获；直接运行与未打补丁行为一致。
- patch 会改变文件哈希并通常破坏签名；agent DLL（--agent-name）需与产物同目录部署。

已实现，完整边界见 [STATIC_PE_PATCH.md](STATIC_PE_PATCH.md)。
- patch 会改变文件哈希并通常破坏签名；agent DLL（--agent-name）需与产物同目录部署。

已实现，完整边界见 [STATIC_PE_PATCH.md](STATIC_PE_PATCH.md)。

## 8. analyze

~~~
noleax analyze [options] trace...
~~~

trace operand 存在时整体覆盖 analysis.inputs。

每次执行接受一个 trace。传入多个文件会返回 5；rotation 文件的跨文件 sequence、module
generation 和机器输出 schema 在实现前不做猜测式拼接。

| CLI | 配置键 | 默认值 |
|---|---|---|
| --mode MODE | analysis.mode | events |
| --format FORMAT | analysis.format | console |
| --output PATH | analysis.output | stdout |
| --from TIME\|#SEQ | analysis.from | trace 起点 |
| --to TIME\|#SEQ | analysis.to | trace 终点 |
| --end TIME\|#SEQ | analysis.end | trace 终点 |
| --group-by DIM | analysis.group_by | 不聚合 |
| --sort KEY | analysis.sort | events 聚合 alloc-bytes,leaks 聚合 bytes |
| --trim-agent-frames / --no-trim-agent-frames | analysis.trim_agent_frames | true |
| --min-size SIZE | filters.min_size | 无 |
| --max-size SIZE | filters.max_size | 无 |
| --event TYPE | filters.events | 全部 |
| --thread TID | filters.threads | 全部 |
| --api NAME | filters.apis | 全部 |
| --module PATTERN | filters.modules | 全部 |
| --stack-module PATTERN | filters.stack_modules | 全部 |
| --allocation-id ID | filters.allocation_ids | 全部 |
| --status STATUS | filters.statuses | 全部 |
| --symbols MODE | symbols.mode | auto |
| --symbol-path PATH | symbols.paths | 空 |
| --symbol-server URL | symbols.servers | 空 |

mode：

- events：查看事件。`--from`/`--to` 限定事件时间窗（半开区间，缺省为全部）。
- leaks：泄露分析，列出在 `[from,to)` 内创建、到 `--end` 时刻仍未释放的对象（即原
  outstanding 语义）。三个窗口参数全部可选，裸 `--mode leaks` 即“任何时间申请、trace 结束时
  仍未释放”。
- memory：定时内存快照的时间序列（trace minor 2 起）。`--from`/`--to` 只接受时间界；
  快照没有事件 sequence，`#sequence` 窗口、`--end`、`--group-by`/`--sort`、
  `--trim-agent-frames` 与全部事件过滤器在该模式下被配置校验拒绝。区域明细只进 JSON；
  console 另附各计数器的峰值汇总。

每个窗口界可以是相对 trace 起点的时间（如 `10s`），也可以是事件 sequence（`#` 前缀加序号，
如 `#123456`）。`--to`/`--end` 超过 trace 终点（时间轴或最终 sequence）时不再报错：排他的
`--to` 使用严格位于最后事件之后的边界，包含式的 `--end` 使用最后事件位置。顺序校验只在同种类
的界之间进行（时间比时间、sequence 比 sequence，`from <= to`、`to <= end`），不同种类混用允许
但不检查顺序。events 模式不接受 `--end`。

--group-by：按指定维度聚合结果，当前唯一取值 `stack`（按调用栈）。events 下聚合成功的
alloc/realloc/free：每组输出
总调用次数、alloc 次数与请求字节合计、free 次数与释放字节合计（free 尺寸经 generation 追踪，
未被追踪的 free 计入 unmatched-frees）及净字节。leaks 下聚合存活的 heap allocation：每组输出
存活分配个数与存活字节合计。每组同时列出涉及的分配 API 规范名（console 的 `apis=`、JSON 的
`apis` 数组、CSV 的 `api_names` 列，均按首次出现排序）。聚合文档的 JSON `mode` 字段为
`stacks`，并以 `dataset` 区分 `events`/`leaks`。

--sort（仅配合 --group-by）：

- events 聚合：calls、alloc-bytes、free-bytes、net-bytes（默认 alloc-bytes）
- leaks 聚合：calls、bytes（默认 bytes）

均按降序，键值相同按 stack id 升序。不搭配 --group-by 使用 --sort 时配置校验报错。

--trim-agent-frames：展示调用栈时隐藏 noleax-agent 自身的帧（默认开启）。agent 在 hook 路径
上会留下少量自身栈帧，隐藏后每组栈的 #0 即目标程序的首个有效帧；需要完整原始栈时用
--no-trim-agent-frames 关闭。该选项只影响展示，不改写 trace。

format：

- console
- json
- csv

status：

- success
- failure
- unmatched
- preexisting

symbols mode：

- auto：尽可能解析符号，失败时静默回退到 module+offset（默认）。
- off：完全不触碰 DbgHelp——不探测映像、不访问符号服务器，始终输出 module+offset；与
  --symbol-path/--symbol-server 同时配置时校验报错。
- required：任一模块无法解析出符号（结果不是 symbols_loaded 或 exports_only）即分析失败，
  用于要求完整符号化的自动化场景。

`--symbol-path` 与 `--symbol-server` 都未配置时，analyzer 回退到 `_NT_SYMBOL_PATH` 与
`_NT_ALT_SYMBOL_PATH`（DbgHelp 惯例，分号连接的搜索路径，支持 `srv*` 语法）；配置任一者
则忽略环境变量。`--symbol-server` 的值已带 `srv*` 前缀（大小写不敏感）时原样透传，可写成
`srv*缓存目录*服务器地址` 指定本地下载缓存，否则自动补 `srv*` 前缀。符号服务器下载由
DbgHelp 在解析缺失 PDB 时按需进行。

同一过滤类别的重复选项为 OR，不同类别为 AND；大小范围包含端点。模块 pattern 支持 `*` 和
`?`，ASCII 大小写及 `/`、`\` 路径分隔符不敏感。API 名称区分大小写。

## 9. symbols

~~~
noleax symbols [options] file
~~~

枚举一个 PE 文件（exe/dll，x86/x64 均可）的符号：有匹配 PDB 时枚举 PDB publics/globals，
否则回退导出表。只读离线映像，不启动或注入进程。file operand 存在时覆盖
symbol_listing.input。

| CLI | 配置键 | 默认值 |
|---|---|---|
| --format FORMAT | symbol_listing.format | console |
| --output PATH | symbol_listing.output | stdout |
| --name PATTERN（可重复） | symbol_listing.name | 空 = 全部 |
| --match-case / --no-match-case | symbol_listing.match_case | false |
| --kind KIND（可重复） | symbol_listing.kind | 空 = 全部 |
| --fields a,b,c | symbol_listing.fields | 空 = 全部字段 |
| --symbol-path PATH | symbols.paths | 空 |
| --symbol-server URL | symbols.servers | 空 |

kind：

- function
- data
- public
- export
- other

fields：`name`、`undecorated_name`、`rva`、`va`、`size`、`kind`；缺省全选且顺序固定，
同时控制 console 列、CSV 列和 JSON 符号对象的键。

`--name` pattern 支持 `*` 与 `?`，同时匹配 `name` 与 `undecorated_name`；同类重复选项为
OR，name 与 kind 之间为 AND。`symbols.mode = off` 与本命令冲突，配置校验报错。
`--symbol-path`/`--symbol-server` 的搜索路径规则与 analyze 相同。完整的输出格式、状态处理
与示例见 [SYMBOLS.md](SYMBOLS.md)。

## 10. config

~~~
noleax --config noleax.toml config validate
noleax --config noleax.toml config print-effective
~~~

validate：

- 只解析、合并和验证配置。
- 不启动、attach、patch 或分析任何目标。

print-effective：

- 输出合并后的有效 TOML。
- 路径规范化。
- 明确每个值来自 default、config 或 CLI。
- 不输出不应公开的随机 session token。

## 11. doctor

doctor 是只读诊断命令，检查：

- 控制器平台和架构。
- agent 是否存在且架构匹配。
- Hoox backend 构建信息。
- Windows 版本。
- 当前用户权限。
- CFG/CET 环境信息。
- 符号解析组件。

doctor 不执行注入。

~~~
noleax doctor [--agent PATH] [--target PATH] [--pid PID] [--inject-method METHOD]
~~~

未提供可选探针时对应检查显示为 `skipped`。当前 `remote-thread`、`thread-hijack`、
`entrypoint-code` 和 `static-pe-patch` 都会通过方法检查。agent/target/PID 可同时提供，以一次
完成文件架构、运行进程架构和注入权限检查。所有四项均可通过 TOML 的
`injection.agent_path`、`target.path`、`target.pid` 和 `injection.method` 设置，CLI 优先。

## 12. 退出码

| code | 含义 |
|---:|---|
| 0 | 成功且结果完整 |
| 1 | 参数、配置、输入或一般运行错误 |
| 2 | 操作成功，但捕获或分析结果不完整 |
| 3 | 注入、权限或远程初始化失败 |
| 4 | trace 不支持或损坏到无法继续 |
| 5 | 平台、架构、API 或方法组合不支持 |

run 正常完成时优先返回目标进程退出码会与工具退出码冲突。V1 采用以下规则：

- noleax 自身失败时返回上述工具退出码。
- noleax 自身成功时返回 0，并在摘要中报告 target_exit_code。
- 未来如需透传目标退出码，新增显式选项，不改变默认行为。

## 13. 示例

只 hook NT Heap：

~~~powershell
noleax run --hook-profile windows-nt-heap --trace app.nlx -- app.exe
~~~

attach 到已运行的进程：

~~~powershell
noleax attach --pid 1234 --inject-method remote-thread --trace app.nlx
~~~

输出所有事件：

~~~powershell
noleax analyze --mode events --format console app.nlx
~~~

列出任何时间申请、trace 结束时仍未释放的对象：

~~~powershell
noleax analyze --mode leaks app.nlx
~~~

查看捕获期间的内存计数器与虚拟内存 map 快照序列：

~~~powershell
noleax analyze --mode memory app.nlx
noleax analyze --mode memory --from 5s --to 20s --format csv --output memory.csv app.nlx
~~~

分析时间窗口并聚合调用栈：

~~~powershell
noleax analyze --mode leaks --from 5s --to 20s --end 60s --group-by stack --sort bytes --min-size 1KiB --max-size 1MiB --format json --output leaks.json app.nlx
~~~

窗口界也可以用事件 sequence（`#` 前缀）：

~~~powershell
noleax analyze --mode events --from '#1000' --to '#5000' app.nlx
~~~

按调用栈聚合全部 alloc/realloc/free 并按净字节排序：

~~~powershell
noleax analyze --mode events --group-by stack --sort net-bytes app.nlx
~~~

列出一个 PE 文件的符号（PDB 优先，无 PDB 回退导出表），按名字与种类筛选并导出 JSON：

~~~powershell
noleax symbols app.dll
noleax symbols --name "*alloc*" --kind function --format json --output symbols.json app.dll
~~~

等价 TOML 和从捕获到分析的完整流程见 [QUICKSTART.md](QUICKSTART.md) 与
[../examples/README.md](../examples/README.md)。
