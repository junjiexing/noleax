# Noleax CLI 规范

> 状态：P8.5 Windows x64 V1 release candidate
> schema version：1

## 1. 命令结构

~~~
noleax [global-options] run [run-options] -- target [args...]
noleax [global-options] attach [attach-options]
noleax [global-options] patch [patch-options]
noleax [global-options] analyze [analyze-options] trace...
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

P7C Windows x64 全部方法均已实现。`static-pe-patch` 要求目标是 `noleax patch` 生成的副本；
未打补丁的目标在执行前以退出码 1 拒绝，patched 副本的捕获语义见
[STATIC_PE_PATCH.md](STATIC_PE_PATCH.md) 与 [ADR 0004](adr/0004-static-pe-patch-run-semantics.md)。
控制器创建 suspended 目标，只有 agent ready 后才恢复目标主线程。达到
`--capture-duration` 或收到 Ctrl+C 时完成 writer drain 和物理 hook revert；若此时目标仍运行，
不终止目标。若目标先于捕获停止自行退出，agent 随进程消失，无法执行 drain 与 revert：noleax
结束会话并保留已按 flush 间隔落盘的 trace（缺少尾部记录），输出 target_exit_code 并以退出码 2
报告结果不完整。`thread-hijack` 的安全语义见
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

P7B Windows x64 已实现两者（`entrypoint-code` 仅适用于 launch，attach 选择它会被配置校验
拒绝），且 `--unload-on-stop` 当前只接受 false。attach 成功不表示
trace 完整；分析输出必须标记注入前分配未知。

## 6. Capture options

| CLI | 配置键 | 默认值 |
|---|---|---|
| --hook-profile PROFILE | capture.hook_profile | windows-native |
| --max-stack-depth N | capture.max_stack_depth | 64 |
| --capture-min-size SIZE | capture.min_size | 0B |
| --buffer-size SIZE | trace.buffer_size | 16MiB |
| --max-trace-size SIZE | trace.max_file_size | 256MiB |
| --max-trace-files N | trace.max_files | 1 |
| --on-trace-full POLICY | trace.on_full | stop |
| --flush-interval DURATION | trace.flush_interval | 250ms |
| --compression CODEC | trace.compression | lz4 |
| --compression-level N | trace.compression_level | codec 默认 |

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

P6 已实现单文件 `stop`，保证输出不超过 `max_file_size`；`rotate` 和 `max_files > 1` 在跨文件分析
协议完成前返回 5，不会静默降级。

compression：

- none
- lz4
- zstd

compression-level 只在 codec 支持时有效；不支持的组合报错。
V1 中 none、lz4 只接受 0；zstd 接受 0（codec 默认，即 level 1）或显式的 1。

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

规则：

- input 与 output 必须不同。
- output 已存在时失败，不提供隐式覆盖。
- V1 只接受原生 x64 EXE。
- 签名文件默认拒绝，`--allow-break-signature` 时从输出中剥离签名。
- managed、driver、EFI、packed 或结构异常文件拒绝。
- patch 只生成输出副本；写临时文件并重新解析验证后才改名。
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

P6.7 每次执行接受一个 trace。传入多个文件会返回 5；rotation 文件的跨文件 sequence、module
generation 和机器输出 schema 在实现前不做猜测式拼接。

| CLI | 配置键 | 默认值 |
|---|---|---|
| --mode MODE | analysis.mode | events |
| --format FORMAT | analysis.format | console |
| --output PATH | analysis.output | stdout |
| --from TIME | analysis.from | trace 起点 |
| --to TIME | analysis.to | trace 终点 |
| --end TIME | analysis.end | trace 终点 |
| --group-by / --no-group-by | analysis.group_by | false |
| --sort KEY | analysis.sort | events 聚合 alloc-bytes,leaks 聚合 bytes |
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

时间一律相对 trace 起点。`--to`/`--end` 超过 trace 终点时按终点截断，不再报错；要求
`from <= to`、`to <= end`。events 模式不接受 `--end`。

--group-by：按调用栈聚合（当前唯一分组维度）。events 下聚合成功的 alloc/realloc/free：每组输出
总调用次数、alloc 次数与请求字节合计、free 次数与释放字节合计（free 尺寸经 generation 追踪，
未被追踪的 free 计入 unmatched-frees）及净字节。leaks 下聚合存活的 heap allocation：每组输出
存活分配个数与存活字节合计。聚合文档的 JSON `mode` 字段为 `stacks`，并以 `dataset`
区分 `events`/`leaks`。

--sort（仅配合 --group-by）：

- events 聚合：calls、alloc-bytes、free-bytes、net-bytes（默认 alloc-bytes）
- leaks 聚合：calls、bytes（默认 bytes）

均按降序，键值相同按 stack id 升序。不搭配 --group-by 使用 --sort 时配置校验报错。

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

- auto

同一过滤类别的重复选项为 OR，不同类别为 AND；大小范围包含端点。模块 pattern 支持 `*` 和
`?`，ASCII 大小写及 `/`、`\` 路径分隔符不敏感。API 名称区分大小写。

## 9. config

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

## 10. doctor

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

## 11. 退出码

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

## 12. 示例

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

分析时间窗口并聚合调用栈：

~~~powershell
noleax analyze --mode leaks --from 5s --to 20s --end 60s --group-by --sort bytes --min-size 1KiB --max-size 1MiB --format json --output leaks.json app.nlx
~~~

按调用栈聚合全部 alloc/realloc/free 并按净字节排序：

~~~powershell
noleax analyze --mode events --group-by --sort net-bytes app.nlx
~~~

等价 TOML 和从捕获到分析的完整流程见 [QUICKSTART.md](QUICKSTART.md) 与
[../examples/README.md](../examples/README.md)。
