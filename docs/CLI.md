# Noleax CLI 规范

> 状态：P0 基线
> schema version：1

## 1. 命令结构

~~~
noleax [global-options] run [run-options] -- target [args...]
noleax [global-options] attach [attach-options]
noleax [global-options] patch [patch-options]
noleax [global-options] analyze [analyze-options] trace...
noleax [global-options] config validate
noleax [global-options] config print-effective
noleax [global-options] doctor
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

run 可用注入方法：

- remote-thread
- thread-hijack
- entrypoint-code

控制器创建 suspended 目标，只有 agent ready 后才恢复目标主线程。

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
| --unload-on-stop BOOL | injection.unload_on_stop | false |

attach 可用注入方法：

- remote-thread
- thread-hijack

attach 成功不表示 trace 完整；分析输出必须标记注入前分配未知。

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

on-trace-full：

- stop
- rotate

compression：

- none
- lz4
- zstd

compression-level 只在 codec 支持时有效；不支持的组合报错。

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
| --allow-break-signature BOOL | patch.allow_break_signature | false |
| --verify BOOL | patch.verify | true |

规则：

- input 与 output 必须不同。
- output 已存在时失败，不提供隐式覆盖。
- V1 只接受原生 x64 EXE。
- 签名文件默认拒绝。
- managed、driver、EFI、packed 或结构异常文件拒绝。

## 8. analyze

~~~
noleax analyze [options] trace...
~~~

trace operand 存在时整体覆盖 analysis.inputs。

| CLI | 配置键 | 默认值 |
|---|---|---|
| --mode MODE | analysis.mode | events |
| --format FORMAT | analysis.format | console |
| --output PATH | analysis.output | stdout |
| --a TIME | analysis.a | 无 |
| --b TIME | analysis.b | 无 |
| --c TIME | analysis.c | trace end |
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

- events
- outstanding

format：

- console
- json
- csv

status：

- success
- failure
- unmatched

outstanding 模式要求 a 和 b。c 可省略。时间默认相对 trace 起点；未来若支持 sequence 表达式，将使用明确前缀，避免与时间混淆。

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

attach 并使用 RIP/thread context 劫持：

~~~powershell
noleax attach --pid 1234 --inject-method thread-hijack --trace app.nlx
~~~

输出所有事件：

~~~powershell
noleax analyze --mode events --format console app.nlx
~~~

分析时间窗口：

~~~powershell
noleax analyze --mode outstanding --a 5s --b 20s --c 60s --min-size 1KiB --max-size 1MiB --format json --output leaks.json app.nlx
~~~
