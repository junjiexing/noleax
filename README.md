# Noleax

Noleax（读音 “no leaks”）是一个基于 hook 的内存事件捕获与离线分析命令行工具。它把 agent
DLL 注入目标进程，hook 内存分配 API，将 alloc/realloc/free、heap lifecycle 和 virtual memory
事件连同原始调用栈写入有界、可恢复的 trace 文件，再由内置 analyzer 离线过滤、聚合与符号化，
用于定位内存泄漏和分析分配行为。

当前支持 Windows x64（控制器与目标均为 x64）。项目处于 V1 release candidate 阶段：AI 技术门禁
已完成，等待人工最终验收，尚未创建 tag 或发布二进制。

## 功能特性

- 四种启动注入：`remote-thread`、`thread-hijack`、`entrypoint-code`、`static-pe-patch`，均在目标
  入口点之前完成注入。
- 两种 attach 注入：`remote-thread`、`thread-hijack`，连接运行中的进程。
- `noleax patch` 生成静态 patch 副本，配合 `static-pe-patch` 方式捕获，无需启动期远程注入。
- 基于 Hoox v0.1.1 的 hook profile 覆盖 Windows NT Heap 与 NT virtual memory 共九个逻辑 API。
- 有界 trace：大小上限、定期 flush、lz4/zstd 压缩、Module/Stack 字典去重，损坏时可部分恢复。
- 离线分析：events/outstanding 两种模式，多维过滤，console/JSON/CSV 输出，离线符号解析。
- TOML 配置与 CLI 等价，优先级为 built-in defaults < TOML < CLI。
- 只读 `doctor` 环境诊断，不执行注入。

## 系统要求

- Windows 10 或 Windows 11 x64。
- 构建需要 Visual Studio 2022（Desktop development with C++）、CMake 3.25+、Ninja、Git 和
  vcpkg。

## 构建

准备 vcpkg（baseline 固定在 vcpkg.json 中），然后进入开发环境：

~~~powershell
git clone https://github.com/microsoft/vcpkg.git _temp/vcpkg
git -C _temp/vcpkg checkout 9d7f79f56ae1a9b4704d6a7fb8237e347a974133
.\_temp\vcpkg\bootstrap-vcpkg.bat -disableMetrics
$env:VCPKG_ROOT = (Resolve-Path .\_temp\vcpkg).Path
.\scripts\Enter-NoleaxDevShell.ps1
~~~

配置、构建、测试（preset 可选 `windows-x64-debug`、`windows-x64-release`、
`windows-x64-hardened`）：

~~~powershell
cmake --preset windows-x64-release
cmake --build --preset windows-x64-release
ctest --preset windows-x64-release
~~~

产物位于 `build/<preset>/bin/`：`noleax.exe` 与 `noleax-agent.dll` 必须保持同目录部署。生成并
校验本地 RC ZIP 包：

~~~powershell
cpack --config .\build\windows-x64-release\CPackConfig.cmake -G ZIP
pwsh -NoProfile -File .\scripts\Test-NoleaxPackage.ps1 -SkipBuild
~~~

完整、可复现的构建命令见 [BUILDING.md](BUILDING.md)。

## 发布包

main 分支 CI 全部通过后，流水线会用 CPack 生成自包含 ZIP（`bin/` 内含 `noleax.exe` 与
`noleax-agent.dll`，另含 LICENSE、文档、示例与第三方声明及 SHA-256 校验文件），并上传到
GitHub Releases 的滚动预发布 `ci-latest`；推送 `v*` 标签则创建对应版本的 release 附件。打包布局
与发布流程见 [docs/PACKAGING.md](docs/PACKAGING.md)。

## 快速上手

以下示例假设已进入 `noleax.exe` 所在目录（RC 包的 `bin` 目录或构建输出的 `bin`）。

1. 只读环境检查，required check 必须全部为 `pass`：

   ~~~powershell
   .\noleax.exe doctor --target C:\apps\demo.exe
   ~~~

2. 启动目标并捕获（`--` 之后原样传入目标程序与参数）：

   ~~~powershell
   .\noleax.exe run --hook-profile windows-nt-heap --trace .\capture.nlx -- C:\apps\demo.exe
   ~~~

   目标退出、达到 `--capture-duration` 或按 Ctrl+C 时停止捕获；后两者不会终止仍在运行的目标。

3. 查看全部事件：

   ~~~powershell
   .\noleax.exe analyze --mode events --format console .\capture.nlx
   ~~~

4. 查找时间窗口 `[a,b)` 内分配、到时刻 c 仍未释放的对象：

   ~~~powershell
   .\noleax.exe analyze --mode outstanding --a 0s --b 10s --min-size 1KiB .\capture.nlx
   ~~~

常见失败的定位方法见 [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)。

## 使用说明

### 命令总览

~~~text
noleax [global-options] run [run-options] -- target [args...]
noleax [global-options] attach [attach-options]
noleax [global-options] patch [patch-options]
noleax [global-options] analyze [analyze-options] trace...
noleax [global-options] config validate
noleax [global-options] config print-effective
noleax [global-options] doctor [doctor-options]
~~~

全局选项：`--config PATH`（读取 TOML）、`--log-level LEVEL`（trace/debug/info/warn/error，
默认 info）、`--color MODE`（auto/always/never）、`--help`、`--version`。

数值与时间格式：大小支持 B、KiB、MiB、GiB；时间支持 ns、us、ms、s、m、h。布尔设置成对提供
`--name` / `--no-name`。命令行出现未知选项时立即失败。

### run：启动目标并捕获

~~~powershell
noleax run [capture-options] [injection-options] -- target [args...]
~~~

| 选项 | 默认值 | 说明 |
|---|---|---|
| `--inject-method METHOD` | remote-thread | remote-thread、thread-hijack、entrypoint-code、static-pe-patch |
| `--agent PATH` | 与 noleax 匹配的 agent | agent DLL 路径 |
| `--inject-timeout DURATION` | 10s | 注入超时 |
| `--trace PATH` | 按目标名与时间生成 | trace 输出路径 |
| `--capture-duration DURATION` | 直到目标退出或手动停止 | 捕获时长 |
| `--working-directory PATH` | 目标文件目录 | 目标工作目录 |

控制器以 suspended 方式创建目标，agent ready 后才恢复主线程，因此四种方法都能在目标入口点前
完成注入。`static-pe-patch` 要求目标是 `noleax patch` 生成的副本，未打补丁的目标会以退出码 1
拒绝。

### attach：连接运行中的进程

~~~powershell
noleax attach --pid 1234 --hook-profile windows-nt-heap --capture-duration 30s --trace .\attach.nlx
~~~

支持 `remote-thread` 与 `thread-hijack`。attach 无法知道注入前已存在的 allocation，分析输出会
标记 `preexisting_allocations_unknown`，并以退出码 2 表示结果不完整。

### patch：生成静态 patch 副本

~~~powershell
noleax patch --input C:\apps\demo.exe --output C:\apps\demo.patched.exe
~~~

规则：input 与 output 必须不同；output 已存在时失败；V1 只接受原生 x64 EXE；签名文件默认
拒绝，`--allow-break-signature` 时从输出剥离签名；managed、driver、EFI、packed 或结构异常文件
拒绝。patch 只生成副本，会改变文件哈希并通常破坏签名；agent DLL（默认名
`noleax-agent.dll`）需与产物同目录部署。产物通过
`noleax run --inject-method static-pe-patch` 捕获，直接运行与未打补丁行为一致。

### 捕获选项（run 与 attach 共用）

| 选项 | 默认值 | 说明 |
|---|---|---|
| `--hook-profile PROFILE` | windows-native | 见下方 profile 表 |
| `--max-stack-depth N` | 64 | 每个事件的最大栈帧数 |
| `--capture-min-size SIZE` | 0B | 过滤小于阈值的创建侧事件 |
| `--buffer-size SIZE` | 16MiB | trace 缓冲 |
| `--max-trace-size SIZE` | 256MiB | 单文件上限，保证不超限 |
| `--max-trace-files N` | 1 | 当前只支持 1 |
| `--on-trace-full POLICY` | stop | 达到上限时停止；rotate 尚未实现（返回 5） |
| `--flush-interval DURATION` | 250ms | 写盘间隔 |
| `--compression CODEC` | lz4 | none、lz4、zstd |
| `--compression-level N` | codec 默认 | none/lz4 只接受 0；zstd 接受 0 或 1 |

hook profile：

| profile | API 组 |
|---|---|
| windows-nt-heap | Rtl heap create/destroy/alloc/realloc/free |
| windows-virtual-memory | NT virtual memory allocate/free/map/unmap |
| windows-native | 上述两组并集 |

`--capture-min-size` 只在 hook 热路径过滤尺寸严格小于阈值的 `RtlAllocateHeap`、
`NtAllocateVirtualMemory` 和 `NtMapViewOfSection` 创建侧事件；realloc、free/unmap、heap
create/destroy 始终记录。被过滤的调用仍计入统计，但没有事件、sequence 或调用栈。

### analyze：离线分析

~~~powershell
noleax analyze [options] trace.nlx
~~~

当前每次执行接受一个 trace。两种模式：

- `events`：输出（过滤后的）全部事件，每个事件引用去重后的 stack id，analyzer 展开为调用栈。
- `outstanding`：选择在半开区间 `[a,b)` 内发生的 allocation/reallocation，只保留到时刻 c 仍未
  释放的对象；c 省略或晚于 trace 结束时使用 trace 结束时间。这是一份候选集合，不等同于语义上
  的泄漏证明，应重复 workload、缩小时间窗口并结合调用栈判断。

| 选项 | 默认值 | 说明 |
|---|---|---|
| `--mode MODE` | events | events、outstanding |
| `--format FORMAT` | console | console、json、csv |
| `--output PATH` | stdout | 输出文件 |
| `--a TIME` / `--b TIME` / `--c TIME` | 无 / 无 / trace end | outstanding 时间窗（相对 trace 起点） |
| `--min-size SIZE` / `--max-size SIZE` | 无 | 大小过滤，包含端点 |
| `--event TYPE` | 全部 | 事件类型 |
| `--thread TID` | 全部 | 线程 |
| `--api NAME` | 全部 | API 名称，区分大小写 |
| `--module PATTERN` | 全部 | 模块，支持 `*`、`?`，大小写与路径分隔符不敏感 |
| `--stack-module PATTERN` | 全部 | 按栈帧模块过滤 |
| `--allocation-id ID` | 全部 | allocation id |
| `--status STATUS` | 全部 | success、failure、unmatched、preexisting |
| `--symbols MODE` | auto | 符号解析模式 |
| `--symbol-path PATH` | 空 | 本地符号路径 |
| `--symbol-server URL` | 空 | 符号服务器 |

过滤规则：同一类别的重复选项为 OR，不同类别之间为 AND。

### config：配置验证与查看

~~~powershell
noleax --config noleax.toml config validate          # 只解析、合并、验证，不执行任何操作
noleax --config noleax.toml config print-effective   # 输出合并后的有效 TOML 及每项来源
~~~

### doctor：只读环境诊断

~~~powershell
noleax doctor [--agent PATH] [--target PATH] [--pid PID] [--inject-method METHOD]
~~~

检查控制器平台与架构、agent 存在性与架构匹配、Hoox backend 构建信息、Windows 版本、当前用户
权限、CFG/CET 环境信息和符号解析组件。不执行注入；未提供探针时对应检查显示 `skipped`。

### TOML 配置

功能性设置同时具有 CLI 和 TOML 表示，优先级为 built-in defaults < TOML < CLI。配置中的
`operation` 可直接选择操作，CLI 数组整体替换配置数组。相对路径在 TOML 中相对于配置文件目录，
在 CLI 中相对于当前目录。最小示例（完整字段见 [docs/CONFIG.md](docs/CONFIG.md)）：

~~~toml
schema_version = 1
operation = "run"

[target]
path = "application.exe"
args = []

[injection]
method = "remote-thread"
timeout = "10s"

[capture]
hook_profile = "windows-nt-heap"
max_stack_depth = 64
duration = "30s"

[trace]
path = "capture.nlx"
max_file_size = "256MiB"
compression = "lz4"
~~~

可直接修改的完整示例位于 [examples](examples)：run、events 分析和 outstanding 分析三份配置。

### 退出码

| code | 含义 |
|---:|---|
| 0 | 成功且结果完整 |
| 1 | 参数、配置、输入或一般运行错误 |
| 2 | 操作成功，但捕获或分析结果不完整（如 attach blind spot、丢弃记录） |
| 3 | 注入、权限或远程初始化失败 |
| 4 | trace 不支持或损坏到无法继续 |
| 5 | 平台、架构、API 或方法组合不支持 |

noleax 自身成功时返回 0，目标进程退出码在摘要中以 `target_exit_code` 报告。不要把退出码 2
当作无输出，先读取输出中的 completeness 原因。

## 文档

- 快速上手与排错：[docs/QUICKSTART.md](docs/QUICKSTART.md)、[docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)
- 完整参考：[docs/CLI.md](docs/CLI.md)、[docs/CONFIG.md](docs/CONFIG.md)、
  [docs/TRACE_FORMAT.md](docs/TRACE_FORMAT.md)、[docs/CONSOLE_OUTPUT.md](docs/CONSOLE_OUTPUT.md)、
  [docs/JSON_OUTPUT.md](docs/JSON_OUTPUT.md)、[docs/CSV_OUTPUT.md](docs/CSV_OUTPUT.md)、
  [docs/SYMBOLIZATION.md](docs/SYMBOLIZATION.md)
- 注入与 hook 设计：[docs/ENTRYPOINT_INJECTION.md](docs/ENTRYPOINT_INJECTION.md)、
  [docs/THREAD_HIJACK_INJECTION.md](docs/THREAD_HIJACK_INJECTION.md)、
  [docs/STATIC_PE_PATCH.md](docs/STATIC_PE_PATCH.md)、
  [docs/RTL_ALLOCATE_HEAP_HOOK.md](docs/RTL_ALLOCATE_HEAP_HOOK.md)、
  [docs/WINDOWS_HOOK_PROFILES.md](docs/WINDOWS_HOOK_PROFILES.md)、[docs/HOOK_API_MATRIX.md](docs/HOOK_API_MATRIX.md)
- 发布：[docs/RELEASE_CANDIDATE.md](docs/RELEASE_CANDIDATE.md)、
  [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md)、[docs/PACKAGING.md](docs/PACKAGING.md)
- 开发计划与全部设计文档索引见 [docs/DEVELOPMENT_PLAN.md](docs/DEVELOPMENT_PLAN.md)。

## License

Noleax 以 [MIT License](LICENSE) 发布。

第三方依赖、版本、Hoox 修改及完整版权文本清单见
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
