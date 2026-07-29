# Noleax 详细开发计划

> 状态：已确认
> 文档版本：0.1
> 更新日期：2026-07-29
> 确认日期：2026-07-29
> 当前阶段：P3 离线分析器
> 已完成工作项：P2.1、P2.2、P2.3、P2.4、P2.5、P2.6、P2.7、P3.1、P3.2、P3.3、P3.4、P3.5
> 下一工作项：P3.6 流式 JSON 输出

## 1. 文档目的

本文将 Noleax 的需求拆解为可以由 AI 独立实现、测试、提交，并由人工逐阶段 review 和验证的开发任务。

本文同时作为以下工作的基线：

- V1 范围和非目标。
- 架构及跨平台边界。
- CLI、配置、trace 和分析语义。
- Windows hook 稳定性方案。
- API 覆盖清单及逐 API 测试门禁。
- 注入方式及其适用范围。
- Git 分支、提交和人工验收流程。
- 后续平台和自定义符号 hook 的扩展路线。

计划获得确认前，不开始产品代码开发。计划确认后，若实现过程中需要改变已确认的公开行为、trace 格式、依赖、支持范围或安全策略，必须先更新本文或新增 ADR，并等待人工确认。

## 2. 产品目标与边界

### 2.1 产品目标

Noleax 是一个基于 hook 的命令行内存事件捕获和离线分析工具，读音为 “no leaks”。

它负责：

1. 将 agent 注入目标进程。
2. hook 目标平台的内存分配、重新分配、释放和相关生命周期 API。
3. 记录调用时间、线程、参数、结果和原始调用栈。
4. 将事件写入有明确大小上限、可恢复的 trace 文件。
5. 离线解析 trace、还原分配生命周期并解析符号。
6. 输出完整事件或指定时间窗口内仍未释放的分配。

### 2.2 “泄漏”的准确定义

Noleax V1 报告的是指定时间点仍未释放的 outstanding allocation，不做对象可达性分析。

因此：

- 仍被程序合法缓存的内存可能出现在结果中。
- 在时间点 c 之前已经释放的内存不出现在 outstanding 结果中。
- attach 之前已经存在的分配无法还原，必须标记捕获范围不完整。
- trace 丢失事件时，工具不得把结果描述为完整或确定无泄漏。

### 2.3 V1 范围

V1 为 Windows x64 的完整可用版本，包含：

- Windows 10/11 x64。
- x64 原生控制器、agent 和目标进程。
- 启动目标进程并注入。
- 运行时 attach 并注入。
- 对 PE 文件副本进行静态 patch 注入。
- 远程线程、线程上下文/RIP 劫持、入口点代码等注入策略。
- Windows 原生堆及虚拟内存规范化 API。
- 有界二进制 trace。
- console、JSON 和 CSV 分析输出。
- 离线 PDB/导出符号解析。
- 严格的逐 API、注入、并发、ABI、故障恢复和压力测试。

### 2.4 V1 非目标

以下能力不阻塞 V1：

- Windows x86 和 ARM64。
- Linux 和 macOS agent/injector。
- 用户自定义 alloc/realloc/free 符号。
- 图形界面。
- 内核模式分配跟踪。
- 受保护进程、PPL、反作弊或 DRM 目标。
- 已加壳程序的通用静态 patch。
- 通用 .NET 程序静态 patch。
- 自动判断 outstanding allocation 是否业务上可达。

### 2.5 长期支持矩阵

| 平台 | x86 | x64 | ARM64 | 计划 |
|---|---:|---:|---:|---|
| Windows | 后续 | V1 | 后续 | 先完成 Windows x64，再补齐其他架构 |
| Linux glibc | 后续 | 后续 | 后续 | 在 Windows V1 后实现 |
| Linux musl | 待评估 | 待评估 | 待评估 | 取决于 Hoox 和运行时兼容性 |
| macOS | 不适用 | 后续 | 后续 | 现代 macOS 不支持 32 位 x86 用户程序 |

每个平台开始开发前，必须先完成 Hoox v0.1.1 对该平台和架构的能力审计。若 Hoox v0.1.1 不支持，不擅自升级、替换或私自维护 fork，而是先提交证据和变更建议供人工决策。

## 3. 需求追踪

| ID | 原始需求 | 落地位置 | 主要验收阶段 |
|---|---|---|---|
| R1 | Git 管理、功能提交、复杂功能分支 review 后合并 | 第 5 节 | P1 起持续执行 |
| R2 | C++、CMake、Ninja、vcpkg、多平台多架构 | 第 6、7 节 | P1、P9 |
| R3 | CLI 和配置文件双入口，CLI 优先 | 第 8 节 | P2 |
| R4 | Hoox v0.1.1 | 第 6.3 节 | P0、P1、P4 |
| R5 | _temp 参考目录不进入 Git | 第 5.5 节 | P1 |
| R6 | hook 内存 API、调用栈、控制文件大小 | 第 9、10、11 节 | P4、P5 |
| R7 | 各系统 API 表格 | 第 9 节 | P0 文档门禁 |
| R8 | 解决 RtlAllocateHeap 崩溃，逐 API 严格测试 | 第 12、14 节 | P4、P5 |
| R9 | 两种分析模式、三种输出和过滤 | 第 13 节 | P3 |
| R10 | 启动、attach、patch 及多种注入细节 | 第 15 节 | P6、P7 |
| R11 | 后续自定义符号和参数语法 | 第 16 节 | P9 |

## 4. AI 与人工职责

### 4.1 AI 负责

- 需求整理、架构设计、ADR 和接口文档。
- 创建和维护构建系统、依赖配置与 CI。
- 编写全部产品代码、测试代码、测试目标和辅助脚本。
- 执行单元、集成、压力、故障、静态检查和格式检查。
- 复现及分析 hook 崩溃，收集调用栈、dump 和差分证据。
- 更新使用文档、支持矩阵和已知限制。
- 按功能创建分支及原子 commit。
- 在申请人工 review 前完成自审，并提供变更、测试和风险摘要。
- 对人工验证发现的问题继续诊断、修复、补测试和提交。

### 4.2 人工负责

- 确认产品语义、范围、公开接口和重大技术决策。
- review commit、分支 diff、测试证据和崩溃结论。
- 在真实机器和需要额外权限的环境中执行验证。
- 提供验证失败时的命令、日志、trace 和 dump。
- 批准复杂分支合并、发布和签名。

人工不承担编码、补测试或手工修复构建的职责。

### 4.3 Definition of Ready

一个开发任务开始前应满足：

- 范围、输入、输出和非目标明确。
- 对外行为已经在本文、CLI 规范、trace 规范或 ADR 中定义。
- 依赖项已完成或有可用 mock。
- 验收标准可自动化验证。
- 涉及破坏性文件操作、进程注入或签名破坏时已有安全边界。

### 4.4 Definition of Done

一个功能只有同时满足以下条件才算完成：

- 产品代码和错误处理完成。
- 正常、边界、失败和并发测试完成。
- 不降低已有测试覆盖和稳定性。
- CLI 与配置文件行为一致。
- 文档、示例和已知限制同步更新。
- 格式检查、静态检查、构建和相关测试全部通过。
- AI 已完成自审。
- 已生成一个范围单一、可回退的 commit。
- 若属于复杂功能，人工已批准分支合并。

## 5. Git 与仓库工作流

### 5.1 初始化

P1 才执行以下操作：

1. 初始化 Git，默认分支为 main。
2. 创建根目录 .gitignore。
3. 忽略 _temp、构建输出、vcpkg 本地缓存、trace、符号缓存、dump 和测试临时目录。
4. 创建基础 README、LICENSE 状态说明、贡献和构建文档。
5. 提交首个 bootstrap commit。

当前计划编写阶段不初始化 Git。

### 5.2 提交规则

- 一个 commit 对应一个可独立说明和验证的功能。
- 不把格式化、重构和功能修改混在同一 commit，除非无法合理分离。
- commit 前执行该功能相关的最小完整测试集。
- 阶段结束前执行全量测试。
- 推荐使用 Conventional Commits，例如：
  - chore: bootstrap cmake and vcpkg project
  - feat(trace): add crash-tolerant chunk codec
  - test(hook): add RtlAllocateHeap stress target
  - docs: define analysis time-window semantics
- 不 force push，不重写人工已 review 的 commit。
- 未经明确要求不 push、不创建远端 PR、不发布 release。

### 5.3 分支规则

普通低风险功能可在当前集成分支完成并直接提交。以下功能必须使用独立分支：

- feat/windows-hook-agent
- feat/windows-thread-hijack
- feat/windows-entrypoint-injection
- feat/windows-pe-patch
- feat/custom-symbol-hooks
- feat/linux-port
- feat/macos-port
- feat/windows-arm64

复杂分支流程：

1. AI 创建分支。
2. AI 完成代码、测试、文档和自审。
3. AI 提供 commit 列表、diff 摘要、测试结果、风险及限制。
4. 人工 review 和验证。
5. 人工明确批准后由 AI 合并 main。

### 5.4 阶段检查点

每个阶段结束时输出：

- 已完成任务 ID。
- commit 哈希及摘要。
- 执行过的构建和测试命令。
- 通过、跳过和失败的测试数量。
- 新增或变化的风险。
- 尚未解决的问题。
- 下一阶段建议。

### 5.5 _temp 使用规则

- _temp 整个目录必须被 Git 忽略。
- Frida、Detours 等参考项目仅在确有研究价值时 clone。
- 每个参考项目放入独立子目录。
- 记录参考项目 URL、commit 和研究目的。
- 不直接链接、不复制实现代码、不把其源码加入产品构建。
- 若设计受到参考实现影响，应记录设计结论和许可证审查结果。

## 6. 技术基线与依赖

### 6.1 语言和工具

| 项目 | 基线 |
|---|---|
| 语言 | C++20 |
| 构建系统 | CMake，建议最低版本 3.25 |
| 构建器 | Ninja |
| Windows 编译器 | Visual Studio 2022 MSVC，后续评估 clang-cl |
| 依赖管理 | vcpkg manifest mode |
| 单元测试 | 在 P0 评估 Catch2 或 GoogleTest 后固定 |
| 格式化 | clang-format |
| 静态检查 | clang-tidy，Windows 警告等级提升 |
| CI | 第一阶段 Windows x64 Debug/Release |

依赖选择遵循最小化原则。agent 热路径不得依赖会隐式分配、启动线程或持有全局锁的通用日志和序列化库。

### 6.2 CMake 目标

计划建立以下主要 target：

- noleax-core：平台无关事件、配置、trace、过滤及分析模型。
- noleax：CLI、控制器、注入器、patcher 和 analyzer。
- noleax-agent：注入目标进程的动态库。
- noleax-platform-windows：Windows 平台实现。
- noleax-test-support：测试 fixture 和合成 trace 工具。
- noleax-target-*：各种受控目标进程。

CMake Presets 至少提供：

- windows-x64-debug
- windows-x64-release
- windows-x64-ci

后续按同样命名规则增加其他平台和架构。

### 6.3 Hoox v0.1.1

Hoox 通过 vcpkg overlay port 引入：

- 固定 v0.1.1 对应的 commit。
- 保存源码归档校验值。
- 不使用浮动分支。
- 将 Hoox 封装在单独的 HookBackend 接口后，不让业务层直接依赖其类型。
- 保存许可证和第三方声明。

P0 必须审计：

- tag 与 commit 是否匹配。
- Windows x64 指令重定位能力。
- 对 CFG、CET、ASLR 和现代 Windows 的行为。
- hook 安装、卸载和并发语义。
- trampoline 是否保持 ABI。
- x86、ARM64、Linux、macOS 的实际支持状态。
- 是否需要目标线程暂停以及失败时的回滚方式。

若审计发现阻塞问题，先形成 ADR 和复现项目，由人工决定继续使用、限制范围或调整版本要求。

### 6.4 候选第三方依赖

以下仅为候选，P0 审计后再锁定：

| 用途 | 候选 | 约束 |
|---|---|---|
| CLI | CLI11 | 所有功能选项必须可映射到配置 |
| TOML | toml++ | 仅控制器侧使用 |
| JSON 输出 | nlohmann-json 或流式自研 writer | 大结果必须流式写出 |
| 格式化 | fmt | 不进入 hook 热路径 |
| 压缩 | LZ4 默认、Zstd 可选 | codec 按块记录，只允许后台 writer 使用 |
| 测试 | Catch2 或 GoogleTest | 统一 unit/integration 测试 |

## 7. 目录规划

建议仓库结构：

~~~
noleax/
  CMakeLists.txt
  CMakePresets.json
  vcpkg.json
  vcpkg-configuration.json
  cmake/
  ports/
    hoox/
  apps/
    noleax/
  agent/
  include/
    noleax/
  src/
    core/
    config/
    trace/
    analysis/
    platform/
      windows/
      linux/
      macos/
  tests/
    unit/
    integration/
    stress/
    targets/
    fixtures/
  docs/
    DEVELOPMENT_PLAN.md
    CLI.md
    CONFIG.md
    TRACE_FORMAT.md
    HOOK_API_MATRIX.md
    TEST_STRATEGY.md
    adr/
  _temp/
~~~

平台无关代码不得包含 Windows 头文件。平台差异通过接口隔离：

- HookBackend
- StackCapture
- ModuleTracker
- TraceSink
- Injector
- ProcessController
- Symbolizer
- MonotonicClock

trace 中不得直接写入 size_t、裸指针结构体或编译器相关布局。

## 8. CLI 与配置设计

### 8.1 命令结构

~~~
noleax [global-options] run [run-options] -- target [args...]
noleax [global-options] attach [attach-options]
noleax [global-options] patch [patch-options]
noleax [global-options] analyze [analyze-options] trace...
noleax config validate [config-options]
noleax config print-effective [config-options]
noleax doctor [doctor-options]
~~~

其中 help、version、config 文件路径等元选项不需要再次写入配置文件；所有影响捕获、注入、分析和输出行为的功能性选项必须有配置键。

### 8.2 配置优先级

~~~
内置默认值 < TOML 配置文件 < 命令行
~~~

实现要求：

- CLI parser 不应先把默认值写入结果，否则无法区分“未指定”和“覆盖配置”。
- 布尔项提供正向和反向 CLI 形式。
- CLI 数组默认整体替换配置数组。
- 如需要追加，使用名称明确的 append 选项。
- 未知配置键默认报错，避免拼写错误被忽略。
- 配置包含 schema_version。
- print-effective 输出合并后的完整配置，方便复现。
- 错误信息同时指出配置键和 CLI 参数名。

### 8.3 建议功能选项

| 分类 | CLI 示例 | TOML 键示例 |
|---|---|---|
| 目标程序 | --target、--arg、--working-directory | target.path、target.args、target.working_directory |
| attach | --pid | target.pid |
| 注入方法 | --inject-method | injection.method |
| agent | --agent | injection.agent_path |
| trace 路径 | --trace | trace.path |
| hook profile | --hook-profile | capture.hook_profile |
| 栈深 | --max-stack-depth | capture.max_stack_depth |
| 最小记录大小 | --capture-min-size | capture.min_size |
| trace 上限 | --max-trace-size | trace.max_file_size |
| 文件满策略 | --on-trace-full | trace.on_full |
| 轮转数量 | --max-trace-files | trace.max_files |
| 缓冲区大小 | --buffer-size | trace.buffer_size |
| 输出格式 | --format | analysis.format |
| 输出路径 | --output | analysis.output |
| 分析模式 | --mode | analysis.mode |
| a、b、c | --a、--b、--c | analysis.a、analysis.b、analysis.c |
| 大小过滤 | --min-size、--max-size | filters.min_size、filters.max_size |
| 事件过滤 | --event | filters.events |
| 线程过滤 | --thread | filters.threads |
| API 过滤 | --api | filters.apis |
| 模块过滤 | --module | filters.modules |
| 符号路径 | --symbol-path | symbols.paths |

最终公开参数在 P0 通过 CLI ADR 冻结，新增用户选项时必须同时增加：

1. CLI 参数。
2. TOML 键。
3. 合并测试。
4. help 文本。
5. CLI.md 和 CONFIG.md。

### 8.4 TOML 示例

~~~
schema_version = 1
operation = "run"

[target]
path = "C:/apps/example.exe"
args = ["--mode", "test"]
working_directory = "C:/apps"

[injection]
method = "remote-thread"

[capture]
hook_profile = "windows-native"
max_stack_depth = 64
min_size = "0B"

[trace]
path = "example.nlx"
max_file_size = "256MiB"
on_full = "stop"
max_files = 1
buffer_size = "16MiB"

[analysis]
mode = "outstanding"
format = "json"
output = "result.json"
a = "5s"
b = "20s"
c = "60s"

[filters]
min_size = "1KiB"
max_size = "1MiB"
~~~

### 8.5 退出码规划

| 退出码 | 含义 |
|---:|---|
| 0 | 成功且结果完整 |
| 1 | 参数、配置、输入或一般运行错误 |
| 2 | 成功生成结果，但 trace 存在丢失、截断或 attach 盲区 |
| 3 | 注入或权限失败 |
| 4 | trace 格式不支持或损坏到无法继续 |
| 5 | 目标平台、架构或注入组合不支持 |

## 9. 内存 API 清单与 V1 hook 策略

### 9.1 Windows

| 层级 | 分配 | 重新分配 | 释放/生命周期 | V1 策略 |
|---|---|---|---|---|
| NT Heap | RtlCreateHeap、RtlAllocateHeap | RtlReAllocateHeap | RtlFreeHeap、RtlDestroyHeap | 直接 hook |
| Win32 Heap | HeapCreate、HeapAlloc | HeapReAlloc | HeapFree、HeapDestroy | 默认由 NT Heap 捕获 |
| Legacy Win32 | LocalAlloc、GlobalAlloc | LocalReAlloc、GlobalReAlloc | LocalFree、GlobalFree | 默认由 NT Heap 捕获 |
| UCRT/CRT | malloc、calloc、aligned alloc 系列 | realloc、recalloc、expand、aligned realloc 系列 | free、aligned free 系列 | 默认由 NT Heap 捕获，直接归因后续实现 |
| C++ | operator new、operator new[] 及 aligned/nothrow 变体 | 通常无独立 API | operator delete、operator delete[] 及 sized/aligned 变体 | 默认由底层捕获 |
| COM/OLE | CoTaskMemAlloc、IMalloc::Alloc、SysAllocString 系列 | CoTaskMemRealloc、IMalloc::Realloc、SysReAllocString 系列 | CoTaskMemFree、IMalloc::Free、SysFreeString | 默认由底层捕获 |
| Virtual Memory | VirtualAlloc、VirtualAllocEx、VirtualAlloc2 | 通常通过释放并重新分配实现 | VirtualFree、VirtualFreeEx | 默认由 NT API 捕获 |
| NT Virtual Memory | NtAllocateVirtualMemory、NtMapViewOfSection | 无通用 realloc | NtFreeVirtualMemory、NtUnmapViewOfSection | 直接 hook |
| File Mapping | MapViewOfFile 系列 | 无通用 realloc | UnmapViewOfFile 系列 | 默认由 NT API 捕获 |

V1 默认直接 hook 的规范化集合：

- RtlCreateHeap
- RtlDestroyHeap
- RtlAllocateHeap
- RtlReAllocateHeap
- RtlFreeHeap
- NtAllocateVirtualMemory
- NtFreeVirtualMemory
- NtMapViewOfSection
- NtUnmapViewOfSection

V1 提供以下命名 profile：

| profile | 直接 hook 的 API 组 | 用途 |
|---|---|---|
| windows-nt-heap | RtlCreateHeap、RtlDestroyHeap、RtlAllocateHeap、RtlReAllocateHeap、RtlFreeHeap | 只跟踪 NT Heap；HeapAlloc、CRT malloc 等落到 NT Heap 的调用仍会被捕获 |
| windows-virtual-memory | NtAllocateVirtualMemory、NtFreeVirtualMemory、NtMapViewOfSection、NtUnmapViewOfSection | 只跟踪直接虚拟内存和映射操作 |
| windows-native | windows-nt-heap 与 windows-virtual-memory 的并集 | Windows V1 默认 profile |

例如，只启用 NT Heap：

~~~powershell
noleax run --hook-profile windows-nt-heap --trace app.nlx -- app.exe
~~~

理由：

- 捕获主要公共包装 API 的最终行为。
- 避免同一次调用同时出现在 CRT、HeapAlloc 和 RtlAllocateHeap 三层。
- 降低 hook 数量和递归复杂度。
- 保留 API 归因模式的扩展空间。

对其他进程地址空间执行的 VirtualAllocEx/NtAllocateVirtualMemory 不应混入当前目标进程的分配状态，事件模型需要记录目标进程句柄并区分 remote allocation。

### 9.2 Linux

| 层级 | 分配 | 重新分配 | 释放/生命周期 |
|---|---|---|---|
| libc heap | malloc、calloc、aligned_alloc、posix_memalign、memalign、valloc、pvalloc | realloc、reallocarray | free，以及运行库提供时的 sized free |
| C++ | operator new、operator new[] 及变体 | 通常无独立 API | operator delete、operator delete[] 及变体 |
| Virtual Memory | mmap、mmap64、brk、sbrk | mremap | munmap |
| 动态分配器 | jemalloc、tcmalloc、mimalloc 等导出符号 | 分配器自有 API | 分配器自有 API |

Linux 需要分别评估 LD_PRELOAD、ptrace/dlopen 和 ELF patch；glibc 与 musl 分开验收。

### 9.3 macOS

| 层级 | 分配 | 重新分配 | 释放/生命周期 |
|---|---|---|---|
| libc heap | malloc、calloc、aligned_alloc、posix_memalign、valloc | realloc、reallocf | free |
| malloc zone | malloc_zone_malloc/calloc/memalign/valloc、malloc_zone_batch_malloc | malloc_zone_realloc | malloc_zone_free、malloc_zone_batch_free、malloc_destroy_zone |
| C++ | operator new、operator new[] 及变体 | 通常无独立 API | operator delete、operator delete[] 及变体 |
| POSIX VM | mmap | 通过重新映射实现 | munmap |
| Mach VM | vm_allocate、mach_vm_allocate、mach_vm_map | vm_remap、mach_vm_remap | vm_deallocate、mach_vm_deallocate |

macOS 注入和 patch 受 SIP、Hardened Runtime、Library Validation 和代码签名影响，必须在平台阶段明确支持边界。

### 9.4 新增 hook API 的门禁

任何 API 进入默认或可选 hook profile 前必须：

1. 在 HOOK_API_MATRIX.md 注册签名、模块、操作语义和平台版本。
2. 实现独立 adapter，不在通用回调中硬编码参数。
3. 增加成功、失败、边界、并发和递归测试。
4. 验证 ABI、返回值和错误状态不变。
5. 验证与其他 hook 组合时不重复记账。
6. 通过安装、运行、卸载和进程退出压力测试。
7. 在 Debug 和 Release 下通过。

CI 必须检查 hook 注册表和测试注册表一一对应。

## 10. Agent 设计

### 10.1 初始化阶段

1. DllMain 只保存模块句柄、关闭不必要的线程通知并返回。
2. 注入器在 loader lock 外调用导出的 noleax_agent_initialize。
3. 验证配置版本、目标架构、共享内存和控制通道。
4. 在安装 hook 前预分配事件缓冲区、TLS/线程状态和 writer 资源。
5. 启动 writer/control 线程，并将其标记为 agent internal。
6. 安装 hook。
7. 发送 ready 握手后才允许控制器恢复目标主线程。

初始化任一步失败都必须完整回滚，不允许留下半安装 hook。

### 10.2 hook 回调约束

hook 回调必须：

- 不使用被 hook 的 heap。
- 不调用 DbgHelp。
- 不执行文件 I/O。
- 不使用通用日志库。
- 不等待可能由目标线程持有的锁。
- 不加载模块。
- 不安装或卸载其他 hook。
- 不抛出异常穿过 ABI 边界。
- 保存并恢复 LastError 和必要的状态。
- 调用原函数恰好一次。
- 对重复进入使用 recursion guard。

建议流程：

1. 保存错误状态和线程状态。
2. 判断是否为内部线程或递归调用。
3. 捕获必要的入参和原始栈。
4. 调用 trampoline。
5. 根据 API 语义捕获返回值和输出参数。
6. 获取单调序号并把定长事件写入预分配队列。
7. 恢复错误状态并返回。

### 10.3 递归和重复事件

- 每线程维护 hook depth。
- agent 自身线程永久标记为 excluded。
- 默认只记录最外层规范化事件。
- RtlAllocateHeap 内部触发 NtAllocateVirtualMemory 时，由递归保护抑制内部 VM 事件。
- 直接由应用调用 NtAllocateVirtualMemory 时正常记录。
- 后续 API 归因模式仍需保证同一逻辑分配只有一个 allocation generation。

### 10.4 栈捕获

- 目标进程中只捕获原始指令地址。
- 不在 hook 回调中解析 PDB、访问符号服务器或生成字符串。
- Windows x64 的栈遍历方式须单独对比 RtlCaptureStackBackTrace 与基于 unwind metadata 的实现。
- 若系统 API 自身可能分配或获取危险锁，必须以压力测试结果选择实现。
- 每个栈记录 capture status，失败不能伪装为空栈。
- 配置最大栈深，默认 64。
- 过滤 agent 自身 hook frame，但保留足够原始帧用于诊断。

### 10.5 模块跟踪

- 记录进程启动时已有模块。
- 使用安全的模块加载通知获取后续加载和卸载事件。
- loader 通知中只采集最小数据或入队，不解析符号。
- 记录模块基址、大小、路径、时间范围、PE 标识和 PDB 标识。
- 即使模块在分析前已卸载，历史地址仍可映射到正确模块代次。

### 10.6 停止和卸载

1. 控制器请求停止接收新事件。
2. 禁用新 hook 入口。
3. 等待 in-flight callback 归零，设置超时。
4. 卸载 hook。
5. writer 排空完整事件块。
6. 写入结束、统计和完整性记录。
7. 关闭 IPC。
8. 仅在确认没有线程执行 agent 代码后卸载 DLL。

超时不得强行卸载正在执行的 agent。

## 11. Trace 格式计划

### 11.1 文件目标

trace 格式必须：

- 跨平台、跨架构可读。
- 版本化并支持向后兼容。
- 支持流式写入和分析。
- 在目标进程崩溃或文件截断后恢复完整块。
- 明确记录事件丢失和捕获范围。
- 不依赖进程内指针或编译器结构体布局。

详细二进制布局在 P0/P2 写入 TRACE_FORMAT.md，并由 golden fixtures 锁定。

### 11.2 建议记录类型

| 记录 | 内容 |
|---|---|
| FileHeader | magic、版本、平台、架构、指针宽度、时钟信息 |
| ProcessInfo | pid、映像路径、命令行、启动和注入时间 |
| CaptureConfig | 影响 trace 解释的有效配置 |
| ModuleLoad | module id、基址、大小、路径、符号标识 |
| ModuleUnload | module id、卸载时间 |
| StackDefinition | stack id、原始地址数组、capture status |
| HeapCreate | heap id/handle、API、栈 |
| HeapDestroy | heap id/handle、结果、栈 |
| Allocate | allocation id、heap/space、大小、结果地址、栈 |
| Reallocate | 旧 allocation id、新 allocation id、旧/新地址、大小、结果、栈 |
| Free | allocation id 或地址、结果、栈 |
| Map | address、size、mapping id、结果、栈 |
| Unmap | mapping id 或地址、size、结果、栈 |
| Loss | 丢失数量、序号范围、原因 |
| Statistics | 捕获、过滤、丢失和写入统计 |
| EndOfTrace | 正常结束标志及最终时间 |

### 11.3 调用栈去重

- hook 回调会为每个事件捕获原始栈地址，并把定长帧数组临时放入预分配队列。
- hook 回调不访问共享哈希表，也不为栈去重分配内存。
- 后台 writer 对完整帧序列进行哈希并做逐帧比较，哈希冲突不能误合并。
- 新栈写入一次 StackDefinition；alloc、realloc、free 等事件在最终 trace 中只保存 stack_id。
- 相同帧序列可以跨事件类型共享 stack_id。
- 栈键需要包含模块 generation 或等价上下文，避免模块卸载后在相同地址重新加载造成错误合并。
- 栈字典有独立内存上限；达到上限后开启新的字典 segment，而不是无界增长或在 hook 线程阻塞。

### 11.4 顺序和时间

- 每个事件分配全局单调 sequence number。
- 使用单调高精度时钟作为分析依据。
- 同时记录 UTC 起点用于展示，不使用墙上时钟排序。
- 同一线程严格保持程序观察顺序。
- 多线程事件以全局序号确定 trace 顺序。
- 文件块可以批量写入，但不得改变事件序号。

### 11.5 分块与恢复

每个块包含：

- block type。
- header version。
- payload length。
- sequence range。
- checksum。

分析器读取到不完整或校验失败的尾块时：

1. 保留之前所有完整块。
2. 将结果标记为 truncated。
3. console 显示醒目警告。
4. JSON 输出完整性字段。
5. 返回退出码 2；若文件头或所有块均不可用，则返回 4。

### 11.6 文件大小控制

建议默认值：

| 选项 | 默认值 |
|---|---:|
| max_file_size | 256 MiB |
| max_files | 1 |
| on_full | stop |
| buffer_size | 16 MiB |
| max_stack_depth | 64 |
| flush_interval | 250 ms |
| compression | lz4 |

策略：

- stop：到达上限后停止记录新事件，写入可用的 Loss/Statistics，并保持 agent 稳定。
- rotate：关闭当前分片后写入下一分片，达到 max_files 后停止或删除最旧文件，具体行为必须显式配置。
- 不在 V1 默认实现环形覆盖，因为覆盖早期 alloc 会破坏生命周期分析。
- 每个数据块显式记录 none、lz4 或 zstd codec，reader 不依赖全局固定算法。
- LZ4 作为默认值以降低目标进程 CPU 和延迟影响；Zstd level 1 作为更高压缩率选项。
- 压缩只能发生在后台 writer，hook 回调永远不压缩。
- 文件大小上限包含文件头和块开销，不允许无界超出。
- 内存队列满时不阻塞 hook 线程，而是计数并生成 Loss 记录。
- 任何 loss 都使 outstanding 分析结果变为 incomplete。

## 12. RtlAllocateHeap 稳定性专项

### 12.1 主要风险

- hook 回调或栈捕获再次分配，造成递归或死锁。
- 在 loader lock 内初始化。
- trampoline 指令重定位错误。
- x64 ABI、栈对齐或非易失寄存器损坏。
- LastError 被 agent 修改。
- writer 或符号组件调用被 hook API。
- 安装/卸载时其他线程正在执行目标函数。
- CFG、CET、ASLR 或系统更新改变入口代码。
- 同时 hook Rtl Heap 和 NT Virtual Memory 产生嵌套事件。

### 12.2 专项实施顺序

1. 建立不使用 Noleax agent 的基线压力目标。
2. 仅安装 RtlAllocateHeap hook，回调只调用原函数。
3. 验证返回值、LastError、寄存器和压力稳定性。
4. 加入 recursion guard。
5. 加入定长事件队列，不捕获栈。
6. 加入原始栈捕获。
7. 加入 writer 和文件上限。
8. 增加 RtlFreeHeap。
9. 增加 RtlReAllocateHeap。
10. 增加 heap create/destroy 和 NT VM API。
11. 增加安装、卸载和进程退出场景。

每一步单独运行差分和压力测试；发生崩溃时暂停增加功能，先保存最小复现和 dump。

### 12.3 通过标准

- Debug/Release 均通过。
- 单线程和多线程行为与未 hook 基线一致。
- 返回值、输出参数、LastError 和异常行为一致。
- Application Verifier/Page Heap 下无新增错误。
- CFG/CET 可用环境下通过。
- 压力测试无 hook 引入的 crash、hang 或 heap corruption。
- 故障注入时最多丢失事件，不能影响目标进程正确性。

## 13. 分析器设计

### 13.1 events 模式

输出所有符合过滤条件的：

- heap create/destroy。
- alloc/calloc。
- realloc。
- free。
- map/unmap。
- 成功和失败调用。
- loss、截断和完整性警告。

每条事件至少包含：

- sequence。
- 相对时间和可选 UTC 时间。
- pid/tid。
- API 和操作类型。
- 输入参数摘要。
- 结果、错误状态和成功标记。
- allocation id 或 mapping id。
- 原始地址、模块偏移和可用符号。
- 调用栈状态。

### 13.2 outstanding 模式

输入：

- a：候选窗口起点，必填。
- b：候选窗口终点，必填。
- c：观察点，可选。

建议固定语义：

- 候选窗口为 a 小于等于事件时间且事件时间小于 b。
- c 未提供时取 trace 结束时间。
- c 大于 trace 结束时间时 clamp 到结束时间。
- 要求 a 小于等于 b 且 b 小于等于 c。
- 状态 c 包含时间等于 c 的全部已排序事件。
- 只把成功 alloc 或成功 realloc 产生的新 generation 作为候选。
- generation 在 c 前 free、被成功 realloc 替换、所属 heap 成功销毁或 mapping 被成功 unmap，则不再存活。

realloc 规则：

- realloc(null, n) 等价于新 alloc。
- realloc 失败时旧 generation 保持存活。
- realloc 成功时旧 generation 结束，创建新 generation。
- 地址不变也创建新 generation。
- size 为零的行为由具体 API adapter 定义，测试必须覆盖。

异常规则：

- 未匹配 free 被保留为 unmatched event，不凭空创建 allocation。
- 重复 free 不修改已结束 generation。
- trace 存在 Loss 时继续输出可确定结果，但标记 incomplete。
- attach 前的未知分配被 free 时记录为 preexisting/unknown。

### 13.3 过滤器

V1 至少支持：

- 大小最小值和最大值。
- 分配时间区间。
- 事件类型。
- 成功或失败。
- 线程 ID。
- API 名称。
- heap/space。
- 模块。
- 调用栈包含模块。
- allocation id。

过滤顺序必须明确：

- events 模式直接过滤事件。
- outstanding 模式先完整还原状态，再对最终候选结果过滤，不能先删掉 free 事件。

### 13.4 输出格式

console：

- 面向人工阅读。
- 摘要、完整性警告、事件表和多行调用栈。
- 支持是否使用颜色；重定向时默认关闭颜色。

JSON：

- 使用版本化 schema。
- 大结果流式写出，不把全部结果驻留内存。
- 包含 metadata、completeness、filters、summary 和 events/allocations。
- 地址默认输出十六进制字符串，避免 JSON 数字精度问题。

CSV：

- 一条事件或 allocation 一行。
- 调用栈作为转义后的单字段，或通过明确选项输出独立 frames CSV。
- 固定 UTF-8。
- 字段顺序和 schema version 写入文档。

### 13.5 符号解析

- Windows 使用 DbgHelp，但只在 analyzer 进程中使用。
- 单线程串行访问 DbgHelp 或通过受控服务封装其线程安全问题。
- 支持本地 PDB、用户 symbol path 和显式允许的 symbol server。
- 默认不隐式联网下载符号。
- 符号不可用时输出 module+offset 和原始地址。
- 模块文件变化或 PDB 不匹配时给出状态，不使用错误符号。

## 14. 测试策略

### 14.1 测试层级

| 层级 | 内容 | 运行频率 |
|---|---|---|
| Unit | 配置、codec、状态机、过滤、格式化、adapter | 每个相关 commit |
| Component | ring buffer、writer、symbolizer、PE parser | 每个相关 commit |
| Hook contract | 单个 API 的行为和 ABI | 每个 hook 变更 |
| Integration | agent、控制器、IPC、trace、analyze | 每个阶段 |
| Injection | run、attach、hijack、entrypoint、patch | 注入变更及阶段结束 |
| Stress | 多线程、长时间、高事件率 | 阶段结束和定期 CI |
| Fault | 文件满、磁盘失败、损坏 trace、目标 crash | P3 以后 |
| Fuzz | trace decoder、配置、未来 DSL | 定期 CI |
| Performance | 延迟、吞吐、内存、文件大小 | P4 以后 |

### 14.2 每个 hook API 的测试模板

每个 API 至少需要：

1. 正常成功调用。
2. null、零值和边界参数。
3. 可控制的失败路径。
4. 返回值和输出参数与基线一致。
5. LastError 或对应错误状态一致。
6. 调用栈存在且不包含损坏地址。
7. 单线程循环压力。
8. 多线程并发压力。
9. recursion guard 生效。
10. 与其他 hook 同时启用。
11. hook 安装和卸载循环。
12. 目标进程正常退出和异常退出。

### 14.3 Windows 专项矩阵

- Windows 10 和 Windows 11。
- Debug 和 Release。
- MSVC 动态和静态 CRT 测试目标。
- 默认 heap 和显式创建 heap。
- Low Fragmentation Heap/Segment Heap 可用组合。
- Page Heap 和 Application Verifier。
- CFG 开启目标。
- CET/硬件强制栈保护可用目标。
- ASLR 和 DEP。
- 单模块、DLL 动态加载/卸载。
- 高线程数、高频 alloc/free/realloc。
- 目标主动 crash 时 trace 恢复。
- attach 后立即退出。
- 停止记录时仍有 in-flight callback。

### 14.4 分析器测试

- 每种事件的 golden trace。
- 指针地址重复使用。
- realloc 原地、迁移、失败和零大小。
- heap destroy 批量结束 allocation。
- a/b/c 边界。
- c 缺省及超出结束时间。
- 在 b 或 c 同一时间戳的多个事件。
- Loss 和截断。
- attach 盲区。
- JSON schema 验证。
- CSV 转义、Unicode 和调用栈。
- 大文件流式内存占用。
- 老版本 trace 向后兼容。

### 14.5 性能指标

P4 先建立基线再确定硬阈值，至少持续报告：

- 每秒可记录事件数。
- 单次 hook 的 p50/p95/p99 增量延迟。
- agent 固定内存和峰值内存。
- writer CPU。
- 每百万事件的 trace 大小。
- 不同栈深的成本。
- 缓冲区满时目标进程行为。

正确性和目标稳定性优先于不报告的静默丢失。无法记录时应快速 drop 并计数，而不是无限阻塞目标线程。

## 15. 注入设计

### 15.1 命令与方法兼容性

| 操作 | remote-thread | thread-hijack | entrypoint-code | static-pe-patch |
|---|---:|---:|---:|---:|
| run | 支持 | 支持 | 支持 | 不适用 |
| attach | 支持 | 支持 | 不适用 | 不适用 |
| patch | 不适用 | 不适用 | 不适用 | 支持 |

不支持的组合必须在执行前报错，不能静默切换方法。

### 15.2 启动注入

推荐顺序：

1. 创建 suspended 目标进程。
2. 检查目标架构和权限。
3. 创建 IPC、共享配置和随机会话标识。
4. 按选定策略加载 agent。
5. 在 loader lock 外调用 agent initialize。
6. 等待 agent ready。
7. 恢复目标主线程。
8. 监控目标和 agent 状态。
9. 目标结束后关闭 trace 并返回目标退出码或明确的 noleax 错误码。

### 15.3 运行时 attach

- 检查 PID、架构、权限和目标是否正在退出。
- 只捕获 ready 时刻之后的事件。
- trace 中记录 attach 时间和 preexisting allocations unknown。
- 支持记录后保持 agent 或安全卸载；默认策略在 CLI ADR 中确定。
- 不支持目标时明确原因，如跨架构、PPL 或权限不足。

### 15.4 remote-thread

- 使用远程内存、受控 bootstrap 和远程线程加载 agent。
- 不仅调用 LoadLibrary，还要保证初始化发生在 loader lock 外并可传递完整配置。
- 每一步检查返回值并回收临时远程内存。
- 目标提前退出时取消等待并清理控制器资源。

### 15.5 thread-hijack

- 选择可安全暂停的目标线程。
- 保存完整线程上下文。
- 写入架构匹配的 bootstrap。
- 修改 RIP 前确认线程不在危险的 loader/系统关键路径。
- bootstrap 完成后恢复原上下文和执行位置。
- 处理异常、超时和目标线程退出。
- 该功能使用独立分支和专门 ABI/寄存器测试。

### 15.6 entrypoint-code

- 仅用于 suspended launch。
- 保存入口点原始字节。
- 写入临时跳转或 bootstrap。
- agent ready 后恢复原字节并刷新指令缓存。
- 验证补丁边界、指令长度、页面保护和 CFG/CET。
- 任一步失败都不允许用损坏的入口点恢复目标。

### 15.7 static PE patch

V1 建议边界：

- 默认只处理原生 x64 EXE。
- 只生成新的输出文件，不原地覆盖输入。
- 新增独立 section 和 bootstrap，最终跳回原入口点。
- 保留原始入口点、校验输入架构和 PE 边界。
- 默认拒绝 Authenticode 签名文件；只有显式 allow-break-signature 才继续。
- 对 packed、managed、驱动、EFI 或结构异常 PE 明确拒绝。
- 写入临时输出并完成重新解析验证后再替换最终输出。
- 提供 verify 子流程检查 patch 结果。

patch 会改变文件哈希并通常破坏签名，文档和 CLI 必须明确提示。

### 15.8 IPC 和安全

- 每次运行生成不可预测的 session id。
- IPC 限制为当前用户和目标会话。
- 控制消息包含协议版本和长度校验。
- 不信任目标进程发回的字符串和长度。
- 所有超时可配置且有上限。
- agent 路径使用绝对规范化路径。
- 控制器不得从不可信 trace 执行代码或加载其中指定的 DLL。

## 16. 后续自定义符号 hook

### 16.1 语法目标

- 简单、可读、可从 CLI 使用。
- 配置文件有等价的结构化表示。
- 不允许任意代码执行。
- 支持不同 ABI 和参数位置。
- 能表示 alloc、realloc 和 free。
- 后续可扩展 calloc、out parameter 和成功条件。

建议 CLI 语法：

~~~
foo.dll!xalloc{op=alloc,size=arg0,result=ret}
foo.dll!xrealloc{op=realloc,ptr=arg0,size=arg1,result=ret}
foo.dll!xfree{op=free,ptr=arg0}
~~~

建议 TOML：

~~~
[[custom_hooks]]
symbol = "foo.dll!xalloc"
operation = "alloc"
size = "arg0"
result = "ret"
abi = "auto"

[[custom_hooks]]
symbol = "foo.dll!xrealloc"
operation = "realloc"
pointer = "arg0"
size = "arg1"
result = "ret"
abi = "auto"

[[custom_hooks]]
symbol = "foo.dll!xfree"
operation = "free"
pointer = "arg0"
abi = "auto"
~~~

参数编号从 arg0 开始。预留 ABI：

- auto
- win64
- sysv64
- cdecl
- stdcall
- thiscall
- aapcs64

表达式第一版只允许：

- argN
- ret
- 常量
- 经过溢出检查的加、减、乘
- 后续经安全审计后增加受限解引用

### 16.2 V1 需要预留的结构

虽然 V1 不实现自定义 hook，但必须预留：

- 通用 operation kind。
- API adapter 接口。
- 参数和结果抽取上下文。
- api id 与用户定义元数据。
- 模块延迟加载后的 hook 注册。
- ABI 与架构分离。
- trace 中未知/自定义 API 的稳定编码。

## 17. 分阶段工作分解

### P0：规格冻结与可行性审计

目标：在写产品代码前冻结关键语义并确认 Hoox 可用边界。

| ID | AI 任务 | 交付物 | 验收 |
|---|---|---|---|
| P0.1 | 整理公开范围和术语 | 更新 DEVELOPMENT_PLAN.md | 人工确认 |
| P0.2 | 审计 Hoox v0.1.1 tag、许可证、平台和架构能力 | HOOK_BACKEND_AUDIT.md | 无未解释阻塞项 |
| P0.3 | 冻结 CLI、配置和优先级 | CLI.md、CONFIG.md、ADR | 人工确认公开命名 |
| P0.4 | 冻结事件和 trace 语义 | TRACE_FORMAT.md、ADR | 可写 golden fixture |
| P0.5 | 冻结 Windows 直接 hook 集合 | HOOK_API_MATRIX.md | 每个 API 有测试计划 |
| P0.6 | 确认许可证、最低 Windows 版本和默认值 | ADR | 人工明确决定 |

阶段门禁：

- 所有“待确认决策”都有结论。
- Hoox v0.1.1 不存在尚未评估的 V1 阻塞项。
- 不开始 hook 实现，直到 P0 review 通过。

### P1：仓库与构建基础

目标：建立可复现、无产品功能的工程骨架。

| ID | AI 任务 | 交付物 | 自动验收 |
|---|---|---|---|
| P1.1 | 初始化 Git/main 和 .gitignore | 初始 repo | _temp 未被跟踪 |
| P1.2 | 创建 CMake targets 和 presets | CMake 工程 | Debug/Release 配置成功 |
| P1.3 | 创建 vcpkg manifest 和 Hoox overlay port | 锁定依赖 | clean install 成功 |
| P1.4 | 建立测试框架 | 空测试和 test support | ctest 成功 |
| P1.5 | 建立格式和静态检查 | 配置文件 | CI 可执行 |
| P1.6 | 创建 Windows CI | workflow | Debug/Release 通过 |
| P1.7 | 编写本机构建说明 | BUILDING.md | 人工按文档构建 |

建议提交：

- chore: initialize repository and ignore generated files
- build: add cmake ninja and vcpkg foundation
- ci: add windows x64 build and test workflow

### P2：配置、事件模型与 trace core

目标：在无注入条件下完成所有可移植基础。

| ID | AI 任务 | 交付物 | 自动验收 |
|---|---|---|---|
| P2.1 | CLI/config schema 和合并器 | config library | 每个选项 precedence 测试 |
| P2.2 | 大小、时间和枚举解析 | value parsers | 边界与错误测试 |
| P2.3 | 平台无关事件模型 | event types | realloc 生命周期测试 |
| P2.4 | 分块 trace writer | codec writer | golden bytes |
| P2.5 | 流式 trace reader | codec reader | 截断恢复测试 |
| P2.6 | Loss、统计和完整性模型 | completeness API | 故障 fixture |
| P2.7 | 合成 trace 生成器 | test utility | 可生成所有事件组合 |

阶段门禁：

- 不需要 agent 即可生成、读取和检查 trace。
- 相同输入产生稳定、版本化的 golden fixture。
- decoder 对不可信长度和损坏输入有上限检查。

状态：已通过。测试工具可按固定顺序生成 metadata、全部九种内存事件、Loss、Statistics 和
EndOfTrace，支持 none、LZ4、Zstd，并由正式 reader 与 record codec 反向校验。相同输入产生
逐字节一致的 trace；非法时序、统计不一致、结束边界不足和文件上限均有自动测试。

### P3：离线分析器

目标：先用合成 trace 验证最终用户语义。

| ID | AI 任务 | 交付物 | 自动验收 |
|---|---|---|---|
| P3.1 | events 模式 | analyzer | 完整事件 golden test |
| P3.2 | allocation generation 状态机 | state engine | pointer reuse/realloc 测试 |
| P3.3 | a/b/c outstanding 模式 | window analyzer | 时间边界矩阵 |
| P3.4 | 过滤器 | filter engine | 状态还原顺序测试 |
| P3.5 | console 输出 | formatter | snapshot test |
| P3.6 | 流式 JSON 输出 | JSON writer/schema | schema validation |
| P3.7 | CSV 输出 | CSV writer | quoting/Unicode 测试 |
| P3.8 | Windows 离线 symbolizer | symbol service | PDB 缺失/匹配测试 |

状态：P3.1-P3.5 已通过。events 过滤和 console 输出保持流式处理；outstanding 过滤在完整状态
还原和 c 时刻存活判定后执行。过滤器覆盖大小、operation、线程、API、API 模块、栈模块、
allocation ID 和 status，并通过可注入元数据 resolver 与后续 ApiDefinition/Module/Stack codec
解耦。console snapshot 固定了全部 payload、Loss、完整性 warning、符号回退和颜色关闭时的
纯文本布局。

人工验证：

- 使用小型合成 trace review console、JSON、CSV。
- 确认 a/b/c 结果符合业务预期。

### P4：Windows Rtl hook 安全原型

目标：只解决最核心的 RtlAllocateHeap 安全问题，不扩张 API 范围。

分支：feat/windows-hook-agent

| ID | AI 任务 | 交付物 | 自动验收 |
|---|---|---|---|
| P4.1 | 建立未 hook 的基线目标 | stress targets | 稳定基线 |
| P4.2 | 封装 Hoox HookBackend | adapter | install/uninstall 测试 |
| P4.3 | 空 RtlAllocateHeap trampoline | minimal hook | ABI 差分通过 |
| P4.4 | recursion/internal-thread guard | guard | 递归测试 |
| P4.5 | 预分配 MPSC 队列 | event queue | 并发/溢出测试 |
| P4.6 | 原始栈捕获 | stack capture | unwind 压力测试 |
| P4.7 | 后台 writer | agent trace path | 文件上限测试 |
| P4.8 | 退出和卸载 quiescence | lifecycle | race 测试 |
| P4.9 | Page Heap/Verifier/CFG/CET 压力 | test report | 零 hook 引入 crash |

阶段门禁：

- 人工 review 分支、dump 分析和压力测试报告。
- 未获得确认不合并 main、不继续扩大 hook 集合。

### P5：Windows agent 完整 API 覆盖

目标：按规范化 API 清单逐个增加且逐个验收。

推荐顺序：

1. RtlFreeHeap。
2. RtlReAllocateHeap。
3. RtlCreateHeap/RtlDestroyHeap。
4. NtAllocateVirtualMemory/NtFreeVirtualMemory。
5. NtMapViewOfSection/NtUnmapViewOfSection。
6. 模块加载/卸载跟踪。
7. profile、过滤和统计。

每增加一个 API：

- 新增 adapter。
- 新增 hook registry 项。
- 新增 contract test。
- 新增组合和压力测试。
- 更新 HOOK_API_MATRIX.md。
- 单独 commit。

阶段门禁：

- hook registry 与测试 registry 一一对应。
- 所有 API 在完整组合下无重复生命周期记账。
- agent 生成的 trace 可由 P3 analyzer 正确处理。

### P6：控制器、启动和 attach

目标：完成首个端到端用户工作流。

| ID | AI 任务 | 交付物 | 自动验收 |
|---|---|---|---|
| P6.1 | controller/agent IPC | protocol | 版本、超时和恶意长度测试 |
| P6.2 | suspended launch | run command | 主线程 ready 后恢复 |
| P6.3 | remote-thread bootstrap | injector | 错误回滚和资源清理 |
| P6.4 | runtime attach | attach command | attach 盲区标记 |
| P6.5 | start/stop/status 生命周期 | controller | in-flight callback 测试 |
| P6.6 | 架构和权限诊断 | doctor | 明确错误信息 |
| P6.7 | 端到端 trace/analyze | integration suite | 预期 outstanding 结果 |

人工验证：

- 启动一个测试程序并生成 trace。
- attach 到长时间运行测试程序。
- 用三种输出格式验证结果。

### P7：高级注入与 PE patch

每种方式单独分支、单独 review：

#### P7A：thread hijack

- 保存及恢复完整 x64 context。
- 远程 bootstrap。
- 线程选择和危险状态规避。
- 异常、超时和目标退出回滚。
- ABI、XMM、栈和 RIP 恢复测试。

#### P7B：entrypoint code injection

- suspended launch 下的临时入口补丁。
- 原始字节恢复和指令缓存刷新。
- 页面权限、指令边界、CFG/CET 测试。
- 失败时保持目标文件和内存入口一致。

#### P7C：static PE patch

- 安全 PE parser/writer。
- 新 section 和 bootstrap。
- 输出副本及原入口跳转。
- 签名、managed、packed 和架构检查。
- patch 后重新解析和启动测试。

阶段门禁：

- 每个分支分别由人工确认后合并。
- CLI 对不支持组合有确定行为。
- patch 测试只操作专用测试副本。

### P8：V1 硬化与发布候选

| ID | AI 任务 | 交付物 | 验收 |
|---|---|---|---|
| P8.1 | 全量稳定性和长时间 soak | report | 无 crash/hang/corruption |
| P8.2 | 性能基线和默认值调整 | benchmark report | 人工接受开销 |
| P8.3 | 故障恢复和 trace 兼容 | recovery suite | 完整性状态准确 |
| P8.4 | 安全和输入边界 review | audit report | 无高风险未处理项 |
| P8.5 | 用户文档和示例 | docs | 可独立按文档操作 |
| P8.6 | 第三方声明和打包 | release archive | clean machine 可运行 |
| P8.7 | Release Candidate | tag candidate | 人工最终验收 |

未经人工明确批准，不创建正式 release tag、不发布二进制。

### P9：后续路线

建议顺序：

1. 自定义符号 hook DSL。
2. Windows ARM64。
3. Windows x86。
4. Linux x64。
5. Linux ARM64。
6. Linux x86。
7. macOS ARM64。
8. macOS x64。

实际顺序根据 Hoox 审计、用户需求和测试环境调整，每个平台作为独立项目阶段重新完成：

- API 清单。
- ABI adapter。
- 栈捕获。
- 注入方式。
- 符号解析。
- hook 合同测试。
- 签名、权限和安全限制。

## 18. 风险登记

| 风险 | 影响 | 处理策略 |
|---|---|---|
| Rtl hook 递归或死锁 | 目标 crash/hang | 无分配热路径、递归保护、P4 独立门禁 |
| trampoline/ABI 错误 | 随机崩溃或数据损坏 | 差分、寄存器、CFG/CET 和压力测试 |
| 多层 API 重复记录 | 错误泄漏结果 | 规范化底层 hook、generation、组合测试 |
| trace 丢失事件 | 假阳性/假阴性 | Loss 记录、退出码 2、禁止静默完整结论 |
| 文件无限增长 | 磁盘耗尽 | 强制上限、stop/rotate 策略 |
| attach 前状态未知 | 结果不完整 | preexisting 标记和完整性元数据 |
| 符号不可用或不匹配 | 栈可读性下降 | 原始地址永久保留、module+offset fallback |
| PE patch 破坏签名 | 文件不可运行/信任丢失 | 只写副本、默认拒绝签名文件 |
| 注入受权限限制 | 功能不可用 | doctor、明确错误、不绕过系统保护 |
| Hoox v0.1.1 能力不足 | 平台计划阻塞 | P0 审计、证据化后人工决策 |
| x86/x64/ARM64 ABI 差异 | 跨架构错误 | 平台接口、独立 agent、ABI 专项测试 |
| macOS SIP/签名限制 | 无法通用注入 | 明确支持矩阵和签名工作流 |
| 分析超大 trace 内存过高 | analyzer OOM | 流式 reader/writer、受限索引 |
| agent 自身被记录 | 噪声或递归 | internal thread 和 recursion exclusion |

## 19. 待确认决策

开始 P0/P1 前需要确认以下默认方案：

1. V1 仅支持 Windows 10/11 x64 原生目标。
2. 默认直接 hook 规范化底层 API，不直接 hook 所有包装层。
3. 默认 trace 上限为 256 MiB，满后 stop 并标记不完整。
4. a/b 候选窗口使用半开区间，c 取该时间点全部事件处理后的状态。
5. static PE patch 仅处理输出副本和原生 x64 EXE。
6. 签名 PE 默认拒绝 patch，显式允许后才破坏签名。
7. macOS 不规划 32 位 x86。
8. Hoox v0.1.1 若无法满足 V1，先暂停并提交审计结论，不自动换库或升级。
9. 仓库许可证待人工指定；在明确前不对外发布。
10. 复杂功能分支必须人工确认后合并，普通小功能测试通过后 AI 可直接提交。

## 20. 计划确认后的第一批动作

人工确认本文后，AI 按以下顺序开始：

1. 将本文状态改为“已确认”，记录确认日期。
2. 执行 P0 的 Hoox、许可证、CLI、trace 和 API 审计。
3. 将仍需人工决定的结果集中提交 review。
4. P0 通过后初始化 Git/main。
5. 创建 .gitignore，首先确保 _temp 不进入 Git。
6. 执行 P1 工程 bootstrap。
7. 每完成一个可验收功能立即测试和提交。

确认方式可以是：

- “按 DEVELOPMENT_PLAN.md 的推荐方案开始”；或
- 指出需要调整的章节和决策编号，AI 先更新计划，不进入开发。
