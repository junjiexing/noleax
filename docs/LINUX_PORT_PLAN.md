# Linux 版开发计划

> 范围：Linux x86_64 / glibc 端口的总体设计与里程碑规划
> 基线：v0.4.1（Windows x64），trace format 1.3，agent ABI 4
> 状态：待审核；审核通过后按里程碑顺序实施

## 1. 目标与范围

把 noleax 的完整能力（hook 捕获 → 有界 trace → 离线分析）移植到 Linux，与 Windows 版
功能对齐、语义一致、trace 格式互通：

- **目标平台**：Linux x86_64，glibc（运行时库明确锁定 glibc；musl 不在本期范围）。
- **能力对齐**：`run` / `attach` / `analyze` / `symbols` / `config` / `doctor` 全命令可用；
  hook profile、有界 trace、内存快照、leaks/events/memory 三模式、console/JSON/CSV 输出、
  自定义 hook、standalone 模式逐一对应。
- **格式互通**：同一份 `.nlx` trace 在 Windows 与 Linux 的 analyzer 上都可打开；
  平台特有内容走格式已预留的平台域（`Platform::kLinux`、`error_domain=posix`、
  schema 中 `metadata.platform` 的 `linux` 枚举均已存在）。
- **共用语义**：退出码 0/1/2/3/4/5、completeness 位、`--live`、TOML < CLI 优先级、
  "每个功能同时具备 TOML+CLI+测试+文档" 的既有规则全部延续。

明确不做（本期）：musl libc、ARM64、macOS、`noleax patch` 的 ELF 静态补丁（见 §5.4）、
Windows trace 的 Linux 侧符号化（跨平台符号化保持现有 `unsupported_platform` 行为）。

## 2. 现状盘点：可复用与需重建

源码布局自始为跨平台预留（[ROADMAP.md](ROADMAP.md)）。下表是按 Windows 版功能逐项
对照的移植工作量清单。

### 2.1 直接复用（已验证平台中性，预期只需 Linux CI 证明）

| 组件 | 位置 | 说明 |
|---|---|---|
| trace 格式与读写 | `src/trace/` | `.nlx` 1.3，header 已含 `Platform::kLinux`；reader/writer/record codec/recovery 无平台代码 |
| analyzer 主体 | `src/analyzer/`（除 symbolizer） | events/leaks/memory、过滤、聚合、三种输出全部 trace 驱动 |
| 配置与 CLI | `src/config/`、`src/cli/` | toml++、CLI11，无平台代码 |
| IPC 帧协议 | `src/ipc/protocol.cpp` | 32 字节 LE 帧、消息状态机与平台无关，仅传输层是 Windows 命名管道 |
| 事件队列算法 | `include/noleax/agent/bounded_mpsc_queue.hpp` | 纯原子操作 MPSC 环形队列 |
| hook backend 适配层 | `agent/hook_backend.cpp` | hoox API 封装，无 OS 依赖 |
| 自定义 hook 声明模型 | [CUSTOM_HOOKS.md](CUSTOM_HOOKS.md) | 声明式 alloc/realloc/free 角色模型近乎 1:1 可搬 |
| vcpkg 依赖 | vcpkg.json | catch2/cli11/lz4/tomlplusplus/zstd 全部跨平台 |
| hoox hook 引擎 | third_party/hoox | 已含 POSIX/pthread 后端（**仅保证可编译，从未验证**，见风险 R1） |

### 2.2 需为 Linux 重建（Windows-only 实现的对应物）

| Windows 实现 | 位置 | Linux 对应方案 |
|---|---|---|
| 进程创建/注入控制 | `src/controller/`（682 + windows/ 约 2700 行） | fork/execve + env 传递（run）；ptrace（attach） |
| 命名管道传输 | `src/ipc/windows/named_pipe.cpp` | Unix domain socket + `SO_PEERCRED` 对端校验 |
| agent 运行时 | `agent/windows/agent_runtime.cpp`（1000 行） | constructor 入口的 Linux agent runtime |
| Rtl/Nt hook 组 | `agent/windows/rtl_*.cpp`、`nt_memory_hooks.cpp`（约 6200 行） | glibc malloc 族 / mmap 族 hook 组（`agent/linux/`） |
| 栈捕获 | `RtlCaptureStackBackTrace` | libunwind（热路径契约不变：raw PC + 状态标记，见 §5.6） |
| 模块跟踪 | `LdrRegisterDllNotification` | `dl_iterate_phdr` 快照 + 轮询代际（见 §5.7） |
| 内存快照 | `K32GetProcessMemoryInfo`、`VirtualQuery` | `/proc/self/status`、`/proc/self/smaps` |
| 符号化 | DbgHelp（PDB/导出表/srv*） | ELF/DWARF 后端（libdw），模块身份用 build-id |
| TLS 防递归 guard | TEB 固定槽位 | initial-exec TLS（§5.5，事故类与 Windows 相同，需重新证明） |
| 停核证明 | Toolhelp 挂起 + `.nlxhk` RIP 扫描 | 信号驱动 rendezvous（§5.8） |
| PE 符号枚举 | `noleax symbols`（PDB/导出） | ELF dynsym/symtab + DWARF 枚举 |

## 3. 能力对照总表

| Windows 版能力 | Linux 版方案 | 里程碑 |
|---|---|---|
| run + 4 种启动注入 | run + `ld-preload` 注入（constructor 保证 main 前就绪） | M3 |
| attach + remote-thread/thread-hijack | attach + `ptrace` 注入 | M6 |
| `patch` / static-pe-patch / standalone 二进制 | standalone 改由 `LD_PRELOAD`+env 直接覆盖；ELF 补丁延后（§5.4） | M3（standalone）/ 延后 |
| profile windows-nt-heap | profile `linux-glibc-heap`（malloc 族） | M3 |
| profile windows-virtual-memory | profile `linux-virtual-memory`（mmap 族） | M4 |
| profile windows-native | profile `linux-native`（并集） | M4 |
| 定时内存快照（计数器 + VM map） | `/proc` 采样器，memory 模式复用 | M4 |
| 自定义符号 hook | 同模型，locator 换 ELF 体系（dynsym/DWARF/文件偏移） | M7 |
| 离线符号化（DbgHelp 回退梯） | ELF/DWARF 后端，同一回退梯语义 | M5 |
| `symbols` 命令 | ELF 符号枚举，schema v1 不变 | M5 |
| doctor | 平台检查换 Linux 项（权限、ptrace_scope、Hoox 构建信息等） | M3 起随里程碑补齐 |
| 打包发布（ZIP） | CPack TGZ + CI Linux job | M8 |

## 4. 里程碑

每个里程碑的完成标准沿用项目惯例：功能同时具备 TOML+CLI 表示、单元/集成测试、
对应文档更新，且 Windows 侧既有测试（当前 release 205/205、hardened 230/230）不回退。

### M0 构建与 CI 地基

> 状态：**已完成**（2026-08-10）。linux-x64-debug / linux-x64-release 各 252/252 测试通过
> （GCC 15.2）；`analyze`/`config` 可用，`run`/`attach`/`patch`/`symbols`/`doctor` 按设计
> 返回退出码 5。CI 新增 ubuntu-latest debug+release job。
> vcpkg 梳理结论：manifest 工具链在全平台保持必需（与 Windows 一致），打包段版权安装与
> CPack 命名（`linux-x86_64`）在 x64-linux triplet 下原样可用，无需条件化。
> 移植中建立的共享设施：`include/noleax/agent/hook_section.hpp`（`.nlxhk` 段跨编译器
> 放置宏，M1+ 的 Linux 替换函数直接使用）；非 Windows 下 `CMAKE_POSITION_INDEPENDENT_CODE=ON`
> （agent.so 链接静态库的前提）。

目标：仓库在 Linux 上可配置、可构建、可测试，中性组件有 CI 看护。

- 新增 `linux-x64-debug` / `linux-x64-release` preset（vcpkg manifest + `x64-linux` triplet，
  GCC 13+ 或 Clang 17+；`cmake/NoleaxWarnings.cmake` 的非 MSVC 分支已就绪）。
- 梳理根 `CMakeLists.txt:113-115` 的 vcpkg 强制要求与打包段在非 Windows 的行为。
- 验证中性库（core/cli/config/trace/ipc 协议/analyzer）与 `apps/noleax` 在 Linux 构建通过；
  `run`/`attach`/`patch`/`symbols` 维持现有 "not implemented on this platform" 桩（退出码 5），
  `analyze`/`config` 直接可用。
- CI 新增 ubuntu-latest 构建+测试 job（中性单测全绿）；format job 维持现状。
- 交付：`BUILDING.md` 增补 Linux 章节；本文件勾选 M0。

### M1 hook 原语验证与加固

目标：在写任何业务 hook 之前，先证明 hook 引擎与防递归/停核原语在 Linux 上成立。
这是全计划风险最高的环节，单独成里程碑。

- hoox POSIX 路径专项验证：对 glibc 导出函数做 attach/replace/flush/teardown 全生命周期
  测试（含多线程并发调用、dlclose 目标模块、重复安装/卸载）；发现的问题修复回
  third_party/hoox（NOTICE 同步）。
- `hook_guard` Linux 模型：agent 以 `-ftls-model=initial-exec` 编译，guard 改用
  initial-exec `__thread`；复现并回归 Windows 侧同类事故（TLS 初始化期内重入
  分配 hook 导致崩溃）。现有 `thread_local` 占位分支（[HOOK_GUARD.md](HOOK_GUARD.md)
  明确标注"未审计"）随之替换。
- `patch_rendezvous` Linux 实现：信号驱动 stop-the-world——枚举 `/proc/self/task`，
  向除自身外线程 `tgkill` 专用信号，handler 记录 PC；扫描命中替换代码段（Linux 侧
  专用 section 名沿用 `.nlxhk`）则 fail-closed 重试，语义对齐
  [HOOK_QUIESCENCE.md](HOOK_QUIESCENCE.md)。
- 交付：hoox/hook_guard/patch_rendezvous 的 Linux 单测与压测；`HOOK_GUARD.md`、
  `HOOK_QUIESCENCE.md` 各增补 Linux 实现章节。

### M2 agent Linux 骨架

目标：`noleax-agent.so` 成型，承载捕获管线的平台骨架就绪（尚未挂业务 hook）。

- `agent/linux/agent_runtime.cpp`：`__attribute__((constructor))` 入口（LD_PRELOAD 下
  先于 main 执行，等价于 Windows "入口点前注入"保证）；bootstrap 参数经环境变量传入
  （socket 路径 + session token + 配置），替代 Windows 的 `WriteProcessMemory` 结构体；
  standalone 模式读 `NOLEAX_AGENT_CONFIG` / sidecar TOML，就绪信号用 unix socket 替代
  命名事件。agent ABI 升到 5（新增 Linux bootstrap 变体）。
- Unix domain socket 传输：`src/ipc/linux/`（流式套接字 + 现有 32 字节帧；
  `SO_PEERCRED` 校验对端 PID/UID，对齐命名管道的 `PIPE_REJECT_REMOTE_CLIENTS` +
  客户端 PID 校验语义）；`[IPC_PROTOCOL.md](IPC_PROTOCOL.md)` 增补传输层章节。
- 栈捕获：libunwind（`UNW_LOCAL_ONLY`）原型验证热路径契约——预分配、无锁、
  不触发 malloc；捕获状态（complete/truncated/failed/unavailable）沿用
  [STACK_CAPTURE.md](STACK_CAPTURE.md) 的既有四态， unwinding 失败按 truncated/failed
  落盘，不阻塞事件记录。**决策点**：若 libunwind 热路径不达标，降级为帧指针快径 +
  `unavailable` 兜底（要求目标 `-fno-omit-frame-pointer`，作为已知限制写入文档）。
- 模块跟踪：`dl_iterate_phdr` 初始快照 + writer 线程周期轮询 diff 产生 load/unload
  代际；轮询窗口内合并为一批（代际模型天然容忍，窗口语义写入文档）。模块身份记录
  ELF build-id + 路径 + 尺寸。
- trace writer 共享层：Windows writer 中平台中性的部分（代际配对、栈字典、Loss、统计
  守恒）抽为 agent 中性组件供两侧复用；平台特有事件保持各自目录。重构以
  "Windows 侧测试不回退" 为界。
- 交付：`agent/linux/` 骨架 + 单测；`MODULE_TRACKING.md`、`STACK_CAPTURE.md`、
  `TRACE_WRITER.md` 增补 Linux 章节。

### M3 run 端到端：`linux-glibc-heap` profile

目标：`noleax run --hook-profile linux-glibc-heap -- ./app` 全链路产出完整 trace，
analyzer 三模式可分析。这是 Linux 版第一个用户可用形态。

- controller Linux 启动：`fork`/`execve` + 环境注入（`LD_PRELOAD=agent.so` 与
  bootstrap 变量），等待 agent 握手后放行语义与 Windows bootstrap 状态机一致；
  默认 agent 直写 trace，`--live` 恢复 socket 实时会话；Ctrl+C detached 语义对齐。
- hook API 组（首版）：`malloc`、`calloc`、`realloc`、`free`、`posix_memalign`、
  `aligned_alloc`、`memalign`、`reallocarray`。每个 API 先建立
  [HOOK_API_MATRIX.md](HOOK_API_MATRIX.md) 式基线档案：glibc 内部调用路径实测
  （公开符号间是否经 PLT 互调，排除重复计数）、errno 保持、original 恰好一次、
  热路径无分配。`capture.min_size` 热路径过滤与统计守恒不变式照搬。
- generation 语义：allocation_id 配对（malloc/calloc/realloc 族）、realloc 的
  shrink-in-place/迁移分支，对齐 Rtl 系列的 writer 语义。
- 已知边界（写入文档）：glibc 内部经 hidden alias（`__libc_malloc` 等）的分配不经过
  公开符号，不在覆盖范围；目标直接 `syscall(SYS_*)` 绕过 libc 同理——与 Windows 版
  "只覆盖 Rtl/Nt 隘口" 同属一类边界。
- `--inject-method` 增加 `ld-preload`（Linux 默认）；Windows 方法在 Linux 报退出码 5，
  反之亦然；配置校验改为平台感知。
- doctor Linux 检查项：agent 存在性与架构、`ptrace_scope`（attach 前置）、Hoox 构建
  信息、符号组件（libdw 可用性）。
- 交付：`docs/LINUX_HOOK_PROFILES.md`（registry/profile/过滤/守恒）、
  `docs/LINUX_LAUNCH_INJECTION.md`（LD_PRELOAD 机制与 bootstrap 状态机）、
  `docs/LINUX_HOOK_API_MATRIX.md`（逐 API 合同与基线）；run 集成测试矩阵
  （直写/live/duration/Ctrl+C/目标异常退出）。

### M4 `linux-virtual-memory` profile 与内存快照

- hook `mmap`、`munmap`、`mremap`：mapping generation（reserve/map/unmap 语义对齐
  Nt 组），`mremap` 对齐 realloc 语义；`linux-native` 并集 profile。
- 内存快照：`/proc/self/status` 计数器（对齐 PROCESS_MEMORY_COUNTERS 字段映射）、
  `/proc/self/smaps` 全量遍历（对齐 VirtualQuery map）；trace memory chunk 字段语义
  核查，平台差异字段如需解释性调整则按格式治理升 trace minor。
- 交付：上述两 API 组矩阵档案并入 `LINUX_HOOK_API_MATRIX.md`；
  `TRACE_WRITER.md`/`TRACE_FORMAT.md` 相应更新；memory 模式集成测试。

### M5 符号化与 `symbols` 命令

- `OfflineSymbolizer` Linux 后端：libdw（elfutils）解析 DWARF + dynsym 兜底，
  回退梯语义对齐 [SYMBOLIZATION.md](SYMBOLIZATION.md) 九态（`symbols_loaded` →
  `exports_only` → …）；模块身份校验用 build-id（找不到符号时给出与 PDB 缺失同类
  的诊断）。`--symbol-path` 保留本地路径语义；`--symbol-server`/`srv*` 为 Windows
  概念，Linux 下文档说明不适用（或映射 debuginfod，**决策点**，倾向本期不做）。
- trace ModuleLoad 身份字段的 Linux 解释（build-id 落位）：尽量在现有平台作用域字段
  内表达；确需变更时按版本化治理升 trace minor 并同步 reader 两侧。
- `noleax symbols`：ELF dynsym/symtab + DWARF 枚举，`noleax.symbols` v1 schema 不变
  （kind 映射增补 ELF 取值）。
- 交付：`SYMBOLIZATION.md`、`SYMBOLS.md` Linux 章节；含 DWARF  fixture 的
  analyzer 集成测试（Linux 录、Linux 解；Windows 录、Linux 解保持
  `unsupported_platform`）。

### M6 attach：`ptrace` 注入

- `PTRACE_SEIZE` + 注入 `dlopen(agent.so)` 调用 stub（等价 thread-hijack 的形态）：
  线程选择规则（RIP 须在可恢复点、避开 ld.so 与 malloc 临界区，对齐
  [THREAD_HIJACK_INJECTION.md](THREAD_HIJACK_INJECTION.md) 的事故教训）、
  syscall 重启处理、注入后上下文恢复。
- completeness 语义照搬：attach 盲期 `preexisting_allocations_unknown` + 退出码 2。
- 权限模型：`ptrace_scope`/capabilities 检查进 doctor 与排错文档。
- 交付：`docs/LINUX_PTRACE_INJECTION.md`；attach 集成测试（盲期标记、
  `--unload-on-stop` 等价物、目标线程在分配器临界区的注入拒绝）。

### M7 自定义 hook（Linux）

- 声明模型不变（TOML/CLI 声明第三方分配器的 alloc/realloc/free 角色）。
- locator 三件套换 ELF 体系：dynsym 导出名（agent 进程内读）、DWARF 符号
  （controller 侧 libdw 解析为文件偏移）、裸文件偏移；standalone baking 合同改为
  build-id + 尺寸身份校验。
- ABI 映射换 System V AMD64：整参 rdi/rsi/rdx/rcx/r8/r9 + 栈槽，`result_arg` /
  calloc 形态 / `free_size_arg` 概念不变。
- 失败降级复用现有 CustomHookFailure 记录 + completeness bit 10 + 退出码 2。
- 交付：`CUSTOM_HOOKS.md` Linux 章节；jemalloc/mimalloc fixture 集成测试。

### M8 打包发布与文档收尾

- CPack Linux 包（TGZ：`bin/noleax` + `bin/noleax-agent.so` 同目录，LICENSE/文档/示例/
  第三方声明/SHA256 对齐 Windows 包布局）；CI 加 Linux 构建-测试-打包-发布链路
  （滚动 `ci-latest` 与 `v*` 标签双轨同 Windows）。
- 用户文档：`README.md`（系统要求/构建/示例双平台化）、`QUICKSTART.md`、
  `TROUBLESHOOTING.md`（Linux 故障表：ptrace_scope、LD_PRELOAD 被
  setuid/静态链接目标忽略、符号缺失）、`PACKAGING.md`；release 包文档清单
  （根 CMakeLists install 段）同步增补。
- `ROADMAP.md` 更新：Linux 条目从"无时间表"移出，剩余边界（musl/ARM64/ELF patch）
  重写。
- 交付：Linux RC 包通过 `Test-NoleaxPackage` 等价校验；双平台测试全绿。

## 5. 关键技术决策

### 5.1 注入：LD_PRELOAD 为主，ptrace 为 attach

LD_PRELOAD 是 Linux 下唯一同时满足"main 之前就绪"与"低侵入"的启动注入通道：
agent constructor 在动态链接器初始化阶段运行，早于目标入口点，等价于 Windows 四种
启动注入共同追求的时序保证。启动期不再提供其余方法（entrypoint-code/static-pe-patch
的 Linux 形态没有对应收益）。attach 没有环境变量通道，用 ptrace——它是
remote-thread/thread-hijack 在 Linux 的唯一现实对应物。

### 5.2 hook 方式：沿用 hoox inline hook，不用符号拦截

malloc 族也可以用 LD_PRELOAD 符号覆盖（interposition）实现，但本项目架构建立在
inline hook 之上（replace_fast 合同、恰好一次 original、停核证明、profile 注册表），
且 hoox 已含 POSIX 后端。保持一致收益更大：hook matrix 合同、quiescence 证明、
失败降级全部同构。若 M1 证明 hoox 对 glibc 不可用，回退方案才是符号覆盖
（架构改动局部化在 agent/linux 的 hook 安装层，合同与 writer 不变）。

### 5.3 hook 目标：glibc 公开符号为隘口

Windows 版选择 ntdll Rtl/Nt 作为一切分配路径的隘口。Linux 没有完全等价的单一隘口：
glibc 内部部分分配经 hidden alias 绕过公开符号。首版以 malloc/mmap 两族的公开符号为
隘口（与 ASan/tcmalloc/heaptrack 同一覆盖类别），边界写入文档（§M3）。这意味着
Linux 版覆盖率声明与 Windows 版不是同一命题，文档中明确区分。

### 5.4 standalone 与静态补丁

Windows 的 standalone 二进制（patch --standalone）解决的是"无控制器常驻"部署。
Linux 下 `LD_PRELOAD=agent.so NOLEAX_AGENT_CONFIG=x.toml ./app` 天然就是 standalone，
无需任何二进制改写。因此 `noleax patch` 的 ELF 对应物（DT_NEEDED 注入/入口点补丁）
本期不做；后续若有"无法设置环境变量"的硬需求（如 systemd 单元不便改 Environment）
再单独立项。

### 5.5 TLS 防递归：initial-exec 模型

LD_PRELOAD 加载的 .so 可分配到静态 TLS 块，agent 全库 `-ftls-model=initial-exec`，
guard 用 initial-exec `__thread`，热路径零调用零分配。Windows 侧 TEB 槽位事故
（loader 期内 thread_local 触雷）在 glibc 上的对应物是 TLS 动态模型首次访问触发
`__tls_get_addr` 分配——同一崩溃类，M1 必须用测试钉死。

### 5.6 栈捕获：libunwind，失败可降级

热路径契约（预分配、无锁、raw PC、四态状态）不变。现代发行版默认
`-fomit-frame-pointer`，帧指针快径不可靠，首选 libunwind + 预热缓存；CFI 缺失或
缓存未命中按 truncated/failed 落盘而非阻塞。该降级语义已在
[STACK_CAPTURE.md](STACK_CAPTURE.md) 的状态机内，不需要格式变更。

### 5.7 模块跟踪：轮询代替通知

Linux 没有进程内模块加载通知（`r_debug` 是调试器接口）。用 writer 线程周期
`dl_iterate_phdr` diff 产生代际：通知语义弱化为"轮询窗口内合并"，但代际模型、
栈帧 `(module_id, offset)` 归一化、卸载模块离线符号化全部不变。窗口语义与
dlopen/dlclose 地址复用的处理写进 `MODULE_TRACKING.md`。

### 5.8 停核证明：信号 rendezvous

Windows 用 Toolhelp 挂起全部线程 + 扫描 RIP 证明无线程在替换代码内。Linux 进程内
对应物：枚举 `/proc/self/task`，向其他线程发专用实时信号，handler 记录 PC 后等待
栅栏；主控线程扫描 PC 集合，命中 `.nlxhk` 段即 fail-closed 重试。信号打断的
slow-path syscall 由 handler 正确恢复（SA_RESTART 语义审计）。证明义务与
[HOOK_QUIESCENCE.md](HOOK_QUIESCENCE.md) 同级。

## 6. 风险登记

| # | 风险 | 影响 | 缓解 |
|---|---|---|---|
| R1 | hoox POSIX 后端从未验证，可能对 glibc 函数不可用 | M3 起全部阻塞 | M1 独立验证先行；回退方案为符号覆盖（§5.2） |
| R2 | TLS/loader 期内重入分配 hook（Windows 已出过一次同类事故） | agent 崩溃 | M1 专项回归；initial-exec 模型（§5.5） |
| R3 | libunwind 热路径分配/加锁，违反捕获契约 | 栈捕获不可用 | M2 原型验证；降级路径已定义（§5.6） |
| R4 | glibc hidden alias 绕过公开符号，覆盖率低于预期 | 遗漏事件 | 基线实测摸清边界并写入文档；与 Windows 边界同类表述（§5.3） |
| R5 | ptrace attach 注入时目标线程持有 ld.so/malloc 锁，死锁 | attach 挂死 | M6 线程选择规则 + 超时拒绝，照搬 thread-hijack 事故教训 |
| R6 | 发行版差异（glibc 版本、内核 ptrace_scope、默认编译 flags） | 行为漂移 | CI 覆盖 ubuntu 近两个 LTS；doctor 检查项兜底 |
| R7 | trace memory chunk / ModuleLoad 字段的 Linux 语义需要格式变更 | 格式治理成本 | 优先在现有平台作用域字段内解释；必须变更时走 minor 升版，双平台 reader 同步 |

## 7. 文档计划汇总

新增：`LINUX_HOOK_PROFILES.md`、`LINUX_HOOK_API_MATRIX.md`、
`LINUX_LAUNCH_INJECTION.md`、`LINUX_PTRACE_INJECTION.md`、本文件。

增补 Linux 章节：`HOOK_GUARD.md`、`HOOK_QUIESCENCE.md`、`STACK_CAPTURE.md`、
`MODULE_TRACKING.md`、`TRACE_WRITER.md`、`IPC_PROTOCOL.md`、`SYMBOLIZATION.md`、
`SYMBOLS.md`、`CUSTOM_HOOKS.md`、`CLI.md`、`CONFIG.md`、`QUICKSTART.md`、
`TROUBLESHOOTING.md`、`PACKAGING.md`、`BUILDING.md`、`README.md`、
`ROADMAP.md`。

格式治理（如需）：trace format minor 升版说明入 `TRACE_FORMAT.md`；agent ABI 5
变更入 `IPC_PROTOCOL.md`。`noleax.analysis` v1–v4 与 `noleax.symbols` v1 schema
已含 `linux` 枚举，无需变更。

## 8. 里程碑依赖与工作量

```text
M0 地基 ── M1 hook 原语 ── M2 agent 骨架 ── M3 run E2E ── M4 VM+快照 ── M8 打包发布
                                          ├─ M5 符号化 ──┤
                                          ├─ M6 attach ──┤
                                          └─ M7 自定义 hook
```

| 里程碑 | 工作量级 | 说明 |
|---|---|---|
| M0 | S | 构建/CI 梳理 |
| M1 | M，风险最高 | hoox 验证可能反复 |
| M2 | L | runtime + 栈 + 模块 + writer 抽层 |
| M3 | L | 第一个用户可用形态 |
| M4 | M | 机制已备，主要是 API 组档案与采样器 |
| M5 | M | libdw 后端 + 身份治理 |
| M6 | M | 线程选择/死锁防护是难点 |
| M7 | M | 模型现成，locator/ABI 替换 |
| M8 | S–M | 打包 + 文档收尾 |

M5/M6/M7 相互独立，M3 完成后可并行推进。
