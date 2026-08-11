# Linux 版开发计划

> 范围：Linux x86_64 / glibc 端口的总体设计与里程碑规划
> 基线：v0.4.1（Windows x64），trace format 1.3，agent ABI 4
> 状态：**全部里程碑已完成**（M0–M8，2026-08-11 收官）；本文档保留为移植的设计与
> 决策档案（每个里程碑的勾选注记记录了与最初方案的偏差及原因）

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

> 状态：**已完成**（2026-08-10）。linux-x64-release / debug 各 277/277 测试通过；并发锤压
> （8 线程 × 50 轮 patch/unpatch）连续 10 轮稳定。
>
> 实证结论（推翻或修正了计划的假设）：
> - hoox POSIX 路径对**完整尺寸的 glibc 函数**开箱可用（malloc/calloc/realloc/free/
>   posix_memalign/mmap 安装、trampoline 调用、卸载全部正确）——R1 大幅缩窄。
> - 发现真实缺陷并已修复（vendored hoox 本地扩展，计划回流上游）：
>   1. FAST replace 只规划 16 字节远跳转，短序言目标（syscall stub、跳转别名）必败 →
>      新增 **near-redirect 回退**（5 字节近跳 + slice 内远跳转），glibc profile 矩阵
>      11 个函数全部可钩；
>   2. POSIX patch 写入无任何线程排除（Windows 有 PC guard）→ 新增**信号停核**
>      （`hoox_peer_park_*`，SIGRTMIN+6 park 协议）并接入 patch guard，语义与 Windows
>      guard 对齐（含区间不净时的 release-重试与 fail-closed）；
>   3. hook_guard 的 Linux 分支从"占位"固化为 **initial-exec TLS** 模型，readelf 结构
>      回归 + 信号 handler 内分类回归（HOOK_GUARD.md §6）。
> - `patch_rendezvous` Linux 实现落地：`hook_code_region` 走 dladdr1+磁盘 ELF 节解析，
>   `verify_replacement_evacuated` 复用 park 原语（HOOK_QUIESCENCE.md §8）。
> - 残余差距（转入 M2/M3 编排层）：FAST trampoline 使用计数恒 0 导致的 slice 回收竞态，
>   由生产拆除顺序（停止记录→路由→quiescence→rendezvous→lease→flush）关闭，与
>   Windows 编排一致。

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

> 状态：**已完成**（2026-08-10）。linux-x64-release / debug 各 290/290 测试通过。
>
> 落地内容与计划出入之处：
> - 栈捕获机制经原型对比从 libunwind 改为 **`_Unwind_Backtrace`**（零依赖、零分配、
>   ~0.7µs/次；libunwind 的 vcpkg 构建还需 autotools 工具链，无优势），见 §5.6 修订注记。
> - agent runtime 骨架以 **LD_PRELOAD constructor 为唯一入口**：env 通道（socket 名/token/
  >   controller pid/timeout）读取后立即 scrub，目标子进程不会再 bootstrap；会话协议状态机
>   （hello/start/status/stop/finalize）已按 Windows agent_worker 同构实现并经 e2e 验证
>   （harness 扮 controller 对 `/bin/sleep` 预加载）；StartCapture 目前返回 M3 占位错误。
> - **agent ABI 保持 4**：wire 协议无变更（Linux bootstrap 走 env 而非内存结构体，
>   不影响 ABI）；计划中的"ABI 5"修订为不需要。
> - **writer 中性层抽取调整**：不重构 Windows writer（避免扰动稳定侧）；Linux writer 在
>   M3 与新 profile 事件语义一并新写，直接复用 `src/trace` 中性库、
>   `bounded_mpsc_queue` 与既有 stack_dictionary（平台中性代码），守恒不变式
>   （sequence 连续、计数对账）照搬。
> - Unix socket 传输、dl_iterate_phdr 轮询模块跟踪、栈捕获均已落地并有测试；
>   IPC_PROTOCOL/STACK_CAPTURE/MODULE_TRACKING 三文档已增 Linux 章节。

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

> 状态：**已完成**（2026-08-10）。linux-x64-release / debug 各 293/293 测试通过，含
> run→trace→analyze 端到端（`cli.linux-end-to-end`）。
>
> 落地与计划出入之处：
> - **注入/会话合并为单通道**：Windows 的"agent 直写"与"--live 管道"两条路在 Linux 合并为
>   一条 socket 会话（默认模式只是不轮询）；Ctrl+C detach 后会话关闭，agent 继续捕获到
>   目标退出。standalone（纯 env + TOML）已在 agent 内实现（exit hook 收尾 + duration
>   定时），`noleax patch` 的 ELF 对应物仍不做（§5.4）。
> - **constructor 同步完成全部 bootstrap**（connect/hello/start/install/begin），原因两条：
>   "入口点前注入"保证 + loader 锁只对同线程递归（worker 线程里 dlsym/dl_iterate_phdr
>   会与 constructor 持有的锁死锁）。该约束写进了 agent_runtime.cpp 头注。
> - **目标退出自收尾**：agent hook 住 `exit`/`_exit`，一次性 finalize（停录→writer 排水→
>   关 trace）；abort/信号死亡走 trace 截断恢复语义。
> - **writer 统计计数通道**：finalize 时从 hook 侧取权威计数快照（filtered 事件不进队列），
>   对账不变式精确成立（observed == successful+failed == written+filtered+dropped）。
> - **事件覆盖实证**：constructor 前 ld.so/CRT 分配也被完整捕获（事件 #1 早于 main）；
>   group-by stack 输出与 Windows 同格式（api 名经 Linux registry 解析）。
> - 交付物：glibc_heap_hooks（8 API 适配器，全合同）、trace_writer（代际配对/栈去重/
  >   模块交织/有界文件/对账）、controller 会话、run plumbing、e2e 测试、
>   LINUX_HOOK_PROFILES/LINUX_HOOK_API_MATRIX/LINUX_LAUNCH_INJECTION 三篇文档。
> - 已知边界（后续里程碑）：attach（M6）、VM 组与内存快照（M4）、符号化（M5，当前栈帧
  >   以 module+offset 呈现）、`--unload-on-stop`（Linux 不 dlclose，文档记录）、
>   detach 后 duration 失效（M3 已知差距，写进 QUICKSTART/TROUBLESHOOTING 时对齐 M8）。

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

> 状态：**已完成**（2026-08-11）。双 preset 296/296；native profile e2e 覆盖
> mmap/munmap/mremap + `--mode memory` 时间序列。
>
> 出入与新增注记：
> - mremap 变参第 5 参仅在 `MREMAP_FIXED` 时有语义（事件如实记录）；迁移展开为
>   VmFree+VmAllocate 记录对，wire 序列与统计按记录计数（hook 侧带 paired_records）。
> - 内存快照字段映射：VmRSS/VmHWM/RssAnon/VmSize → working_set/peak/private/commit；
>   maps 遍历按 `---p` → Reserve、可执行文件映射 → Image、命名/匿名分类，POSIX PROT
>   位进 protect。analyzer 侧无需改动（memory 模式平台中立）。
> - **新发现的 ELF 链接陷阱**（已固化进 hook_section.hpp 注释与 HOOK_QUIESCENCE.md §8
>   应补的位置）：-O0 下多个 hook TU 的 `.nlxhk` 段构成同签名 linkonce 组，链接器去重
>   会丢弃整个 TU 的替换函数集。解法是门/生命周期 inline 助手移入兄弟节 `.nlxhk.imm`
>   （跨 TU 内容一致，去重正确），各 TU 替换函数独占签名；region 解析按 `.nlxhk` 前缀
>   覆盖。这是 Windows 从未暴露的问题类型（MSVC 无 COMDAT 组）。
> - 内存快照按字段映射语义写入 TRACE_WRITER 待 M8 汇总；部分 munmap 的代际语义简化
>   （部分解除映射按整段结束）与 analyzer 模型一致，写入 LINUX_HOOK_API_MATRIX §5。

- hook `mmap`、`munmap`、`mremap`：mapping generation（reserve/map/unmap 语义对齐
  Nt 组），`mremap` 对齐 realloc 语义；`linux-native` 并集 profile。
- 内存快照：`/proc/self/status` 计数器（对齐 PROCESS_MEMORY_COUNTERS 字段映射）、
  `/proc/self/smaps` 全量遍历（对齐 VirtualQuery map）；trace memory chunk 字段语义
  核查，平台差异字段如需解释性调整则按格式治理升 trace minor。
- 交付：上述两 API 组矩阵档案并入 `LINUX_HOOK_API_MATRIX.md`；
  `TRACE_WRITER.md`/`TRACE_FORMAT.md` 相应更新；memory 模式集成测试。

### M5 符号化与 `symbols` 命令

> 状态：**已完成**（2026-08-11）。双 preset 303/303；e2e trace 的栈帧解析为
> `module!symbol+offset`（含主程序真实符号，见下）。
>
> 出入与注记：
> - **后端选型落地为内置 ELF64 符号读取器**（symtab 优先、dynsym 兜底、
>   `__cxa_demangle` 反修饰），零外部依赖——libdw 只在需要 DWARF 行号时才必要，
>   而输出模型消费函数级符号，故未引入。
> - **build-id 落位推迟**：ModuleLoad 记录布局无变量长身份字段，v1 按路径符号化，
>   身份不匹配检测缺位（如实记录于 SYMBOLIZATION.md §9；记录版本 2 是后续治理项）。
> - **修了一个真 bug**：agent 此前把主程序记为字面量 `/proc/self/exe`，离线分析时
>   解析成 noleax 自身映像；现在快照时 readlink 取真实路径。
> - `noleax symbols` 支持 ELF（schema v1 不变，PE 身份字段输出 0x0）。
> - debuginfod 不做（本期）。

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

> 状态：**已完成**（2026-08-11）。双 preset 304/304；CLI attach 实测退出码 2
> （盲期语义）、duration 到点停止后目标继续运行。
>
> 出入与注记：
> - 注入为三段式：全线程 SEIZE/INTERRUPT → 安全点选线（syscall 阻塞优先，ld.so 内
>   RIP 排除）→ 借用 libc syscall gadget 分配 stub 页，两段调用（dlopen →
>   `noleax_agent_attach_bootstrap`）。线程上下文全恢复。
> - **实测抓到一个内核语义坑**：syscall 阻塞线程的 `rax=-ERESTART_RESTARTBLOCK`
>   会让内核在恢复时把 RIP 回退 2 字节，stub 从错误位置执行；改向时写
>   `orig_rax=-1` 解决（LINUX_PTRACE_INJECTION.md §3）。
> - attach bootstrap ABI：`AttachBootstrapParameters`（socket 名/token/pid/超时）
>   写入 stub 页；agent worker 吞掉所有会话异常（控制器死亡不得终止目标）。
> - 默认方法在 attach 下自动升级 ptrace（显式写 ld-preload 报错）；非子进程目标
>   用 `/proc/<pid>` 存在性探测退出。
> - 已知边界：stub 页保留一页、FP/向量态不保存、initial-exec TLS 依赖盈余区——
>   均写入文档 §5。

- `PTRACE_SEIZE` + 注入 `dlopen(agent.so)` 调用 stub（等价 thread-hijack 的形态）：
  线程选择规则（RIP 须在可恢复点、避开 ld.so 与 malloc 临界区，对齐
  [THREAD_HIJACK_INJECTION.md](THREAD_HIJACK_INJECTION.md) 的事故教训）、
  syscall 重启处理、注入后上下文恢复。
- completeness 语义照搬：attach 盲期 `preexisting_allocations_unknown` + 退出码 2。
- 权限模型：`ptrace_scope`/capabilities 检查进 doctor 与排错文档。
- 交付：`docs/LINUX_PTRACE_INJECTION.md`；attach 集成测试（盲期标记、
  `--unload-on-stop` 等价物、目标线程在分配器临界区的注入拒绝）。

### M7 自定义 hook（Linux）

> 状态：**已完成**（2026-08-11）。双 preset 310/310；e2e 以工作负载目标的
> `my_alloc`/`my_free` 为声明点，leaks 命中两块驻留自定义分配。
>
> 出入与注记：
> - SysV AMD64 参数映射：0–5 读寄存器（rdi/rsi/rdx/rcx/r8/r9），6–7 读入口栈槽；
>   `result_arg`、calloc 形态（溢出按失败事件）、`free_size_arg`（读但不入线——
>   FreeEvent 无尺寸字段，与 Windows §10.4 一致）。
> - 定位器：`alloc`/`free`/`realloc` 为 dynsym 导出（agent 进程内解析磁盘 ELF），
>   `*_rva` 为模块相对偏移，新增 `*_sym`（任意 symtab/dynsym 符号，controller 侧
>   解析为偏移）；`*_pdb` 为 Windows 专用，平台校验各自拒绝另一侧拼法。
> - 分配 id 由 **writer 侧**按 `(api_id<<40)|counter` 命名空间盖印（事件 POD 无 id
>   字段）；失败降级（CustomHookFailure + completeness bit 10）完整复用。
> - PE 身份校验（image_identity）在 Linux 无对应物，忽略并文档化；build-id 烘焙合同
>   与 ELF 静态补丁同属后续项。

- 声明模型不变（TOML/CLI 声明第三方分配器的 alloc/realloc/free 角色）。
- locator 三件套换 ELF 体系：dynsym 导出名（agent 进程内读）、DWARF 符号
  （controller 侧 libdw 解析为文件偏移）、裸文件偏移；standalone baking 合同改为
  build-id + 尺寸身份校验。
- ABI 映射换 System V AMD64：整参 rdi/rsi/rdx/rcx/r8/r9 + 栈槽，`result_arg` /
  calloc 形态 / `free_size_arg` 概念不变。
- 失败降级复用现有 CustomHookFailure 记录 + completeness bit 10 + 退出码 2。
- 交付：`CUSTOM_HOOKS.md` Linux 章节；jemalloc/mimalloc fixture 集成测试。

### M8 打包发布与文档收尾

> 状态：**已完成**（2026-08-11）。双 preset 310/310。
>
> - CPack TGZ 包（`noleax-<version>-linux-x86_64.tar.gz` + sha256），`bin/noleax` 与
>   `bin/noleax-agent.so` 同目录；从解包目录实测 doctor/run/analyze 全通，`ldd` 只列
>   系统库（hoox/lz4/zstd/toml++/CLI11 全静态）。
> - CI：`linux-x64` job 在 release preset 打包上传 artifact；`release` job 门禁加入
>   linux-x64，`v*` 标签与滚动 `ci-latest` 同时发布 Windows ZIP 与 Linux TGZ。
> - 文档：README 双平台化；QUICKSTART/CLI/CONFIG/TROUBLESHOOTING 增加 Linux 章节；
>   PACKAGING.md Linux 包节；TRACE_WRITER.md Linux 注记；ROADMAP 重写为完成态 + 剩余
>   边界（musl/ARM64/ELF patch/macOS 无时间表）。
> - 过程中补了一个一致性缺口：Linux 的 execute_capture 漏接 validate_capture_support，
>   `on_full=rotate`/`max_files>1` 曾静默忽略——现在与 Windows 一致以退出码 5 拒绝；
>   同时把该函数移出 Windows-only 区块（共用）。
> - Linux RC 校验脚本（Test-NoleaxPackage 的 Linux 等价物）本期以手工 smoke + CI 打包
>   代替；脚本化校验留作后续。

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

### 5.6 栈捕获：`_Unwind_Backtrace`，失败可降级

> 修订（M2 原型验证后）：首选从 libunwind 改为 **libgcc 的 `_Unwind_Backtrace`**——零新增
> 依赖（agent 自身链接 libgcc_s，目标进程无需任何配合），原型实测（2.5 万次×双构型）：
> 省略帧指针下完整回溯 47/47 帧、冷热路径**全程零分配**、~0.7µs/次（≤32 帧）。
> libunwind 方案弃用：它需要 vcpkg autotools 工具链且没有表现出任何优势。
> 已知约束：依赖 `.eh_frame`（发行版默认携带）；glibc ≥ 2.35 的 lock-free `_dl_find_object`
> 是无 loader 锁竞争的前提，更老 glibc 的风险写入文档。

热路径契约（预分配、无锁、raw PC、四态状态）不变。现代发行版默认
`-fomit-frame-pointer`，帧指针快径不可靠（实测仅剩 2 帧），只作为调试辅助。
CFI 缺失或异常按 truncated/failed 落盘而非阻塞。该降级语义已在
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
| R1 | hoox POSIX 后端从未验证，可能对 glibc 函数不可用 | M3 起全部阻塞 | **已在 M1 验证并修复**：完整尺寸函数开箱可用；短序言目标由新增的 near-redirect 回退覆盖；patch 写入安全由新增的信号停核 guard 保证。残余：slice 回收竞态（M2/M3 编排关闭） |
| R2 | TLS/loader 期内重入分配 hook（Windows 已出过一次同类事故） | agent 崩溃 | **已在 M1 固化**：initial-exec TLS + readelf 结构回归 + 信号 handler 回归（HOOK_GUARD.md §6） |
| R3 | libunwind 热路径分配/加锁，违反捕获契约 | 栈捕获不可用 | **已消解**：M2 原型选定 `_Unwind_Backtrace`（零依赖、实测零分配、~0.7µs/次），libunwind 弃用；glibc≥2.35 的 loader 锁前提写入文档 |
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
