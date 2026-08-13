# Noleax 生产化加固计划（十亿级事件 / 无人值守采集）

> 输入文档：`/mnt/ssd1/Perforce/uc_dev_junjie-xing-p05_3452/temp/leaks/docs/NoleaxImprovementRequirements_2026-08-13.md`
> （SCL Linux 内存泄漏排查复盘，P0×6 / P1×8 / P2×3）。本文把其中的需求落成可执行的
> 里程碑，每项给出范围、设计要点、改动面、验收和依赖。
>
> 状态：**实施中**（2026-08-13 立项；H0 见 PR #33，H1 前置 hoox PR #26，H2 见 PR 本节分支；
> 各里程碑按 §10 顺序推进，状态以主干为准）

## 0. 背景

一小时 SCL 采集（180.8 GB trace、14.5 亿事件、47.8 MiB/s 写入、353 万 unique stacks、零丢失）
证明了采集管道的吞吐能力，同时暴露了六类系统性短板：目标进程内存被 agent 污染、live hook
生命周期不安全、writer 失败不可恢复、VM 区间建模错误、analyzer 内存失控、以及若干效率/可观测性
缺口。本计划按"先不破坏目标、再可稳定分析、再提升效率、最后架构演进"分四个阶段实施。

## 1. 总体原则

1. **不牺牲正确性换性能**。采样、min-size、概率栈只能是显式 opt-in 并在 completeness 中标记；
   默认路径必须 lifecycle 完整。
2. **失败必须可诊断**。目标进程不得因 noleax 崩溃；trace 必须保留到失败点；controller/退出码
   必须区分失败阶段。
3. **每里程碑带可执行验收**。沿用项目惯例：功能 + TOML/CLI 表示 + 单元/集成测试齐备才算完成。
4. **本地原型只作参考实现**。当前工作区 14 个未提交文件是事故现场止血代码，合入时必须按本文
   对应里程碑重构、补测试，不得原样提交（逐文件处置见 §5）。

### 1.1 硬约束 A：hoox 改动一律走上游

`third_party/hoox/` 只存放上游 release 资产（当前 v0.2.2，README 记录 SHA512），**禁止在
noleax 仓库内直接修改/提交 hoox.c/hoox.h**。固定流程：

1. 在 hoox 仓库（`junjiexing/hoox`）开分支实现，CI 全绿后建 PR。
2. 合并后按惯例发版（`chore: release vX.Y.Z` + tag → CI 产出 `hoox-vX.Y.Z-amalgamation.zip`）。
3. noleax 侧 re-vendor：下载 release 资产，转 LF 行尾，更新 README 版本号与 SHA512
   （SHA512 按 CRLF 原始资产计算），双 preset 全量回归。

v0.2.1（near-redirect + peer park + POSIX patch guard）与 v0.2.2（park 重试）均按此流程落地，
本计划的 H1 沿用同一通道。

### 1.2 硬约束 B：DWARF 解析用第三方库，但不自己实现、也不用 elfutils

选型分析（详见 §4.4 H9）：

| 方案 | 结论 |
|---|---|
| 自己实现 DWARF line/inline 解析 | 不做。格式演进（DWARF5/split DWARF）和维护成本远超收益 |
| elfutils（libdw） | 不用（已明确排除；libdw 为 LGPLv3，集成面也大） |
| LLDB | 不可行。DWARF 解析器在 LLVM/LLDB 单仓内部，不可作为库消费 |
| frida(-gum) | 无可借鉴。只有 exports/symtab 级符号，无 DWARF 行号能力 |
| **libdwarf**（选定） | vcpkg 有 2.3.1（依赖 zlib/zstd，均已在使用）。C API 覆盖 line table 与 inline chain（DIE 树遍历）。许可证 LGPL 2.1 |
| 子进程（llvm-symbolizer/eu-addr2line） | 备选（plan B）。本次排查已用它人工兜底，批量+缓存可满足，但引入运行时依赖 |

LGPL 2.1 与 noleax（MIT）的组合：analyzer CLI 默认**动态链接** libdwarf（TGZ 附带 `.so` 或
依赖发行版包）；noleax 全源码开放本身已满足 LGPL 的 relink 要求，静态链接可作为 CMake 选项保留。
libdwarf 只进 analyzer（`noleax symbols`/`analyze`），**不进 agent**——目标进程零新增依赖。

## 2. 阶段划分总览

| 阶段 | 目标 | 里程碑 | 对应需求 |
|---|---|---|---|
| A | 不破坏目标、不产生错误结论 | H0–H4 | P0-6, P0-2, P0-3, P0-4, P0-1 |
| B | 十亿级 trace 可稳定分析 | H5–H6 | P0-5, P1-1 |
| C | 泄漏排查效率 | H7–H10 | P1-2, P1-6, P1-4, P1-3/5/8 |
| D | 长期架构 | H11–H13 | P2-3, P2-1, P2-2 |

## 3. 阶段 A：正确性与目标安全

### H0（P0-6）：Linux memory map free-space 溢出修复

- **范围**：`agent/linux/memory_snapshot.cpp` 的 gap 累加 + wire/JSON 的 unavailable 语义。
- **设计要点**：
  - 累加全部改 checked arithmetic，溢出 → 字段 unavailable（非 wrap、非 0）。
  - `free_bytes`/`largest_free_bytes` 限定在用户 canonical range（x86-64 四级页表
    `0x0000'7fff'ffff'ffff`；为五级页表预留常量与 fixture），`[vsyscall]`/VDSO/VVAR 不参与。
  - JSON schema 允许 `null` + reason；summary 的 peak/slope 跳过 unavailable 字段。
  - 文档注明 committed/reserved 是从 maps 权限推断，不等于 Windows commit charge。
- **改动面**：agent snapshot、trace record（字段已有则仅语义）、analyzer JSON/console、测试。
- **验收**：需求文档 §4.6 三条（SCL snapshot 不再溢出；四/五级页表 fixture；summary 跳过）。
- **依赖**：无。**最小独立项，第一个落地。**
- **工作量**：约 0.5–1 天。

### H1（P0-2）：Linux hook 生命周期与 stop-the-world 边界

本阶段最大、风险最高的一项，单独排期。

- **范围**：hoox 上游 API、ptrace attach 时序、agent 状态机、quiescence 等待、dormant 语义、
  `unload_on_stop` 门禁。
- **设计要点**：
  1. **hoox 上游 API**（按 §1.1 流程）：`hoox_memory_set_external_thread_suspension(enabled)`
     类 API，声明"调用者已提供 STW"，patch 事务跳过 signal-park。带 hoox 侧测试（模拟
     外部停止标记下 patch 成功、且不做 park）。上游合并后按流程发版、noleax re-vendor。
     当前 vendored 内的私有改动在 re-vendor 时移除。
  2. **ptrace stop window 内完成安装**（本地原型方向正确，保留语义重构）：
     - attach bootstrap 同步执行（handshake + StartCapture + 全部 hook 安装）后才返回
       injector；injector 才恢复线程。
     - controller 侧 handshake 与 inject 并发协调（本地原型已实现 worker 线程模型，保留）。
     - **失败窗口补强（本地原型缺口）**：injector deadline 在 bootstrap 中途触发时，绝不恢复
       仍在执行注入代码的线程；恢复前必须确认 call stub 已退出/返回。这是验收 2 的打靶点。
     - `injection.timeout` 覆盖 seizure→dlopen→bootstrap→handshake→安装全程（本地原型已做），
       超时后目标寄存器/线程状态完整恢复。
  3. **agent 状态机显式化**：installed / recording / draining / dormant / unpatching /
     finalized / failed，进 IPC status 可见。
  4. **logical stop 与物理撤钩分离**：duration 到期默认 drain-only（新调用走 original、
     in-flight 退出、queue drain、写 Statistics/EndOfTrace、patch 保持 dormant）。
     launch/attach/standalone 三路径统一。
  5. **quiescence 等待换掉 `UINT32_MAX` yields**：condition/futex + 明确 deadline；超时保留
     patch、写 incomplete，不无限忙等。
  6. **`unload_on_stop=true`**：在实现可靠的外部 STW unpatch 之前，配置校验明确拒绝
     （effective config 与运行时行为一致，一正一反两个 e2e）。
  7. 失败安全：安装/停止失败目标不崩溃，replacement 可安全回退 original。
- **改动面**：`agent/hook_backend.*`、`agent/linux/agent_runtime.cpp`、`agent/linux/*_hooks.cpp`
  的 stop_recording/uninstall 签名与语义、`src/controller/linux/*`、hoox（上游）。
- **验收**：需求文档 §4.2 全部 6 条（64–256 线程 100 轮 attach/drain 零崩溃零死锁；
  事务各阶段随机延迟不死锁不执行半写 prologue；duration 后目标续跑 10 分钟无新事件；
  安装失败 controller 拿到阶段与根因；`observed = successful + failed`、
  `written + filtered + dropped = observed` 守恒；unload_on_stop 双路径 e2e）。
  本地 ptrace 测试中"屏蔽 park 信号的 peer"用例并入正式回归。
- **依赖**：hoox 上游 PR + 发版（关键路径，第一天就提）。
- **工作量**：约 1.5–2 周。

### H2（P0-3）：writer 失败可诊断、可恢复

- **范围**：`agent/linux/trace_writer.cpp` 错误路径、controller 失败分类、live status 语义。
- **设计要点**：
  1. error tail 产品化（基于本地原型重构）：首次失败保留 errno/路径/chunk 类型/offset/阶段；
     释放 file reserve 后尽力写 `LossReason::kWriterError` + per-API Statistics + abnormal
     EndOfTrace；tail 也失败时 stderr/controller 同时携带两个错误。
  2. **`.nlx.partial` → 正常完成后原子 rename 为 `.nlx`**；SIGKILL 后的残留 partial 下次可识别。
  3. controller 失败分类：agent crash / writer error / hook install error / target exit /
     protocol error，各自稳定错误码。
  4. live status 拆分 observed/queued/consumed/written/filtered/dropped + queue occupancy/
     high-water + bytes written + last flush time（与 H10 的 P1-7 衔接）。
  5. `filtered_before_queue` 全局 = 各 per-API 之和（本地已修，补守恒属性测试）。
- **改动面**：writer、agent runtime 状态上报、controller、trace 恢复路径文档。
- **验收**：fault injection 覆盖 open/write/flush/compression/file-limit/disk-full/close；
  每个失败 trace 可被 analyzer 打开并给出明确 completeness；writer 失败不触发目标
  abort/terminate；Statistics 守恒属性测试。
- **依赖**：无（可与 H1 并行，但合入排在 H1 后以避免交叉冲突）。
- **工作量**：约 3–4 天。

### H3（P0-4）：Linux VM 区间与 generation 模型

- **范围**：writer 与 analyzer 的 mapping 生命周期建模，取代"同 base map/multimap"。
- **设计要点**：
  1. live mapping 改不重叠区间树（fragment）：full 删除、prefix/suffix 缩短、middle 拆分、
     跨 mapping 展开、重复/空洞 unmap 安全。
  2. fragment 保留原 creation event/stack/time/module/generation identity；如需新 fragment ID
     则 wire format 显式版本化，不伪造分配栈。
  3. `MAP_FIXED`/`MAP_FIXED_NOREPLACE`/`mremap`（grow/shrink/move/fixed）按重叠区间处理。
  4. **并发序列化点**：不再假设"入队顺序 = 内核 VM 操作顺序"。定义 syscall 完成序
     （replacement 内在 syscall 返回点取单调序号入队），同址 generation 按序号匹配；
     本地 multimap FIFO 作为该规则的一个子集被覆盖。
  5. writer 与 analyzer 共享同一区间语义（同一份实现或逐字段对拍），VM outstanding 输出
     明确标注 virtual bytes ≠ resident。
- **改动面**：writer VM 段、analyzer outstanding/events VM 侧、wire 语义文档、测试。
- **验收**：需求文档 §4.4 全部 5 条（区间七类用例；同址/MAP_FIXED/mremap 矩阵；≥64 线程
  同址复用 stress 无 writer error；Binned2 风格 partial-unmap fixture 终态与 /proc/maps 等价；
  既有短测 trace 与 `analyze_vm_intervals.py` 对拍一致）。
- **依赖**：无强依赖；建议在 H1 后（共用 quiescence/序号机制）。
- **工作量**：约 1 周。

### H4（P0-1）：agent 内存归属与量化

- **范围**：buffer 换算透明化、agent-owned 内存分类统计、写入 trace、analyzer 拆分输出。
- **设计要点**：
  1. buffer_size → slot 的换算结果全量上报（requested bytes、effective slots、
     sizeof(event)/sizeof(slot)、reserved bytes、实际 resident、是否被上限/2 幂调整）；
     调整即 warning，严格模式拒绝启动。
  2. agent 大块内存迁独立 `mmap` region（queue、stack dictionary、chunk/compression buffer），
     自记 resident pages；module tracker、hook backend/trampoline 单独归类；其余进 agent heap。
  3. agent-owned 统计随 memory snapshot 写入 trace；memory mode 输出 process-inclusive /
     agent-owned / application-estimate 三组曲线（estimate 明确标注精确或估算）。
  4. 队列不再为初始化 sequence 而触碰整个多 GiB buffer（分段/惰性提交，附并发论证）。
  5. capture 启动记录 hook/queue 创建前后两个基线点。
  6. 所有 agent 分配继续被 HookGuard 排除（回归测试）。
- **改动面**：heap_event queue、writer、module tracker、snapshot、analyzer memory 模式。
- **验收**：需求文档 §4.1 全部 5 条（8 GiB 请求的精确说明；空闲 workload RSS 增量
  ≤5% 误差可归因；dictionary 增长不产生 application 伪增长；HookGuard 排除回归；
  调整/失败稳定错误码）。
- **依赖**：无；与 H3 可并行。
- **工作量**：约 1 周。

## 4. 阶段 B：十亿级 trace 可稳定分析

### H5（P0-5）：outstanding/leaks analyzer 受控内存

- **范围**：`src/analyzer/outstanding.cpp` 数据结构 + 资源治理。
- **设计要点**：
  1. 保留本地原型语义（确定在 C 前结束即淘汰；已有 20 测试 + JSON hash 对拍），
     `list+unordered_map` 双索引替换为紧凑 flat hash/sparse set（候选只存输出与过滤必需字段）。
  2. `--max-memory`：启动容量估算；接近上限选择 spill/checkpoint 或明确失败；不触发 OOM。
  3. 磁盘 spill 文件带 trace identity + config hash + 校验；中断可清理/恢复。
  4. 到达 C 点后停止解码 lifecycle 无关 payload（仍读 terminal metadata/Statistics/Loss/
     EndOfTrace）。
  5. 输出事务化（临时文件 + rename）；stderr 限频进度（bytes/events、%、live/candidate、
     RSS、spill、ETA）。
- **验收**：需求文档 §4.5 全部 5 条（六 cohort golden JSON 一致；峰值由 live set 决定；
  8 GiB 限制下 spill 完成或明确拒绝；C 前/恰 C/C 后 + ID 复用矩阵；stale partial 识别）。
- **依赖**：无；本地 outstanding.cpp 原型是语义基线。
- **工作量**：约 1 周。

### H6（P1-1）：单遍多窗口 + trace 索引

- **设计要点**：analyze config 多命名 window 单遍产出；`--cohort-width/--from/--to/--end` 简写；
  creation 只进一个 cohort、free/realloc 只处理一次；sidecar/footer 索引（chunk type/offset/
  size/time/sequence/stack/module 范围）可重建可校验，旧 trace 自动补建；memory mode 跳过
  event/stack payload；`--top N` 只序列化前 N 组但保留完整 summary。
- **验收**：需求文档 §5.1 全部 4 条（多窗口与六次独立运行逐字段一致；六窗口读取量≈一遍；
  memory mode 不读 event payload；索引损坏安全重建/明确失败）。
- **依赖**：H5（内存治理先行，索引放大并发分析能力）。
- **工作量**：约 1 周。

## 5. 阶段 C：排查效率

### H7（P1-2）：Linux 物理内存指标与趋势

- 原生 counter：VmRSS/VmHWM/VmSize/VmSwap、RssAnon/RssFile/RssShmem、smaps_rollup 的
  Pss/Private_Clean/Private_Dirty/Anonymous、派生 RSS+Swap/PSS+Swap；跨平台抽象字段带
  source/definition 标注；smaps 独立采样周期；memory analyze 输出 trailing window 的
  delta/rate/OLS/R²/min/max/median/样本数；JSON 支持 counters-only/summary-only/maps 分级输出；
  三组曲线（process/agent/application）。
- **验收**：需求文档 §5.2 三条（与 proc CSV 对拍；slope 与 analyze_soak_proc.py 一致；
  无 smaps_rollup 权限时降级并列出 unavailable）。
- **工作量**：约 3–4 天。

### H8（P1-6）：marker / ResetGame cohort

- Marker record（monotonic/UTC/sequence/category/name/ordinal/小 KV）；`noleax mark` 与 IPC API
  双通道，写回执返回 sequence/time；`--from-marker/--to-marker/--end-marker`；相邻同名 marker
  自动成 cohort；marker 丢失/乱序进 completeness；run/attach/standalone 三模式可写。
- **验收**：需求文档 §5.6 三条。
- **工作量**：约 3–4 天。

### H9（P1-4）：DWARF 行号与 inline chain（libdwarf 后端）

- **范围**：analyzer 新增可选 DWARF 后端，**仅 CLI 侧**（analyze/symbols），agent 零改动。
- **设计要点**：
  1. 依赖：vcpkg `libdwarf` 2.3.1（zlib/zstd 已在依赖树）。默认动态链接
     （TGZ 附带或系统包），静态链接留 CMake 选项（源码全开放满足 LGPL 2.1 relink 条款）；
     依赖缺失时后端自动禁用，函数级符号行为不变。
  2. 流水线：函数级仍走内置 ElfImage（含 §4.2 的 debuglink/CRC/BuildID 校验），
     DWARF 层只增量解析 line table/inline chain；split debug 身份校验结论直接复用。
  3. 批量+缓存：唯一地址只解析一次，进程内缓存，多 cohort 共享；与 `--top N` 联动，
     只对最终展示地址做 DWARF 解析。
  4. 输出：function/file/line/column/inline depth/module build ID；`--source-map old=new`
     路径重映射；DWARF 失败保留函数级结果并注明原因。
- **验收**：需求文档 §5.4 三条（SCL Top 100 与 eu-addr2line 一致；无 DWARF 回退 dynsym；
  单地址单次解析、跨 cohort 缓存）。
- **工作量**：约 1 周。

### H10（P1-3 / P1-5 / P1-8）：自动化与身份

- P1-3：query/window 级 completeness + `--incomplete-policy fail|warn|allow`（默认 fail 兼容）+
  稳定 `command_status`；stderr 终态一行（状态/输出路径/completeness 原因）。
- P1-5：`custom-only` profile（无 built-in hooks，保留 module tracking/snapshot/Statistics/
  EndOfTrace）；RVA locator 支持并要求 expected_build_id，identity 不符拒绝安装；trace 记录
  原始 locator/resolved RVA/absolute/build ID/可选 prologue hash；preflight 命令离线解析并输出
  函数边界/可执行段/参数模型；每 role 独立 display name；realloc 边角语义定义与测试
  （nullptr/0 尺寸/失败保留/in-place vs moved/attach 前指针）。
- P1-8：capture manifest（版本/git commit/ABI/binary hash、target Build ID/hash、effective
  config 带来源、resolved hooks、injection 信息、trace path/session ID），结束原子追加 final
  statistics/end reason/exit code/trace hash；敏感信息 redaction；trace metadata 存 manifest hash。
- **验收**：需求文档 §5.3/§5.5/§5.8 各自条款。
- **工作量**：约 1 周（三项合计）。

## 6. 阶段 D：长期架构

- **H11（P2-3）**：writer/dictionary 外置。目标内只留 hook + stack capture + 有界 shared-memory
  transport；文件 I/O、compression、dictionary、rotation、manifest 全部出进程。验收按需求 §6.3
  （controller 死→agent 安全停；target 死→controller finalize 并标 abnormal；ring 满按配置
  block/drop 且准确记 loss；与 in-process writer 事件流等价）。
- **H12（P2-1）**：rotation/capture set。on_full=rotate 与 max_files 真正生效；capture-set
  manifest（session/file index/全局 sequence 与 time range/前后文件 identity/hash）；跨文件
  module generation/stack dictionary/allocation ID 全局语义；segment 独立可校验、缺段报 gap；
  ring 模式必须带 live-allocation checkpoint；analyzer 拒绝混合 session。
- **H13（P2-2）**：运行时开销优化。先消不必要工作（free 不抓栈但 lifecycle 完整、一次
  normalization、批量写入）、per-role stack policy、benchmark 分项计量；采样/min-size 仅
  opt-in 且输出醒目标记。

## 7. 本地未提交修改的处置映射

| 本地文件 | 处置 |
|---|---|
| `third_party/hoox/hoox.{c,h}` | 机制迁入 hoox 上游（H1 第 1 步），noleax 侧**丢弃本地改动**，re-vendor 新版 |
| `agent/hook_backend.{cpp,hpp}`（external suspension 开关） | H1 保留语义、按上游 API 重写 |
| `agent/linux/agent_runtime.cpp`（同步 bootstrap/drain-only/dormant/长等待） | H1 重构：状态机 + deadline 等待替换 UINT32_MAX；dormant 语义保留 |
| `include/noleax/agent/linux/bootstrap.hpp`、`src/controller/linux/*` | H1 保留并发协调与 timeout 贯通，补强失败窗口（§3 H1-2） |
| `agent/linux/trace_writer.cpp`（error tail/multimap/filtered 聚合） | error tail 与 filtered 修复进 H2；multimap 进 H3 被区间模型取代 |
| `src/analyzer/outstanding.cpp`（早淘汰） | H5 保留语义，数据结构按紧凑方案重写 |
| `tests/integration/linux_ptrace_injector_test.cpp`（屏蔽 park 信号 peer） | H1 并入正式回归 |
| `tests/integration/linux_standalone_profile_test.cpp` 新增两例 | vm-stress 用例先修校准（debug 下丢事件：加大 buffer/降载/改断言）再随 H3 入库；quiescence 用例随 H1 入库 |
| `tests/targets/linux_workload_target.cpp`（vm-stress/slow_alloc） | 随对应测试一起入库 |

## 8. 风险登记

| 风险 | 缓解 |
|---|---|
| H1 触碰 hoox 上游 + ptrace 时序，回归面最大 | hoox PR 第一天发起；stfu 场景用故障注入矩阵覆盖；保持 4.x 已验证的 exit/drain 语义不动 |
| libdwarf LGPL 2.1 合规 | 默认动态链接；THIRD_PARTY_NOTICES 登记；静态选项附 relink 说明 |
| H3 并发序列化点定义错误会破坏 VM 结论 | writer/analyzer 对拍 + analyze_vm_intervals.py 外部基准；先文档化规则再实现 |
| 大 trace 回归成本（180.8 GB） | H5/H6 验收复用既有 golden JSON；机器预留内存上限跑批 |
| 游戏侧配合窗口（人工驾驶/ResetGame） | 阶段 C 功能按优先级解耦，任一延期不阻塞 A/B |

## 9. 总体验收门槛

以需求文档 §10 的七条为准（100 轮 attach/drain 零事故；partial unmap/MAP_FIXED/mremap/
同址复用 workload 与 /proc/maps 一致；180.8 GB trace 一遍六 cohort 不 OOM；memory mode 区分
application/agent 且 RSS/PSS/Swap 正确；ResetGame marker 直接生成逐轮 survivor；disk full/
writer failure/controller crash/target crash/analyzer interruption 均有可诊断产物；所有产物
携带 target/agent/config identity）。

## 10. 实施顺序与排期摘要

1. **H0**（0.5–1 天）——最小独立修复，立即消除错误输出。
2. **H1**（1.5–2 周）——hoox 上游 PR 第一天发起（关键路径）。
3. **H2**（3–4 天，可与 H1 并行开发、后合入）。
4. **H3**（1 周）。
5. **H4**（1 周，可与 H3 并行）。
6. **H5**（1 周）→ **H6**（1 周）。
7. **H7**（3–4 天）、**H8**（3–4 天）、**H9**（1 周）、**H10**（1 周）。
8. **H11–H13** 按人力与游戏侧窗口排。

阶段 A 完成前，不建议再跑一小时级正式采集；阶段 B 完成后，现有 180.8 GB trace 的六 cohort
回归作为常态化基准。
