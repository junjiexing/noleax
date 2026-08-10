# Windows Raw Stack Capture

> 范围：Windows memory adapter 的原始地址捕获；不解析符号、不去重、不写 trace

## 1. 合同

hook 热路径只捕获原始指令地址。它不得调用 DbgHelp、访问符号服务器、生成符号字符串或维护共享
栈字典；符号化和栈去重分别属于离线 analyzer 与后台 writer。

`CapturedStack` 是 520-byte、trivially-copyable 的定长对象：

- 最多 64 个 64-bit 原始地址；
- 实际帧数和请求深度；
- 捕获方法与显式状态；
- 不包含进程内指针、动态容器或所有权。

状态语义为：

| 状态 | `frame_count` | 含义 |
|---|---:|---|
| `kDisabled` | 0 | 有效配置要求深度为 0 |
| `kCaptured` | 1..requested | 已到达当前可遍历栈的末尾 |
| `kTruncated` | requested | 至少还有一帧被深度上限截断 |
| `kFailed` | 0 | 本次 unwind 未得到任何帧 |

失败不能伪装成 disabled 或一个“成功的空栈”。后台 writer 为每个 `kFailed` 结果生成
`stack_capture_failed/agent_queue` Loss，同时仍保留 allocation/free 事件；该 Loss 只降低 stack
completeness，不声称生命周期事件已经丢失。

## 2. 生产策略

Windows x64 生产路径使用 `RtlCaptureStackBackTrace`：

1. NT Heap original 返回后立即保存原始 `LastError`；
2. 仅在 MPSC queue 成功取得 slot 后执行捕获，queue-full 事件不再承担 unwind 成本；
3. 请求 `maximum_depth + 1` 帧，用额外一帧区分 complete 与 truncated；
4. 跳过捕获实现、adapter 和 replacement 帧，使第一帧从目标调用方开始；
5. 发布完整 event，最后恢复 original 的 `LastError`。

默认和固定上限均为 64 帧。构造 adapter 时会在 hook 安装前执行一次冷路径 preflight；非法深度或
preflight 完全失败会拒绝构造，不允许半安装。单个目标线程仍可能得到显式 `kFailed`，这不会中止
进程或伪造帧。

生产路径中的 Noleax 代码不分配内存、不执行 I/O、不获取显式锁，也不查询 loader 或符号。栈数组
直接写入已预分配的 queue slot；未使用帧不进入后续编码。

## 3. 对照策略

另实现一套只用于测试的 Windows x64 metadata unwind：

- `RtlCaptureContext` 获取寄存器；
- `RtlLookupFunctionEntry` 查询 x64 unwind metadata；
- `RtlVirtualUnwind` 处理有 pdata 的函数；
- leaf function 从受 TEB `StackLimit/StackBase` 约束的栈顶读取返回地址；
- 每一步要求 RIP 前进且 RSP 严格增加，避免损坏上下文造成死循环。

该策略用于和系统 backtrace 的调用链交叉检查，不进入 allocator hook 热路径。
`RtlLookupFunctionEntry` 的 loader/runtime 行为、架构差异和更大的自维护攻击面不适合作为当前
Windows x64 的默认实现。未来 ARM64/x86 支持必须各自重新验证 unwind 合同，不能直接沿用 x64
leaf 规则。

## 4. 事件与失败边界

allocate event 加入栈后为 576 bytes；随后统一为 608 bytes，并为容纳 NT VM target、
mapping 与 section 字段扩展为 672-byte `RtlHeapEvent`。默认 queue 为 16,384 个 slot，含 slot sequence 预分配
约 10.1 MiB；测试 harness 使用 256 个 slot
稳定制造 overflow。

系统 `RtlCaptureStackBackTrace` 在高并发下可能偶发返回 0。压力测试因此验证以下合同，而不是假设
每次系统 unwind 都必定成功：

- 每个结果必须是结构完整的成功/截断栈或显式零帧失败；
- 两种策略各完成 8 线程 × 2,000 次捕获且成功率至少 99%；
- 成功帧全部非零，两种策略在普通嵌套调用中至少共享两个 caller frame；
- 真实 hook drain 的事件必须使用生产方法和配置深度，并且整批至少有一个成功栈；
- hooked/unhooked workload 的返回、内容、`LastError` 和 checksum 保持逐字节一致。

捕获层自身不执行后台 drain、栈去重或 trace 编码；后台 writer 已接入 queue-full 和
stack-capture-failed 的 Loss record。

## 5. 验证

~~~powershell
. .\scripts\Enter-NoleaxDevShell.ps1
cmake --build --preset windows-x64-debug
cmake --build --preset windows-x64-release
ctest --preset windows-x64-debug -R "stack capture|rtl-allocate-heap-passthrough" --output-on-failure
ctest --preset windows-x64-release -R "stack capture|rtl-allocate-heap-passthrough" --output-on-failure
~~~

Release object 审计确认生产捕获函数唯一的外部调用是 `RtlCaptureStackBackTrace`；replacement 调用
guard、original、错误状态/计时/thread API、无锁 queue 和该捕获入口，未出现 allocator、文件、
日志、符号、loader 或显式锁调用。相关 object 也没有 `.tls$` section。卸载时的 replacement
in-flight 生命周期见 [HOOK_QUIESCENCE.md](HOOK_QUIESCENCE.md)。

## 6. Linux 实现：`_Unwind_Backtrace`

> 状态：已实现（Linux 移植 M2）。机制选型经原型对比后从计划的 libunwind 改为 libgcc
> `_Unwind_Backtrace`，合同与状态机不变。

- 机制：`_Unwind_Backtrace`（libgcc_s 随 agent 自身加载，目标进程零配合），逐帧取
  `_Unwind_GetIP` 原始 PC，热路径合同（预分配、无锁、无 I/O、raw PC）与第 1 节一致。
- 原型实测（2.5 万次 × 双构型）：省略帧指针下完整回溯；冷/热路径全程零分配；
  ~0.7µs/次（≤32 帧），hook 化 malloc 压测 2 秒 1020 万次捕获零失败。
- 依赖前提：`.eh_frame`（发行版默认携带，含 release 构建）；glibc ≥ 2.35 的 lock-free
  `_dl_find_object` 保证与 loader 锁无竞争（探针以 dlopen/dlclose 并发搅动专项验证）。
  更老 glibc 与 stripped 掉 `.eh_frame` 的目标按 kFailed/kUnavailable 落盘。
- 帧指针快径实测仅剩 2 帧（`-fomit-frame-pointer` 主流默认），不作主路径，仅调试辅助。
- 对应物映射：method 取值 `kUnwindBacktrace`；Windows 的 `kRtlCaptureStackBackTrace`/
  `kVirtualUnwind` 语义分别对应"生产默认"与"对照校验"，Linux 目前单方法。
